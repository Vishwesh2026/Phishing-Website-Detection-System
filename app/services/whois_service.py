"""
app/services/whois_service.py
─────────────────────────────────────────────────────────────
WHOIS domain lookup service.

• get_domain_info(url) → DomainInfoDict
• Thread-safe, synchronous (runs in executor from async context)
• Graceful fallback — WHOIS failure never breaks prediction
• Timeout-guarded via concurrent.futures
• Normalises list vs. single-value WHOIS fields
"""

from __future__ import annotations

import logging
import math
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Thread pool shared across requests (keeps WHOIS off the event loop)
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")

# How long to wait for a WHOIS response before giving up (seconds).
# Raised to 15s — WHOIS servers for ccTLDs & newly-registered domains
# can be slow; 8s was causing premature fallbacks on legitimate sites.
WHOIS_TIMEOUT_SECONDS: float = 15.0


# ── Type alias for the returned dict ─────────────────────────────────────────

DomainInfoDict = dict  # typed alias for readability


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    """
    Extract bare domain (without www.) from a URL.
    e.g. 'https://www.example.com/path?q=1' → 'example.com'
    """
    parsed = urlparse(url)
    netloc = parsed.netloc or url
    host = netloc.split(":")[0]           # strip port
    if host.startswith("www."):
        host = host[4:]
    return host.lower()


def _normalise(value) -> Optional[str]:
    """Return a string from a value that may be a list, datetime, or None."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value).strip() or None


def _normalise_list(value) -> list[str]:
    """Return a list of strings from a value that may be a list or single item."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip().lower() for v in value if v]
    return [str(value).strip().lower()]


def _calculate_domain_age(creation_date) -> Optional[str]:
    """
    Calculate domain age as a human-readable string.
    Returns None if creation_date is missing or undetermined.
    """
    if creation_date is None:
        return None

    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if not isinstance(creation_date, datetime):
        return None

    # Make timezone-aware comparison
    now = datetime.now(timezone.utc)
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    delta = now - creation_date
    days = delta.days

    if days < 0:
        return "N/A"
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''}"
    if days < 365:
        months = days // 30
        return f"{months} month{'s' if months != 1 else ''}"

    years = days / 365.25
    if years >= 1:
        y = math.floor(years)
        m = math.floor((years - y) * 12)
        parts = [f"{y} year{'s' if y != 1 else ''}"]
        if m:
            parts.append(f"{m} month{'s' if m != 1 else ''}")
        return ", ".join(parts)

    return f"{days} days"


def _is_new_domain(creation_date) -> bool:
    """Return True if the domain was created less than 1 year ago."""
    if creation_date is None:
        return False
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if not isinstance(creation_date, datetime):
        return False
    now = datetime.now(timezone.utc)
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)
    return (now - creation_date).days < 365


def _is_expiring_soon(expiration_date, threshold_days: int = 30) -> bool:
    """Return True if the domain expires within threshold_days."""
    if expiration_date is None:
        return False
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    if not isinstance(expiration_date, datetime):
        return False
    now = datetime.now(timezone.utc)
    if expiration_date.tzinfo is None:
        expiration_date = expiration_date.replace(tzinfo=timezone.utc)
    return 0 <= (expiration_date - now).days <= threshold_days


# ── Core WHOIS lookup ─────────────────────────────────────────────────────────

def _do_whois_lookup(domain: str) -> DomainInfoDict:
    """
    Perform the actual WHOIS query (blocking, runs in thread pool).
    Returns a normalised dict — never raises.
    """
    try:
        import whois  # python-whois
        w = whois.whois(domain)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for domain=%s: %s", domain, exc)
        return _empty_domain_info(domain, error=str(exc))

    creation_date   = w.get("creation_date")
    expiration_date = w.get("expiration_date")
    updated_date    = w.get("updated_date")

    return {
        "domain":           domain,
        "registrar":        _normalise(w.get("registrar")),
        "creation_date":    _normalise(creation_date),
        "expiration_date":  _normalise(expiration_date),
        "updated_date":     _normalise(updated_date),
        "domain_age":       _calculate_domain_age(creation_date),
        "is_new_domain":    _is_new_domain(creation_date),
        "is_expiring_soon": _is_expiring_soon(expiration_date),
        "name_servers":     _normalise_list(w.get("name_servers")),
        "status":           _normalise_list(w.get("status")),
        "country":          _normalise(w.get("country")),
        "org":              _normalise(w.get("org")),
        "whois_available":  True,
        "error":            None,
    }


def _empty_domain_info(domain: str, error: Optional[str] = None) -> DomainInfoDict:
    """Return a safe empty result when WHOIS is unavailable."""
    return {
        "domain":           domain,
        "registrar":        None,
        "creation_date":    None,
        "expiration_date":  None,
        "updated_date":     None,
        "domain_age":       None,
        "is_new_domain":    False,
        "is_expiring_soon": False,
        "name_servers":     [],
        "status":           [],
        "country":          None,
        "org":              None,
        "whois_available":  False,
        "error":            error,
    }


# ── Public API ────────────────────────────────────────────────────────────────

async def get_domain_info(url: str) -> DomainInfoDict:
    """
    Async-safe WHOIS lookup.

    Runs the blocking WHOIS call in a thread pool with a timeout.
    NEVER raises — returns a safe empty result on any failure.

    Args:
        url: Full URL string (e.g. 'https://www.example.com/path')

    Returns:
        DomainInfoDict with domain metadata fields.
    """
    domain = _extract_domain(url)

    import asyncio
    loop = asyncio.get_event_loop()

    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_executor, _do_whois_lookup, domain),
            timeout=WHOIS_TIMEOUT_SECONDS,
        )
        return result

    except asyncio.TimeoutError:
        logger.warning(
            "WHOIS_TIMEOUT  domain=%s  timeout=%.1fs — returning sentinel values; "
            "inference continues unblocked",
            domain, WHOIS_TIMEOUT_SECONDS,
        )
        return _empty_domain_info(domain, error=f"WHOIS timed out after {WHOIS_TIMEOUT_SECONDS}s")

    except Exception as exc:
        logger.exception("Unexpected error in WHOIS lookup for domain=%s: %s", domain, exc)
        return _empty_domain_info(domain, error=str(exc))
