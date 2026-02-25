"""
app/utils/deep_feature_extractor.py
─────────────────────────────────────────────────────────────
Stage 2 feature extraction — maps a live URL to the 111-feature
numeric vector that matches the dataset_full.csv schema.

Architecture:
  Layer A  — Pure lexical (<1ms, no network I/O)
             URL / domain / directory / file / params char-count
             features derived by urllib.parse + regex.

  Layer B  — Infrastructure (async, capped at timeout)
             DNS A/NS/MX/TXT records, HTTP latency, SSL cert check,
             WHOIS timing (via whois_service), ASN lookup, redirects.

Sentinel Policy (must match training):
  -1  → unavailable / error / timeout
   0  → boolean absent  (e.g. domain_spf=0, tls_ssl_certificate=0)
  ≥0  → measured value (durations, counts)

Caching:
  Infrastructure results are cached per (domain, ttl_bucket) where
  ttl_bucket = floor(unix_time / 300) — a rolling 5-minute window.
  This prevents hammering DNS for repeated scans of the same domain.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import ssl
import socket
import time
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Canonical feature order (must match deep_feature_cols.json) ───────────────
# This list is the single source of truth for feature vector ordering at
# runtime.  train_deep.py saves the same order from the DataFrame columns.
FEATURE_COLS: list[str] = [
    # URL-level char counts
    "qty_dot_url","qty_hyphen_url","qty_underline_url","qty_slash_url",
    "qty_questionmark_url","qty_equal_url","qty_at_url","qty_and_url",
    "qty_exclamation_url","qty_space_url","qty_tilde_url","qty_comma_url",
    "qty_plus_url","qty_asterisk_url","qty_hashtag_url","qty_dollar_url",
    "qty_percent_url","qty_tld_url","length_url",
    # Domain-level
    "qty_dot_domain","qty_hyphen_domain","qty_underline_domain",
    "qty_slash_domain","qty_questionmark_domain","qty_equal_domain",
    "qty_at_domain","qty_and_domain","qty_exclamation_domain",
    "qty_space_domain","qty_tilde_domain","qty_comma_domain",
    "qty_plus_domain","qty_asterisk_domain","qty_hashtag_domain",
    "qty_dollar_domain","qty_percent_domain","qty_vowels_domain",
    "domain_length","domain_in_ip","server_client_domain",
    # Directory-level
    "qty_dot_directory","qty_hyphen_directory","qty_underline_directory",
    "qty_slash_directory","qty_questionmark_directory","qty_equal_directory",
    "qty_at_directory","qty_and_directory","qty_exclamation_directory",
    "qty_space_directory","qty_tilde_directory","qty_comma_directory",
    "qty_plus_directory","qty_asterisk_directory","qty_hashtag_directory",
    "qty_dollar_directory","qty_percent_directory","directory_length",
    # File-level
    "qty_dot_file","qty_hyphen_file","qty_underline_file","qty_slash_file",
    "qty_questionmark_file","qty_equal_file","qty_at_file","qty_and_file",
    "qty_exclamation_file","qty_space_file","qty_tilde_file","qty_comma_file",
    "qty_plus_file","qty_asterisk_file","qty_hashtag_file","qty_dollar_file",
    "qty_percent_file","file_length",
    # Params-level
    "qty_dot_params","qty_hyphen_params","qty_underline_params",
    "qty_slash_params","qty_questionmark_params","qty_equal_params",
    "qty_at_params","qty_and_params","qty_exclamation_params",
    "qty_space_params","qty_tilde_params","qty_comma_params",
    "qty_plus_params","qty_asterisk_params","qty_hashtag_params",
    "qty_dollar_params","qty_percent_params","params_length",
    "tld_present_params","qty_params","email_in_url",
    # Infrastructure (Layer B)
    "time_response","domain_spf","asn_ip","time_domain_activation",
    "time_domain_expiration","qty_ip_resolved","qty_nameservers",
    "qty_mx_servers","ttl_hostname","tls_ssl_certificate",
    "qty_redirects","url_google_index","domain_google_index","url_shortened",
]

# ── Char-counter helpers ───────────────────────────────────────────────────────

def _count(text: str, char: str) -> int:
    return text.count(char)

def _count_vowels(text: str) -> int:
    return sum(1 for c in text.lower() if c in "aeiou")

def _safe_len(text: str | None) -> int:
    return len(text) if text else 0

def _char_counts(segment: str) -> dict[str, int]:
    """Return counts for all special characters used in the dataset schema."""
    return {
        ".":  _count(segment, "."),
        "-":  _count(segment, "-"),
        "_":  _count(segment, "_"),
        "/":  _count(segment, "/"),
        "?":  _count(segment, "?"),
        "=":  _count(segment, "="),
        "@":  _count(segment, "@"),
        "&":  _count(segment, "&"),
        "!":  _count(segment, "!"),
        " ":  _count(segment, " "),
        "~":  _count(segment, "~"),
        ",":  _count(segment, ","),
        "+":  _count(segment, "+"),
        "*":  _count(segment, "*"),
        "#":  _count(segment, "#"),
        "$":  _count(segment, "$"),
        "%":  _count(segment, "%"),
    }

CHAR_KEYS = [".", "-", "_", "/", "?", "=", "@", "&", "!", " ", "~", ",", "+", "*", "#", "$", "%"]
SEGMENT_PREFIXES = ["url", "domain", "directory", "file", "params"]

def _is_ip(netloc: str) -> int:
    host = netloc.split(":")[0]
    return int(bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host)))


# ── Layer A: Pure Lexical ─────────────────────────────────────────────────────

def extract_lexical(url: str) -> dict[str, Any]:
    """Compute all 97 lexical features from the URL string alone. No I/O."""
    parsed = urlparse(url)
    netloc    = parsed.netloc or ""
    domain    = netloc.split(":")[0]
    directory = parsed.path or ""
    # extract file name (last path segment after final /)
    path_parts = directory.rsplit("/", 1)
    file_seg   = path_parts[-1] if len(path_parts) > 1 else ""
    params_seg = (parsed.query or "") + (parsed.params or "")

    segments = {
        "url":       url,
        "domain":    domain,
        "directory": directory,
        "file":      file_seg,
        "params":    params_seg,
    }

    feats: dict[str, Any] = {}

    # char counts per segment
    for seg_name, seg_text in segments.items():
        counts = _char_counts(seg_text)
        for char, prefix in zip(CHAR_KEYS, [
            "qty_dot","qty_hyphen","qty_underline","qty_slash",
            "qty_questionmark","qty_equal","qty_at","qty_and",
            "qty_exclamation","qty_space","qty_tilde","qty_comma",
            "qty_plus","qty_asterisk","qty_hashtag","qty_dollar","qty_percent"
        ]):
            feats[f"{prefix}_{seg_name}"] = counts[char]

    # length per segment
    feats["length_url"]       = len(url)
    feats["domain_length"]    = len(domain)
    feats["directory_length"] = len(directory)
    feats["file_length"]      = len(file_seg)
    feats["params_length"]    = len(params_seg)

    # domain specific
    feats["qty_vowels_domain"]  = _count_vowels(domain)
    feats["domain_in_ip"]       = _is_ip(netloc)
    feats["server_client_domain"] = int(
        "server" in domain.lower() or "client" in domain.lower()
    )

    # TLD in URL
    tld_match = re.search(r"\.(com|net|org|edu|gov|io|co|info|biz|xyz|online|site|web|shop|store)", url.lower())
    feats["qty_tld_url"] = 1 if tld_match else 0

    # Params
    feats["tld_present_params"] = int(bool(
        re.search(r"\.(com|net|org|edu|gov|io|co)", params_seg.lower())
    ))
    feats["qty_params"] = len(parsed.query.split("&")) if parsed.query else 0

    # Email in URL
    feats["email_in_url"] = int("@" in url and bool(
        re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", url)
    ))

    # URL shorteners
    shorteners = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","adf.ly","short.link"}
    feats["url_shortened"] = int(domain.lower() in shorteners)

    return feats


# ── Layer B: Infrastructure (async, with timeout) ─────────────────────────────

async def _safe(coro, fallback=-1, timeout: float = 15.0):
    """
    Await a coroutine with a hard timeout; return `fallback` on any error.
    Timeout is raised as a WARNING so it appears clearly in logs.
    Other errors are DEBUG (transient DNS/network noise).
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Infrastructure check timed out after %.1fs — using sentinel fallback", timeout)
        return fallback
    except Exception as exc:
        logger.debug("Infrastructure call failed: %s", exc)
        return fallback


async def _measure_response_time(url: str) -> float:
    """HTTP HEAD request latency in seconds. Returns -1.0 on failure."""
    import httpx
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
            t0 = time.perf_counter()
            await client.head(url)
            return round(time.perf_counter() - t0, 4)
    except Exception:
        return -1.0


async def _count_redirects(url: str) -> int:
    """Count HTTP redirects. Returns -1 on failure."""
    import httpx
    try:
        history = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0, max_redirects=10) as client:
            r = await client.head(url)
            history = r.history
        return len(history)
    except Exception:
        return -1


async def _dns_info(domain: str) -> dict[str, Any]:
    """Resolve DNS records for domain. Returns counts and TTL."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0

        qty_ip   = -1
        qty_ns   = -1
        qty_mx   = -1
        ttl      = -1
        spf_flag = 0

        # A records → IPs
        try:
            ans = resolver.resolve(domain, "A")
            qty_ip = len(ans)
            ttl = ans.rrset.ttl if ans.rrset else -1
        except Exception:
            pass

        # NS records
        try:
            ans = resolver.resolve(domain, "NS")
            qty_ns = len(ans)
        except Exception:
            pass

        # MX records
        try:
            ans = resolver.resolve(domain, "MX")
            qty_mx = len(ans)
        except Exception:
            pass

        # SPF check
        try:
            ans = resolver.resolve(domain, "TXT")
            spf_flag = int(any("spf" in str(r).lower() for r in ans))
        except Exception:
            pass

        return {
            "qty_ip_resolved": qty_ip,
            "qty_nameservers": qty_ns,
            "qty_mx_servers":  qty_mx,
            "ttl_hostname":    ttl,
            "domain_spf":      spf_flag,
        }
    except Exception as e:
        logger.debug("DNS resolution failed for %s: %s", domain, e)
        return {
            "qty_ip_resolved": -1, "qty_nameservers": -1,
            "qty_mx_servers": -1, "ttl_hostname": -1, "domain_spf": 0,
        }


async def _asn_lookup(domain: str) -> int:
    """Resolve domain to IP, then look up ASN. Returns ASN int or -1."""
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        from ipwhois import IPWhois
        result = await loop.run_in_executor(None, lambda: IPWhois(ip).lookup_rdap(depth=1))
        return int(result.get("asn", -1) or -1)
    except Exception:
        return -1


async def _whois_timing(domain: str) -> dict[str, int]:
    """
    Get domain activation and expiration as integer days since Unix epoch.
    Uses the shared whois_service for consistency with the WHOIS UI metadata.
    """
    try:
        from app.services.whois_service import get_domain_info
        info = await get_domain_info(f"https://{domain}")

        def _to_relative_days(date_str: str | None, is_expiry: bool = False) -> int:
            if not date_str:
                return -1
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(date_str.split("T")[0])
                now = datetime.now()
                if is_expiry:
                    # Days until expiration (Expiration - Now)
                    delta = dt - now
                else:
                    # Days since activation (Now - Activation)
                    delta = now - dt
                return max(0, int(delta.days))
            except Exception:
                return -1

        return {
            "time_domain_activation": _to_relative_days(info.get("creation_date"), is_expiry=False),
            "time_domain_expiration": _to_relative_days(info.get("expiration_date"), is_expiry=True),
        }
    except Exception:
        return {"time_domain_activation": -1, "time_domain_expiration": -1}


async def _ssl_check(domain: str) -> int:
    """Check if SSL/TLS certificate is valid. Returns 1, 0, or -1 (error)."""
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()
        def _check():
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=4),
                server_hostname=domain,
            ) as s:
                return 1
        return await asyncio.wait_for(loop.run_in_executor(None, _check), timeout=5.0)
    except ssl.SSLCertVerificationError:
        return 0
    except Exception:
        return -1


# ── LRU Cache wrapper (domain × 5-minute TTL bucket) ─────────────────────────

@lru_cache(maxsize=512)
def _infra_cache_key(domain: str, ttl_bucket: int) -> str:
    """Cache key combining domain and time bucket (unused value, key for lru)."""
    return f"{domain}:{ttl_bucket}"


_infra_cache: dict[str, dict] = {}  # separate dict to hold actual results


async def _get_infra(domain: str, timeout: float = 15.0) -> dict[str, Any]:
    """Run all infrastructure checks with per-domain 5-minute LRU caching."""
    ttl_bucket = int(time.time() / 300)
    cache_key  = f"{domain}:{ttl_bucket}"

    if cache_key in _infra_cache:
        logger.debug("Infra cache HIT for %s", domain)
        return _infra_cache[cache_key]

    logger.debug("Infra cache MISS for %s, running checks...", domain)

    # Run all infrastructure checks concurrently
    response_time_task = _safe(_measure_response_time(f"https://{domain}"), fallback=-1.0, timeout=timeout)
    redirect_task      = _safe(_count_redirects(f"https://{domain}"), fallback=-1, timeout=timeout)
    dns_task           = _safe(_dns_info(domain), fallback={
        "qty_ip_resolved": -1, "qty_nameservers": -1,
        "qty_mx_servers": -1, "ttl_hostname": -1, "domain_spf": 0,
    }, timeout=timeout)
    asn_task           = _safe(_asn_lookup(domain), fallback=-1, timeout=timeout)
    whois_task         = _safe(_whois_timing(domain), fallback={
        "time_domain_activation": -1, "time_domain_expiration": -1,
    }, timeout=timeout)
    ssl_task           = _safe(_ssl_check(domain), fallback=-1, timeout=timeout)

    (
        time_resp,
        qty_redirects,
        dns_info,
        asn,
        whois_timing,
        ssl_valid,
    ) = await asyncio.gather(
        response_time_task, redirect_task, dns_task,
        asn_task, whois_task, ssl_task,
    )

    result = {
        "time_response":          time_resp,
        "qty_redirects":          qty_redirects,
        "asn_ip":                 asn,
        "tls_ssl_certificate":    ssl_valid,
        # Google index — always -1 at runtime (documented sentinel policy)
        "url_google_index":       -1,
        "domain_google_index":    -1,
        **dns_info,
        **whois_timing,
    }

    _infra_cache[cache_key] = result
    return result


# ── Public API ────────────────────────────────────────────────────────────────

async def extract(url: str, infra_timeout: float = 8.0) -> dict[str, Any]:
    """
    Extract the full 111-feature vector for a URL.

    Returns a dict keyed by FEATURE_COLS entries.
    Missing / errored infrastructure values default to -1 (sentinel policy).

    Args:
        url:           Raw URL string (must include scheme).
        infra_timeout: Max seconds to wait for each Layer B check.

    Returns:
        Dict[str, Any] — 111 features in canonical order.
    """
    # Canonicalize URL (trailing slashes, fragments, case, default ports)
    from app.utils.url_normalizer import normalize_url
    url = normalize_url(url)

    # Clean URL: strip scheme and optional www to match training data distribution
    # (where URLs are typically domain.tld/path)
    clean_url = re.sub(r"^https?://(www\.)?", "", url)
    
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0] or parsed.path.split("/")[0]

    # Layer A — instant, no I/O (use clean_url for counts)
    feats = extract_lexical(clean_url)

    # Layer B — async network, with timeout
    t0 = time.perf_counter()
    infra = await _get_infra(domain, timeout=infra_timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.debug("Infra extraction for %s took %.1fms", domain, elapsed_ms)

    feats.update(infra)

    # Ensure every feature column is present; fill sentinel for anything missing
    for col in FEATURE_COLS:
        if col not in feats:
            feats[col] = -1
            logger.warning("Feature '%s' missing — defaulting to -1", col)

    return feats


def to_vector(feature_dict: dict[str, Any], feature_cols: list[str]) -> list[float]:
    """
    Convert feature dict to an ordered numeric list matching feature_cols.
    Used by ModelService before calling predict_proba().
    """
    return [float(feature_dict.get(col, -1)) for col in feature_cols]
