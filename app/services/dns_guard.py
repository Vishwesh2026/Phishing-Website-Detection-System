"""
app/services/dns_guard.py
─────────────────────────────────────────────────────────────
Deterministic DNS existence pre-check.

Security Rationale:
-------------------
Why deterministic DNS checks must precede ML:
Non-existent domains (NXDOMAIN) are fundamentally out-of-distribution for the ML model.
If a domain cannot be resolved dynamically, it cannot physically host a phishing page.
However, because our infrastructure extractor uses sentinel values (-1) to represent
failed or timed-out connections, an NXDOMAIN results in a feature vector consisting
almost entirely of sentinels.

Why ML should not decide on impossible states:
The XGBoost model was trained on live, resolving domains. It does not know what a
"non-existent" domain looks like. If presented with all -1s, it may arbitrarily guess "SAFE"
(relying heavily on the lexical Layer A features) or "PHISHING", both of which are technically
incorrect and can mislead a security analyst. By explicitly short-circuiting the ML pipeline
on an NXDOMAIN and marking it INVALID, we preserve model integrity and provide a deterministic,
accurate response.
"""

import asyncio
import logging
import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)

async def domain_exists(domain: str, timeout: float = 2.0) -> bool:
    """
    Checks if a domain resolves to any A records.
    Returns False explicitly for NXDOMAIN or NoAnswer.
    Returns True if it resolves OR if the query times out (to allow graceful degraded inference).
    """
    if not domain:
        return False

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    try:
        await resolver.resolve(domain, "A")
        return True
    except dns.resolver.NXDOMAIN:
        logger.info("DNS Guard: NXDOMAIN for %s", domain)
        return False
    except dns.resolver.NoAnswer:
        logger.info("DNS Guard: NoAnswer for A record on %s", domain)
        return False
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        # Do not block inference on temporary timeouts; let the feature extractor 
        # try its full robust process and potentially return a Degraded ML response.
        logger.warning("DNS Guard: Timeout for %s, allowing ML inference to proceed", domain)
        return True
    except Exception as exc:
        logger.warning("DNS Guard: Unexpected error for %s (%s), allowing ML", domain, exc)
        return True
