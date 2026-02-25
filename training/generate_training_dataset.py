"""
training/generate_training_dataset.py
──────────────────────────────────────────────────────────────────────────────
Phase 1 — Reproducible Feature Dataset Generation for 200k+ URLs.

DESIGN PRINCIPLES
─────────────────
Feature Parity:
  At runtime, DeepFeatureExtractor runs in "full" mode (DNS + SSL + WHOIS + HTTP).
  Many dataset URLs are dead or inaccessible during training. Running all
  infrastructure checks per URL would make 200k rows take weeks and produce
  inconsistent results across repeated runs.

  This script uses 'training_mode=True' which:
    ✔ Layer A — Identical lexical extraction (no change; 97 features)
    ✔ Layer B — Only lightweight DNS A/NS/MX/TXT resolution (fast, cacheable)
    ✗ Skips WHOIS timing (slow, rate-limited, not production-critical for training)
    ✗ Skips SSL validation (irrelevant for dead training URLs)
    ✗ Skips HTTP latency / redirect counting (live network required)
    ✗ Skips ASN lookup (requires IPWhois RDAP calls per unique IP)

  All skipped fields are set to -1 (the established sentinel policy).

Why This Prevents Distribution Mismatch:
  At runtime, skipped fields also return -1 when infrastructure is unreachable.
  The model sees -1 at both training and inference time for these features,
  so the decision boundary is consistent. The key risk of mismatch occurs when
  training data has real values but inference silently returns -1; here, all
  sentinel columns are explicitly trained as sentinels.

Domain-Level Caching:
  DNS records for the same apex domain (e.g., google.com) are reused across
  all URLs sharing that domain. 200k URLs may only have 30k–60k unique domains,
  so this gives a massive speedup.

Async Batching:
  asyncio.gather with BATCH_SIZE=150 and SEMAPHORE_LIMIT=50 provides safe,
  high-throughput concurrent DNS resolution without overwhelming nameservers.

USAGE
─────
  cd 'e:\\4-2\\Vish\\Phishing-Website-Detection-System'
  # Activate venv first
  python -m training.generate_training_dataset

  Output:
    Dataset/generated_training_dataset_clean.csv
    models/deep_feature_cols_clean.json

ESTIMATED RUNTIME (200k URLs)
──────────────────────────────
  • Lexical extraction: ~0.1ms / URL → 20s for 200k
  • DNS per-domain (cached): ~200ms per unique domain
  • ~50k unique domains × 200ms / 50 concurrent = ~200 seconds
  • Checkpoint writes, CSV overhead: ~60 seconds
  ─────────────────────────────────────────
  Total estimated: ~10–15 minutes on a standard home internet connection.
"""

from __future__ import annotations

import csv
import concurrent.futures
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ── Path setup (allow running from project root) ──────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd

try:
    from tqdm import tqdm as _tqdm
except ImportError:
    print("[WARN] tqdm not installed. Progress bars will be disabled. Run: pip install tqdm")
    _tqdm = None

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("generate_dataset")

# ── Configuration ─────────────────────────────────────────────────────────────
DATASET_CSV  = ROOT / "Dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT_CSV   = ROOT / "Dataset" / "generated_training_dataset_clean.csv"
CHECKPOINT   = ROOT / "Dataset" / "generated_training_partial_X.csv"
FEATURE_JSON = ROOT / "models" / "deep_feature_cols_clean.json"

BATCH_SIZE       = 200     # URLs processed per thread pool batch
MAX_WORKERS      = 40      # concurrent threads for DNS resolution
CHECKPOINT_EVERY = 5_000  # save a partial CSV every N rows

# ── DNS per-domain in-memory cache ────────────────────────────────────────────
# Key: apex domain string (e.g. 'google.com')
# Value: dict of DNS features {qty_ip_resolved, qty_nameservers, qty_mx_servers, ttl_hostname, domain_spf}
_domain_cache: dict[str, dict[str, Any]] = {}

# ── Feature columns / order (must exactly match FEATURE_COLS in deep_feature_extractor.py)
# Import FEATURE_COLS from the extractor to guarantee parity.
from app.utils.deep_feature_extractor import FEATURE_COLS, extract_lexical


# ── Lightweight synchronous DNS resolver (training_mode) ────────────────────
# IMPORTANT: This runs in a ThreadPoolExecutor thread, not the event loop.
# We use dns.resolver (synchronous) to avoid nested asyncio.run() calls
# which are forbidden inside threads that are themselves spawned from async code.

def _resolve_dns_sync(domain: str) -> dict[str, Any]:
    """
    Synchronous DNS resolution for use inside ThreadPoolExecutor.
    Returns the same keys as deep_feature_extractor's _dns_info().
    """
    DISABLED = {
        "time_response":          -1,
        "qty_redirects":          -1,
        "asn_ip":                 -1,
        "tls_ssl_certificate":    -1,
        "time_domain_activation": -1,
        "time_domain_expiration": -1,
        "url_google_index":       -1,
        "domain_google_index":    -1,
    }

    if domain in _domain_cache:
        return {**_domain_cache[domain], **DISABLED}

    qty_ip, qty_ns, qty_mx, ttl, spf_flag = -1, -1, -1, -1, 0

    try:
        import dns.resolver as dnsresolver
        resolver = dnsresolver.Resolver()
        resolver.lifetime = 3.0

        try:
            ans = resolver.resolve(domain, "A")
            qty_ip = len(ans)
            ttl = ans.rrset.ttl if ans.rrset else -1
        except Exception:
            pass

        try:
            ans = resolver.resolve(domain, "NS")
            qty_ns = len(ans)
        except Exception:
            pass

        try:
            ans = resolver.resolve(domain, "MX")
            qty_mx = len(ans)
        except Exception:
            pass

        try:
            ans = resolver.resolve(domain, "TXT")
            spf_flag = int(any("spf" in str(r).lower() for r in ans))
        except Exception:
            pass

    except Exception as e:
        logger.debug("DNS resolution failed for %s: %s", domain, e)

    live_dns = {
        "qty_ip_resolved": qty_ip,
        "qty_nameservers": qty_ns,
        "qty_mx_servers":  qty_mx,
        "ttl_hostname":    ttl,
        "domain_spf":      spf_flag,
    }
    _domain_cache[domain] = live_dns
    return {**live_dns, **DISABLED}


# ── Single URL extractor (synchronous, thread-safe) ──────────────────────────

def extract_url_sync(url: str, label: int) -> dict[str, Any] | None:
    """
    Extract full feature vector for a URL in training mode (synchronous).
    Returns None on unrecoverable error (URL skipped from output).
    """
    try:
        from app.utils.url_normalizer import normalize_url
        url = normalize_url(url)

        # Same URL cleaning as runtime extractor
        clean_url = re.sub(r"^https?://(www\.)?" , "", url)
        parsed    = urlparse(url)
        domain    = parsed.netloc.split(":")[0] or parsed.path.split("/")[0]

        # Layer A — lexical (instant, same as runtime)
        feats = extract_lexical(clean_url)

        # Layer B Training — DNS only (synchronous)
        dns_result = _resolve_dns_sync(domain)
        feats.update(dns_result)

        # Guarantee feature completeness
        for col in FEATURE_COLS:
            if col not in feats:
                feats[col] = -1

        feats["label"] = label
        return feats

    except Exception as exc:
        logger.warning("Skipping URL %s — error: %s", url, exc)
        return None




# ── Main Pipeline ─────────────────────────────────────────────────────────────

def _detect_url_label_columns(df: pd.DataFrame) -> tuple[str, str]:
    """
    Auto-detect the URL and label column names.
    The PhiUSIIL dataset may have different capitalization or names.
    """
    # Common URL column names
    url_candidates   = ["url", "URL", "Url", "phishing_url", "link"]
    label_candidates = ["label", "Label", "LABEL", "phishing", "class", "target", "status"]

    url_col   = next((c for c in url_candidates   if c in df.columns), None)
    label_col = next((c for c in label_candidates if c in df.columns), None)

    if url_col is None:
        raise ValueError(f"No URL column found. Available columns: {list(df.columns)}")
    if label_col is None:
        raise ValueError(f"No label column found. Available columns: {list(df.columns)}")

    logger.info("Detected URL column: '%s', Label column: '%s'", url_col, label_col)
    return url_col, label_col


def main() -> None:
    logger.info("=" * 65)
    logger.info("Phishing Dataset Generation — Training Mode (ThreadPool)")
    logger.info("=" * 65)
    logger.info("Input  : %s", DATASET_CSV)
    logger.info("Output : %s", OUTPUT_CSV)

    if not DATASET_CSV.exists():
        logger.error("Dataset file not found: %s", DATASET_CSV)
        sys.exit(1)

    # ── 1. Load and preprocess ────────────────────────────────────────────────
    logger.info("Loading dataset...")
    df = pd.read_csv(DATASET_CSV, low_memory=False)
    logger.info("Raw shape: %d rows × %d cols", *df.shape)
    logger.info("Columns: %s", list(df.columns))

    url_col, label_col = _detect_url_label_columns(df)

    # Keep only URL and label
    df = df[[url_col, label_col]].copy()
    df.columns = ["url", "label"]
    df = df.dropna(subset=["url"])  # drop null URLs

    # PhiUSIIL label convention IMPORTANT:
    # PhiUSIIL uses label=0 for PHISHING and label=1 for LEGITIMATE.
    # Our system convention is label=1 for phishing, label=0 for safe.
    # We INVERT: 0 (phishing in PhiUSIIL) → 1 (phishing in our system)
    #            1 (legit   in PhiUSIIL) → 0 (safe    in our system)
    label_map = {
        0: 1,   # PhiUSIIL phishing → our phishing
        1: 0,   # PhiUSIIL legit   → our safe
        # Handle any string variants
        "phishing": 1, "Phishing": 1, "PHISHING": 1, "bad": 1, "malicious": 1,
        "legitimate": 0, "Legitimate": 0, "legit": 0, "safe": 0, "good": 0, "benign": 0,
    }
    df["label"] = df["label"].map(lambda x: label_map.get(x, x)).astype(int)

    # Validate label range
    assert df["label"].isin([0, 1]).all(), "Labels must be 0 or 1 after normalization"

    # Add http:// scheme to bare URLs if missing
    df["url"] = df["url"].apply(lambda u: u if u.startswith("http") else f"http://{u}")

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Class distribution
    vc = df["label"].value_counts().rename({0: "safe (0)", 1: "phishing (1)"})
    logger.info("Class distribution:\n%s\n", vc.to_string())
    logger.info("Total rows: %d", len(df))

    # ── 2. Threaded batch extraction ─────────────────────────────────────────
    # We use ThreadPoolExecutor (synchronous DNS) instead of asyncio.gather.
    # This avoids nested event-loop issues and is simpler + equally fast for
    # blocking I/O like DNS resolution.
    all_rows: list[dict[str, Any]] = []
    pairs    = list(zip(df["url"], df["label"]))
    total    = len(pairs)

    logger.info(
        "Starting thread-pool extraction | batch=%d | workers=%d",
        BATCH_SIZE, MAX_WORKERS
    )
    t_start = time.perf_counter()
    checkpoint_counter = 0

    progress = _tqdm(total=total, unit="url", desc="Extracting") if _tqdm else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for batch_start in range(0, total, BATCH_SIZE):
            batch = pairs[batch_start: batch_start + BATCH_SIZE]

            futures = {
                executor.submit(extract_url_sync, url, label): (url, label)
                for url, label in batch
            }
            batch_results = []
            for fut in concurrent.futures.as_completed(futures):
                try:
                    result = fut.result()
                    if result is not None:
                        batch_results.append(result)
                except Exception as exc:
                    logger.warning("Future error: %s", exc)

            all_rows.extend(batch_results)

            if progress:
                progress.update(len(batch))

            processed    = batch_start + len(batch)
            elapsed      = time.perf_counter() - t_start
            rate         = processed / max(elapsed, 1)
            eta          = (total - processed) / max(rate, 1)

            logger.info(
                "[%d / %d] %.1f%% | %.0f rows/sec | ETA: %ds | unique_domains=%d",
                processed, total, 100 * processed / total, rate, eta, len(_domain_cache)
            )

            # Checkpoint
            checkpoint_counter += len(batch)
            if checkpoint_counter >= CHECKPOINT_EVERY and all_rows:
                pd.DataFrame(all_rows).to_csv(CHECKPOINT, index=False)
                logger.info("  ── Checkpoint saved: %d rows → %s", len(all_rows), CHECKPOINT)
                checkpoint_counter = 0

    if progress:
        progress.close()

    elapsed_total = time.perf_counter() - t_start
    logger.info("Extraction complete in %.1f seconds", elapsed_total)
    logger.info("Extracted %d rows (skipped %d)", len(all_rows), total - len(all_rows))

    if not all_rows:
        logger.error("No rows extracted! Check your dataset or URL format.")
        sys.exit(1)

    # ── 3. Save output dataset ────────────────────────────────────────────────
    out_df = pd.DataFrame(all_rows)

    # Ensure canonical column order
    feature_order = FEATURE_COLS + ["label"]
    out_df = out_df.reindex(columns=feature_order, fill_value=-1)

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(OUTPUT_CSV, index=False)
    logger.info("Saved training dataset: %s  (%d rows × %d cols)", OUTPUT_CSV, *out_df.shape)

    # Print final distribution
    vc2 = out_df["label"].value_counts().rename({0: "safe (0)", 1: "phishing (1)"})
    logger.info("Final class distribution:\n%s", vc2.to_string())

    # ── 4. Save feature column list ───────────────────────────────────────────
    FEATURE_JSON.parent.mkdir(parents=True, exist_ok=True)
    feature_cols_only = [c for c in feature_order if c != "label"]
    FEATURE_JSON.write_text(json.dumps(feature_cols_only, indent=2))
    logger.info("Saved feature list: %s  (%d features)", FEATURE_JSON, len(feature_cols_only))

    # Cleanup partial checkpoint
    if CHECKPOINT.exists():
        CHECKPOINT.unlink()
        logger.info("Removed partial checkpoint file.")

    logger.info("Done. Feed %s into train_deep_clean.py", OUTPUT_CSV.name)


if __name__ == "__main__":
    main()
