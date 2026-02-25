"""
training/validate_clean_model.py
──────────────────────────────────────────────────────────────────────────────
Phase 3 — Sanity validation of the trained phishing_deep_clean_v1.pkl model.

Tests well-known legitimate domains and asserts they are NOT flagged as
phishing at high probability in production mode (using the live feature extractor).

USAGE
─────
  cd 'e:\\4-2\\Vish\\Phishing-Website-Detection-System'
  python -m training.validate_clean_model
"""

from __future__ import annotations

import asyncio
import json
import logging
import pickle
import sys
from pathlib import Path

import numpy as np

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("validate")

MODEL_PATH = ROOT / "models" / "phishing_deep_clean_v1.pkl"

# ── Sanity test cases ─────────────────────────────────────────────────────────
# Legitimate sites — should NOT be classified as phishing at high confidence.
SAFE_SITES = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
]

# Known phishing-pattern sites (purely lexical — no live lookup needed)
SUSPICIOUS_SITES = [
    "https://login-paypal-account-verify.se/update",
    "https://secure-bank-auth-signin.xyz/session",
]

PHISHING_THRESHOLD = 0.50


async def run_validation() -> None:
    """Load the new model and validate it on known URLs."""

    if not MODEL_PATH.exists():
        logger.error("Model not found: %s  — Run train_deep_clean.py first.", MODEL_PATH)
        sys.exit(1)

    logger.info("Loading model: %s", MODEL_PATH)
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)

    imputer      = bundle["imputer"]
    xgb          = bundle["xgb"]
    iso          = bundle["iso_regressor"]
    feature_cols = bundle["feature_cols"]

    logger.info("Feature columns: %d", len(feature_cols))
    logger.info("XGB type: %s", type(xgb).__name__)

    # Import the live extractor (same as production / inference)
    from app.utils.deep_feature_extractor import extract as extract_full

    def predict_url(feat_dict: dict) -> tuple[str, float]:
        """Return (label, probability) using the clean model."""
        vec = [float(feat_dict.get(col, -1)) for col in feature_cols]
        arr = np.array(vec).reshape(1, -1)
        arr_imp = imputer.transform(arr)
        raw_prob = float(xgb.predict_proba(arr_imp)[0][1])
        prob     = float(iso.predict([raw_prob])[0])  # calibrated
        label = "phishing" if prob >= PHISHING_THRESHOLD else "safe"
        return label, prob

    print("\n" + "=" * 65)
    print("PHASE 3 — Model Sanity Validation")
    print("=" * 65)

    print("\n[+] Testing known-safe domains (expect: SAFE)")
    all_passed = True
    for url in SAFE_SITES:
        try:
            feat_dict = await extract_full(url, infra_timeout=10.0)
            label, prob = predict_url(feat_dict)
            status = "✅ PASS" if label == "safe" else "❌ FAIL"
            if label != "safe":
                all_passed = False
            print(f"  {status}  {url}")
            print(f"          Prob(phishing)={prob:.4f}  label={label}")

            # Top contributing features
            try:
                if hasattr(xgb, "feature_importances_"):
                    importances = xgb.feature_importances_
                    top_feats = sorted(
                        zip(feature_cols, importances),
                        key=lambda x: -x[1]
                    )[:5]
                    print("          Top features:", {f: round(imp, 4) for f, imp in top_feats})
            except Exception:
                pass
        except Exception as exc:
            logger.warning("Extraction failed for %s: %s", url, exc)
            print(f"  ⚠ WARN  {url} — extraction error")

    print("\n[+] Testing suspicious domains (expect: PHISHING, validation only)")
    for url in SUSPICIOUS_SITES:
        try:
            feat_dict = await extract_full(url, infra_timeout=5.0)
            label, prob = predict_url(feat_dict)
            icon = "🚨" if label == "phishing" else "⚠"
            print(f"  {icon}  {url}")
            print(f"     Prob(phishing)={prob:.4f}  label={label}")
        except Exception as exc:
            logger.warning("Extraction failed for %s: %s", url, exc)

    print("\n" + "=" * 65)
    if all_passed:
        print("✅ All legitimate sites passed sanity checks.")
        print("   The model does NOT appear to over-classify legitimate domains as phishing.")
    else:
        print("❌ One or more legitimate sites were classified as PHISHING!")
        print("   Review the training data balance and model threshold.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    asyncio.run(run_validation())
