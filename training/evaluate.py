"""
training/evaluate.py
─────────────────────────────────────────────────────────────
Standalone evaluation script — run a saved model against a
test split without re-fitting.

Usage:
    cd <project_root>
    python -m training.evaluate --model models/phishing_v2.pkl

Outputs:
  • Classification report (precision, recall, F1 per class)
  • Confusion matrix (pretty-printed)
  • ROC-AUC score
  • Confidence distribution histogram (ASCII)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

DATASET_PATH = _ROOT / "Dataset" / "phishing_site_urls.csv"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Label encoder (mirrors train.py) ─────────────────────────────────────────

def _encode_label(lbl) -> int:
    s = str(lbl).strip().lower()
    return 1 if s in ("bad", "phishing", "1", "malicious", "spam") else 0


# ── ASCII histogram ───────────────────────────────────────────────────────────

def _ascii_histogram(values: np.ndarray, title: str, bins: int = 10, width: int = 40) -> None:
    counts, edges = np.histogram(values, bins=bins, range=(0, 1))
    max_count = max(counts) if max(counts) > 0 else 1
    print(f"\n  {title}")
    print("  " + "─" * (width + 18))
    for i, count in enumerate(counts):
        bar = "█" * int(count / max_count * width)
        print(f"  [{edges[i]:.2f}–{edges[i+1]:.2f}] {bar:<{width}} {count}")
    print()


# ── Confusion matrix printer ──────────────────────────────────────────────────

def _print_confusion_matrix(cm: np.ndarray) -> None:
    print("\n  Confusion Matrix:")
    print("               Predicted")
    print("              Safe  Phishing")
    print(f"  Actual Safe    {cm[0, 0]:>5}   {cm[0, 1]:>5}")
    print(f"  Actual Phish   {cm[1, 0]:>5}   {cm[1, 1]:>5}")
    print()


# ── Main evaluation ───────────────────────────────────────────────────────────

def evaluate(model_path: Path) -> None:
    logger.info("Loading model from %s", model_path)
    pipeline = joblib.load(model_path)

    # ── Load & prepare same data ──────────────────────────────────────────────
    logger.info("Loading dataset from %s", DATASET_PATH)
    df = pd.read_csv(DATASET_PATH)
    df.columns = df.columns.str.strip().str.lower()

    url_col = next((c for c in df.columns if "url" in c), None)
    lbl_col = next((c for c in df.columns if c in ("label", "type", "class")), None)

    if url_col is None or lbl_col is None:
        raise ValueError(f"Cannot find url/label columns. Found: {list(df.columns)}")

    df = df[[url_col, lbl_col]].rename(columns={url_col: "url", lbl_col: "label"})
    df = df.dropna()
    df["url"] = df["url"].astype(str).str.strip()
    df = df.drop_duplicates(subset="url")
    df["label"] = df["label"].apply(_encode_label)

    X = df["url"].values
    y = df["label"].values

    # Reproduce same split as train.py (same random_state)
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    logger.info("Evaluating on %d test samples ...", len(X_test))

    # ── Predict ───────────────────────────────────────────────────────────────
    preds = pipeline.predict(X_test)

    # Confidence scores
    try:
        proba = pipeline.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, proba)
    except AttributeError:
        try:
            proba = pipeline.decision_function(X_test)
            auc = roc_auc_score(y_test, proba)
        except Exception:
            proba = None
            auc = None

    # ── Metrics ───────────────────────────────────────────────────────────────
    acc = accuracy_score(y_test, preds)
    f1  = f1_score(y_test, preds, zero_division=0)
    cm  = confusion_matrix(y_test, preds)

    print("\n" + "=" * 60)
    print(f"  Model Evaluation: {model_path.name}")
    print("=" * 60)
    print(f"\n  Accuracy : {acc:.4f}")
    print(f"  F1-Score : {f1:.4f}")
    print(f"  ROC-AUC  : {auc:.4f}" if auc is not None else "  ROC-AUC  : N/A")
    print("\n" + classification_report(y_test, preds, target_names=["safe", "phishing"]))

    _print_confusion_matrix(cm)

    if proba is not None:
        phish_proba = proba[y_test == 1]
        safe_proba  = proba[y_test == 0]
        if len(phish_proba) > 0:
            _ascii_histogram(phish_proba, "Confidence distribution — Phishing (true label 1)")
        if len(safe_proba) > 0:
            _ascii_histogram(safe_proba,  "Confidence distribution — Safe (true label 0)")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate a saved phishing detection model.")
    parser.add_argument(
        "--model",
        type=Path,
        default=_ROOT / "models" / "phishing_v2.pkl",
        help="Path to the saved joblib pipeline (default: models/phishing_v2.pkl)",
    )
    args = parser.parse_args()

    if not args.model.exists():
        logger.error("Model file not found: %s", args.model)
        sys.exit(1)

    evaluate(args.model)
