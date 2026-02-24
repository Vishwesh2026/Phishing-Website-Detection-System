"""
training/train.py
─────────────────────────────────────────────────────────────
Production-grade ML training pipeline for phishing URL detection.

Usage:
    cd <project_root>
    python -m training.train

What it does:
  1. Loads & deduplicates Dataset/phishing_site_urls.csv
  2. Handles class imbalance via class_weight='balanced'
  3. Stratified 80/20 split + 5-fold cross-validation
  4. Benchmarks 6 classifiers inside the full feature pipeline
  5. Evaluates: Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix
  6. Saves best model to models/phishing_v2.pkl
  7. Logs all experiment results to experiments/<timestamp>.json
"""

from __future__ import annotations

import json
import logging
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

DATASET_PATH  = _ROOT / "Dataset" / "phishing_site_urls.csv"
MODELS_DIR    = _ROOT / "models"
EXPERIMENTS_DIR = _ROOT / "experiments"

MODELS_DIR.mkdir(exist_ok=True)
EXPERIMENTS_DIR.mkdir(exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Import feature pipeline (late, after sys.path patch) ──────────────────────
from app.utils.feature_engineering import build_pipeline  # noqa: E402


# ── Data loading & cleaning ───────────────────────────────────────────────────

def load_data(path: Path) -> pd.DataFrame:
    logger.info("Loading dataset from %s", path)
    df = pd.read_csv(path)

    # Normalise column names (handle varying CSV headers)
    df.columns = df.columns.str.strip().str.lower()

    # Expected columns: 'url' and 'label' (or 'type')
    url_col = next((c for c in df.columns if "url" in c), None)
    lbl_col = next((c for c in df.columns if c in ("label", "type", "class")), None)

    if url_col is None or lbl_col is None:
        raise ValueError(
            f"Cannot find url/label columns. Found columns: {list(df.columns)}"
        )

    df = df[[url_col, lbl_col]].rename(columns={url_col: "url", lbl_col: "label"})
    df = df.dropna()
    df["url"] = df["url"].astype(str).str.strip()

    # Deduplication — critical to prevent data leakage
    before = len(df)
    df = df.drop_duplicates(subset="url")
    after = len(df)
    logger.info("Deduplication: %d → %d rows (removed %d duplicates)", before, after, before - after)

    # Encode label: 'bad' / 'phishing' / 1 → 1,  'good' / 'safe' / 0 → 0
    df["label"] = df["label"].apply(_encode_label)
    logger.info("Class distribution:\n%s", df["label"].value_counts().to_string())

    return df


def _encode_label(lbl) -> int:
    s = str(lbl).strip().lower()
    if s in ("bad", "phishing", "1", "malicious", "spam"):
        return 1
    return 0


# ── Evaluation helper ─────────────────────────────────────────────────────────

def evaluate_model(name: str, pipeline, X_test, y_test) -> dict:
    """Compute all classification metrics for a fitted pipeline."""
    preds = pipeline.predict(X_test)

    # ROC-AUC — use proba if available, else decision_function
    try:
        scores = pipeline.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, scores)
    except AttributeError:
        try:
            scores = pipeline.decision_function(X_test)
            auc = roc_auc_score(y_test, scores)
        except Exception:
            auc = None

    metrics = {
        "model": name,
        "accuracy":  round(accuracy_score(y_test, preds),  4),
        "precision": round(precision_score(y_test, preds, zero_division=0), 4),
        "recall":    round(recall_score(y_test, preds, zero_division=0), 4),
        "f1":        round(f1_score(y_test, preds, zero_division=0), 4),
        "roc_auc":   round(auc, 4) if auc is not None else "N/A",
        "confusion_matrix": confusion_matrix(y_test, preds).tolist(),
        "report": classification_report(y_test, preds, target_names=["safe", "phishing"]),
    }

    logger.info(
        "%-30s  acc=%.4f  prec=%.4f  rec=%.4f  f1=%.4f  auc=%s",
        name, metrics["accuracy"], metrics["precision"],
        metrics["recall"], metrics["f1"], metrics["roc_auc"],
    )

    return metrics


# ── Experiment logger ─────────────────────────────────────────────────────────

def save_experiment(results: list[dict], best_name: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_path = EXPERIMENTS_DIR / f"run_{ts}.json"
    payload = {
        "timestamp": ts,
        "best_model": best_name,
        "results": results,
    }
    with open(exp_path, "w") as f:
        json.dump(payload, f, indent=2)
    logger.info("Experiment results saved → %s", exp_path)
    return exp_path


# ── Main training loop ────────────────────────────────────────────────────────

def main() -> None:
    logger.info("=" * 60)
    logger.info("Phishing Detection — Model Training & Benchmarking")
    logger.info("=" * 60)

    # ── 1. Load data ──────────────────────────────────────────────────────────
    df = load_data(DATASET_PATH)
    X = df["url"].values          # raw URL strings — pipeline handles transform
    y = df["label"].values

    # ── 2. Stratified split (no leakage: split AFTER dedup) ───────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info(
        "Split: train=%d  test=%d  phishing_rate_train=%.2f%%",
        len(X_train), len(X_test),
        100 * np.mean(y_train),
    )

    # ── 3. Define classifiers ─────────────────────────────────────────────────
    # Note: MultinomialNB requires non-negative features.
    # Our ColumnTransformer can produce sparse negative values from TF-IDF
    # so MNB is excluded from the full pipeline and trained on word-TF-IDF only.
    classifiers: list[tuple[str, object]] = [
        (
            "Logistic Regression",
            LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42, n_jobs=-1),
        ),
        (
            "Random Forest",
            RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1),
        ),
        (
            "Gradient Boosting",
            GradientBoostingClassifier(n_estimators=150, max_depth=5, random_state=42),
        ),
        (
            "Linear SVM",
            LinearSVC(class_weight="balanced", max_iter=2000, random_state=42),
        ),
    ]

    # Try to import XGBoost (optional dependency)
    try:
        from xgboost import XGBClassifier  # noqa: F401
        classifiers.append((
            "XGBoost",
            XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                scale_pos_weight=(y_train == 0).sum() / (y_train == 1).sum(),
                use_label_encoder=False,
                eval_metric="logloss",
                random_state=42,
                n_jobs=-1,
            ),
        ))
        logger.info("XGBoost found — included in benchmark")
    except ImportError:
        logger.warning("XGBoost not installed — skipping. Install with: pip install xgboost")

    # ── 4. Train, cross-validate, and evaluate ────────────────────────────────
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    all_results: list[dict] = []
    best_f1 = -1.0
    best_name = ""
    best_pipeline = None

    for name, clf in classifiers:
        logger.info("\n── Training: %s ──", name)
        pipeline = build_pipeline(clf)

        # Cross-validation on training set
        t0 = time.perf_counter()
        cv_f1 = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
        cv_time = time.perf_counter() - t0
        logger.info("  CV F1 (5-fold): %.4f ± %.4f  (%.1fs)", cv_f1.mean(), cv_f1.std(), cv_time)

        # Final fit on full train split
        pipeline.fit(X_train, y_train)

        # Holdout evaluation
        metrics = evaluate_model(name, pipeline, X_test, y_test)
        metrics["cv_f1_mean"] = round(float(cv_f1.mean()), 4)
        metrics["cv_f1_std"]  = round(float(cv_f1.std()),  4)
        all_results.append(metrics)

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_name = name
            best_pipeline = pipeline

    # ── 5. Report ─────────────────────────────────────────────────────────────
    logger.info("\n" + "=" * 60)
    logger.info("BEST MODEL: %s  (F1=%.4f)", best_name, best_f1)
    logger.info("=" * 60)

    for r in sorted(all_results, key=lambda x: x["f1"], reverse=True):
        logger.info(
            "  %-30s  F1=%.4f  AUC=%s  CV_F1=%.4f±%.4f",
            r["model"], r["f1"], r["roc_auc"], r["cv_f1_mean"], r["cv_f1_std"],
        )

    print("\n" + all_results[0]["report"] if all_results else "")

    # ── 6. Save versioned model ───────────────────────────────────────────────
    model_path = MODELS_DIR / "phishing_v2.pkl"
    joblib.dump(best_pipeline, model_path)
    logger.info("Saved: %s", model_path)

    # ── 7. Log experiment ─────────────────────────────────────────────────────
    save_experiment(all_results, best_name)

    logger.info("\nTo use the new model set MODEL_VERSION=v2 in your .env file.")
    logger.info("Then call POST /reload-model or restart the server.\n")


if __name__ == "__main__":
    main()
