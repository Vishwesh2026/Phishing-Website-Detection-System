"""
training/train_deep.py
─────────────────────────────────────────────────────────────
Stage 2: Deep Model Training Pipeline

Trains an XGBoost classifier (with probability calibration) on
dataset_full.csv (88k rows, 111 structured features including
DNS, SSL, ASN, WHOIS timing, and URL char-count features).

Saved artifacts:
  models/phishing_deep_v1.pkl      — calibrated XGBoost pipeline
  models/deep_feature_cols.json    — canonical 111-column order
  models/deep_feature_stats.json   — per-column training statistics
                                     (used by runtime drift guard)
  experiments/metrics.json         — latest holdout evaluation metrics
                                     (read by GET /api/v1/metrics)

Usage:
    cd <project_root>
    python -m training.train_deep
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
from sklearn.calibration import CalibratedClassifierCV
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

DATASET_PATH  = _ROOT / "Dataset" / "dataset_full.csv"
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

LABEL_COL = "phishing"

# ── Sentinel / Missing Value Policy ──────────────────────────────────────────
# dataset_full uses -1 as a sentinel for "unavailable" (WHOIS, DNS, etc.)
# We impute these with the column median so XGBoost can handle them properly.
SENTINEL_VALUE = -1


from app.utils.deep_model_bundle import DeepModelBundle


# ── Data Loading ──────────────────────────────────────────────────────────────

def load_data(path: Path) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Load dataset_full, separate label, return X DataFrame, y Series, feature cols."""
    logger.info("Loading dataset from %s", path)
    df = pd.read_csv(path)
    logger.info("Dataset shape: %d rows × %d cols", *df.shape)

    if LABEL_COL not in df.columns:
        raise ValueError(f"Label column '{LABEL_COL}' not found. Columns: {list(df.columns)}")

    # Drop rows where label is null
    before = len(df)
    df = df.dropna(subset=[LABEL_COL])
    logger.info("Dropped %d null-label rows", before - len(df))

    y = df[LABEL_COL].astype(int)
    feature_cols = [c for c in df.columns if c != LABEL_COL]
    X = df[feature_cols].copy()

    logger.info(
        "Label distribution:\n%s",
        y.value_counts().rename({0: "safe", 1: "phishing"}).to_string()
    )
    logger.info("Feature count: %d", len(feature_cols))
    return X, y, feature_cols


# ── Feature Stats (Drift Guard Baseline) ─────────────────────────────────────

def compute_feature_stats(X: pd.DataFrame) -> dict:
    """
    Compute per-column training statistics for runtime drift detection.
    Sentinel values (-1) are excluded from stats computation since they
    represent "unknown" rather than real measurements.
    """
    stats = {}
    for col in X.columns:
        col_data = X[col][X[col] != SENTINEL_VALUE]
        if col_data.empty:
            stats[col] = {"mean": -1.0, "std": 0.0, "min": -1.0, "max": -1.0}
        else:
            stats[col] = {
                "mean": round(float(col_data.mean()), 6),
                "std":  round(float(col_data.std()),  6),
                "min":  round(float(col_data.min()),  6),
                "max":  round(float(col_data.max()),  6),
            }
    return stats


# ── Model Evaluation ─────────────────────────────────────────────────────────

def evaluate(y_test: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> dict:
    auc = roc_auc_score(y_test, y_proba)
    metrics = {
        "accuracy":  round(float(accuracy_score(y_test, y_pred)),   4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_test, y_pred,    zero_division=0)), 4),
        "f1":        round(float(f1_score(y_test, y_pred,         zero_division=0)), 4),
        "roc_auc":   round(float(auc), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }
    logger.info(
        "  acc=%.4f  prec=%.4f  rec=%.4f  f1=%.4f  AUC=%.4f",
        metrics["accuracy"], metrics["precision"],
        metrics["recall"], metrics["f1"], metrics["roc_auc"],
    )
    return metrics


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    logger.info("=" * 60)
    logger.info("Phishing Detection — Stage 2 Deep Model Training")
    logger.info("=" * 60)

    # 1. Load data
    X, y, feature_cols = load_data(DATASET_PATH)

    # 2. Compute and save training distribution stats BEFORE imputation
    #    (stats represent the raw data distribution the model was built on)
    logger.info("Computing feature distribution stats for drift guard...")
    feature_stats = compute_feature_stats(X)

    # 3. Three-way split: train / calibration / test
    # We train XGBoost on train_set, calibrate on cal_set, evaluate on test_set.
    # This avoids cv='isotonic' cross-validation which conflicts with Pipeline internals.
    X_train_cv, X_test, y_train_cv, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    X_train, X_cal, y_train, y_cal = train_test_split(
        X_train_cv, y_train_cv, test_size=0.20, random_state=42, stratify=y_train_cv
    )
    logger.info(
        "Split: train=%d  cal=%d  test=%d  phishing_rate_train=%.2f%%",
        len(X_train), len(X_cal), len(X_test), 100 * y_train.mean()
    )


    # 4. Class imbalance weight
    safe_count    = (y_train == 0).sum()
    phish_count   = (y_train == 1).sum()
    scale_pos_weight = safe_count / phish_count
    logger.info("scale_pos_weight=%.4f  (safe=%d / phishing=%d)", scale_pos_weight, safe_count, phish_count)

    # 5. Impute -1 sentinels with median BEFORE fitting.
    logger.info("Fitting imputer on training data...")
    imputer = SimpleImputer(missing_values=SENTINEL_VALUE, strategy="median")
    X_train_imp = imputer.fit_transform(X_train.values)
    X_cal_imp   = imputer.transform(X_cal.values)
    X_test_imp  = imputer.transform(X_test.values)

    # 6. Train XGBoost
    logger.info("Training XGBoost on train set (%d samples)...", len(X_train_imp))
    xgb = XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="auc",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    t0 = time.perf_counter()
    xgb.fit(X_train_imp, y_train.values)
    logger.info("XGB fit complete in %.1fs", time.perf_counter() - t0)

    # 7. Probability calibration via IsotonicRegression on held-out cal set.
    #    (Equivalent to CalibratedClassifierCV(method='isotonic', cv='prefit')
    #     but compatible with sklearn 1.6 + XGBoost 2.x)
    from sklearn.isotonic import IsotonicRegression
    logger.info("Calibrating probabilities on cal set (%d samples)...", len(X_cal_imp))
    raw_cal_proba = xgb.predict_proba(X_cal_imp)[:, 1]
    iso_regressor = IsotonicRegression(out_of_bounds="clip")
    iso_regressor.fit(raw_cal_proba, y_cal.values)

    elapsed = time.perf_counter() - t0
    logger.info("Training + calibration complete in %.1f seconds", elapsed)

    # 8. Bundle: imputer → XGB → isotonic calibration (module-level for pickling)
    model_bundle = DeepModelBundle(
        imputer=imputer,
        xgb=xgb,
        iso_regressor=iso_regressor,
    )


    # 9. Evaluate on holdout set
    logger.info("\n── Holdout Evaluation ──")
    y_pred  = model_bundle.predict(X_test.values)
    y_proba = model_bundle.predict_proba(X_test.values)[:, 1]


    metrics = evaluate(y_test.values, y_pred, y_proba)

    logger.info("\nClassification Report:\n%s",
        classification_report(y_test, y_pred, target_names=["safe", "phishing"]))

    # 10. Save model bundle (imputer + calibrated XGB)
    model_path = MODELS_DIR / "phishing_deep_v1.pkl"
    joblib.dump(model_bundle, model_path)
    logger.info("✓ Model saved: %s", model_path)

    # 8. Save canonical feature column order
    cols_path = MODELS_DIR / "deep_feature_cols.json"
    with open(cols_path, "w") as f:
        json.dump(feature_cols, f, indent=2)
    logger.info("✓ Feature cols saved: %s", cols_path)

    # 9. Save feature distribution stats (drift guard baseline)
    stats_path = MODELS_DIR / "deep_feature_stats.json"
    with open(stats_path, "w") as f:
        json.dump(feature_stats, f, indent=2)
    logger.info("✓ Feature stats saved: %s", stats_path)

    # 10. Save experiment log
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_path = EXPERIMENTS_DIR / f"deep_run_{ts}.json"
    with open(exp_path, "w") as f:
        json.dump({
            "timestamp": ts,
            "model": "XGBoost + CalibratedClassifierCV(isotonic, cv=5)",
            "dataset": str(DATASET_PATH),
            "n_features": len(feature_cols),
            "train_size": len(X_train),
            "test_size":  len(X_test),
            "training_seconds": round(elapsed, 2),
            "metrics": metrics,
        }, f, indent=2)
    logger.info("✓ Experiment log saved: %s", exp_path)

    # 11. Save standardised metrics.json for homepage display
    metrics_path = EXPERIMENTS_DIR / "metrics.json"
    metrics_export = {
        "model": "XGBoost + Isotonic Calibration",
        "accuracy":        metrics["accuracy"],
        "precision":       metrics["precision"],
        "recall":          metrics["recall"],
        "f1_score":        metrics["f1"],
        "roc_auc":         metrics["roc_auc"],
        "confusion_matrix": metrics["confusion_matrix"],
        "dataset_size":    int(len(X_train.index) + len(X_test.index)),
        "train_size":      int(len(X_train.index)),
        "test_size":       int(len(X_test.index)),
        "n_features":      len(feature_cols),
        "trained_at":      datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with open(metrics_path, "w") as f:
        json.dump(metrics_export, f, indent=2)
    logger.info("✓ Metrics summary saved: %s", metrics_path)

    logger.info("\n" + "=" * 60)
    logger.info("STAGE 2 TRAINING COMPLETE")
    logger.info("  ROC-AUC : %.4f", metrics["roc_auc"])
    logger.info("  F1 Score: %.4f", metrics["f1"])
    logger.info("=" * 60)
    logger.info("\nTo activate deep model, restart the API server.")
    logger.info("Set DEEP_MODEL_VERSION=v1 in your .env file.")


if __name__ == "__main__":
    main()
