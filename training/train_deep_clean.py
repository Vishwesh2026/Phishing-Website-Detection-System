"""
training/train_deep_clean.py
──────────────────────────────────────────────────────────────────────────────
Phase 2 — Train and calibrate XGBoost on the generated_training_dataset_clean.csv.

Calibration strategy:
  Uses a three-way train/cal/test split + IsotonicRegression (prefit pattern).
  This avoids the sklearn 1.7 + XGBoost 2.x incompatibility with
  CalibratedClassifierCV(cv=N) which requires __sklearn_tags__ not yet
  implemented by XGBoost.  The prefit approach is identical to train_deep.py.

Features a full training pipeline:
  - Stratified 80/10/10 split (train / calibration / test)
  - SimpleImputer for -1 sentinels
  - XGBClassifier with scale_pos_weight class balancing
  - IsotonicRegression fitted on a dedicated calibration set (prefit)
  - Full evaluation metrics (accuracy, precision, recall, F1, ROC-AUC, CM)
  - Writes model to models/phishing_deep_clean_v1.pkl
  - Writes canonical feature list to models/deep_feature_cols_clean.json
  - Exports training metrics to experiments/metrics_clean.json

Phase 3 — Sanity validation on known-safe domains.

USAGE
─────
  cd 'e:\\4-2\\Vish\\Phishing-Website-Detection-System'
  python -m training.train_deep_clean

Run AFTER:
  python -m training.generate_training_dataset
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pickle

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_clean")

# ── Configuration ─────────────────────────────────────────────────────────────
DATASET_CSV       = ROOT / "Dataset" / "generated_training_dataset_clean.csv"
MODEL_OUT         = ROOT / "models" / "phishing_deep_clean_v1.pkl"
FEATURE_JSON_IN   = ROOT / "models" / "deep_feature_cols_clean.json"
FEATURE_JSON_OUT  = ROOT / "models" / "deep_feature_cols_clean.json"
METRICS_JSON      = ROOT / "experiments" / "metrics_clean.json"

SENTINEL_VALUE    = -1
LABEL_COL         = "label"
TEST_SIZE         = 0.20
RANDOM_STATE      = 42


# ── Utility ───────────────────────────────────────────────────────────────────

def load_data(path: Path) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    logger.info("Loading dataset from %s", path)
    df = pd.read_csv(path, low_memory=False)
    logger.info("Raw shape: %d rows × %d cols", *df.shape)

    if LABEL_COL not in df.columns:
        raise ValueError(f"Label column '{LABEL_COL}' not found. Columns: {list(df.columns)}")

    df = df.dropna(subset=[LABEL_COL])
    # Replace any NaN with sentinel
    df = df.fillna(SENTINEL_VALUE)

    y = df[LABEL_COL].astype(int)
    feature_cols = [c for c in df.columns if c != LABEL_COL]
    X = df[feature_cols].copy()

    vc = y.value_counts().rename({0: "safe", 1: "phishing"})
    logger.info("Label distribution:\n%s", vc.to_string())
    logger.info("Feature columns: %d", len(feature_cols))

    return X, y, feature_cols


def evaluate(y_test: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> dict:
    auc = roc_auc_score(y_test, y_proba)
    cm  = confusion_matrix(y_test, y_pred)
    metrics = {
        "accuracy":         round(float(accuracy_score(y_test, y_pred)), 4),
        "precision":        round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall":           round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1":               round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "roc_auc":          round(float(auc), 4),
        "confusion_matrix": cm.tolist(),
    }
    logger.info(
        "  acc=%.4f  prec=%.4f  rec=%.4f  f1=%.4f  AUC=%.4f",
        metrics["accuracy"], metrics["precision"], metrics["recall"],
        metrics["f1"], metrics["roc_auc"],
    )
    tn, fp, fn, tp = cm.ravel()
    logger.info("  Confusion Matrix:  TP=%d  FP=%d  TN=%d  FN=%d", tp, fp, tn, fn)
    return metrics


def main() -> None:
    logger.info("=" * 65)
    logger.info("Phishing Detector — Training on Clean Generated Dataset")
    logger.info("=" * 65)

    if not DATASET_CSV.exists():
        logger.error(
            "Dataset not found: %s\n"
            "Run: python -m training.generate_training_dataset   first.",
            DATASET_CSV,
        )
        sys.exit(1)

    # 1. Load
    X, y, feature_cols = load_data(DATASET_CSV)

    # 2. Save / validate feature column list
    if FEATURE_JSON_IN.exists():
        expected_cols = json.loads(FEATURE_JSON_IN.read_text())
        missing = set(expected_cols) - set(feature_cols)
        extra   = set(feature_cols) - set(expected_cols)
        if missing:
            logger.warning("Missing expected columns: %s", missing)
        if extra:
            logger.warning("Unexpected extra columns in CSV: %s", extra)
        # Align to expected order
        feature_cols = [c for c in expected_cols if c in feature_cols]
        X = X[feature_cols]
        logger.info("Aligned to feature JSON: %d columns", len(feature_cols))
    else:
        logger.info("No existing feature JSON found; using CSV column order.")

    # 3. Three-way stratified split: 70% train / 10% calibration / 20% test
    # Calibration set is held out from training and used to fit IsotonicRegression
    # on raw XGB probabilities (prefit pattern, avoids sklearn/XGBoost compat issue)
    X_train_cv, X_test, y_train_cv, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )
    X_train, X_cal, y_train, y_cal = train_test_split(
        X_train_cv, y_train_cv, test_size=0.125, random_state=RANDOM_STATE, stratify=y_train_cv
    )  # 0.125 of 80% ≈ 10% of total
    logger.info(
        "Split: train=%d  cal=%d  test=%d  phishing_rate_train=%.2f%%",
        len(X_train), len(X_cal), len(X_test), 100 * y_train.mean()
    )

    # 4. Impute sentinel -1 values with median
    # Note: columns filled entirely with -1 produce a FutureWarning; we catch
    # these and leave them at -1 (their only value) as the imputer has nothing to do.
    logger.info("Imputing sentinel values (-1) with median...")
    imputer = SimpleImputer(missing_values=SENTINEL_VALUE, strategy="median")
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        X_train_imp = imputer.fit_transform(X_train.values)
        X_cal_imp   = imputer.transform(X_cal.values)
        X_test_imp  = imputer.transform(X_test.values)

    # 5. Class imbalance weight
    safe_count   = (y_train == 0).sum()
    phish_count  = (y_train == 1).sum()
    scale_pos_weight = safe_count / max(phish_count, 1)
    logger.info(
        "scale_pos_weight=%.4f  (safe=%d  phishing=%d)",
        scale_pos_weight, safe_count, phish_count
    )

    # 6. Train XGBClassifier on train set
    logger.info("Training XGBoost classifier (%d samples)...", len(X_train_imp))
    xgb = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="auc",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbosity=0,
    )
    t0 = time.perf_counter()
    xgb.fit(X_train_imp, y_train.values)
    logger.info("XGB training complete in %.1fs", time.perf_counter() - t0)

    # 7. Isotonic calibration on held-out calibration set (prefit, sklearn-safe)
    # CalibratedClassifierCV(cv=N) requires __sklearn_tags__ on XGBoost (not yet
    # implemented in XGBoost 2.x against sklearn 1.7). We instead:
    #   a) get raw probabilities on the cal set from the already-trained XGB
    #   b) fit IsotonicRegression mapping raw_prob → calibrated_prob
    # This is mathematically equivalent to CalibratedClassifierCV(cv='prefit').
    logger.info("Calibrating via IsotonicRegression on cal set (%d samples)...", len(X_cal_imp))
    raw_cal_proba = xgb.predict_proba(X_cal_imp)[:, 1]
    iso = IsotonicRegression(out_of_bounds="clip")
    iso.fit(raw_cal_proba, y_cal.values)
    logger.info("Isotonic calibration complete.")

    # 8. Evaluate on test set using the two-step inference pipeline
    logger.info("Evaluating on holdout test set (%d samples)...", len(X_test_imp))
    raw_test_proba  = xgb.predict_proba(X_test_imp)[:, 1]
    y_proba         = iso.predict(raw_test_proba)         # calibrated
    y_pred          = (y_proba >= 0.5).astype(int)

    metrics = evaluate(y_test.values, y_pred, y_proba)
    metrics["dataset_size"]  = len(X)
    metrics["feature_count"] = len(feature_cols)
    metrics["trained_at"]   = time.strftime("%Y%m%dT%H%M%S")
    metrics["model_file"]   = MODEL_OUT.name

    # 9. Save model bundle (same structure as DeepModelBundle for compatibility)
    # We store imputer + xgb + iso_regressor + feature_cols so that
    # validate_clean_model.py and future model_service adapters can load this.
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_OUT, "wb") as f:
        pickle.dump({
            "imputer":       imputer,
            "xgb":           xgb,
            "iso_regressor": iso,
            "feature_cols":  feature_cols,
        }, f, protocol=5)
    logger.info("Saved model: %s", MODEL_OUT)

    # 10. Save canonical feature list
    FEATURE_JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    FEATURE_JSON_OUT.write_text(json.dumps(feature_cols, indent=2))
    logger.info("Saved feature list: %s  (%d features)", FEATURE_JSON_OUT, len(feature_cols))

    # 11. Save metrics JSON
    METRICS_JSON.parent.mkdir(parents=True, exist_ok=True)
    METRICS_JSON.write_text(json.dumps(metrics, indent=2))
    logger.info("Saved eval metrics: %s", METRICS_JSON)
    logger.info("=" * 65)
    logger.info("Training complete! Metrics summary:")
    for k, v in metrics.items():
        if k not in ("confusion_matrix", "trained_at", "model_file"):
            logger.info("  %-22s %s", k + ":", v)
    logger.info("=" * 65)
    logger.info("")
    logger.info("NEXT STEPS:")
    logger.info("  1. Run: python -m training.validate_clean_model")
    logger.info("  2. Update .env: MODEL_VERSION=clean_v1 (or copy the .pkl appropriately)")
    logger.info("  3. Hit: curl -X POST http://127.0.0.1:8000/reload-model")


if __name__ == "__main__":
    main()
