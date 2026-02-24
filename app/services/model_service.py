"""
app/services/model_service.py
─────────────────────────────────────────────────────────────
Single-model ModelService: loads phishing_deep_v1.pkl (XGBoost +
IsotonicRegression calibration, wrapped in DeepModelBundle).

  predict(feature_dict) → {prediction, label, confidence, risk_level, latency_ms}

Drift guard logs a WARNING for any feature value > 3σ from its
training distribution.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.config import settings
from app.utils.deep_model_bundle import DeepModelBundle  # ensures joblib can unpickle

logger = logging.getLogger(__name__)


# ── Risk helpers ─────────────────────────────────────────────────────────────

def _label_from_proba(phishing_proba: float, threshold: float) -> int:
    return 1 if phishing_proba >= threshold else 0


def _risk_level(confidence: float, label: int) -> str:
    if label == 1:
        if confidence >= 0.85: return "HIGH"
        if confidence >= 0.60: return "MEDIUM"
        return "LOW"
    return "LOW"


# ── Service ───────────────────────────────────────────────────────────────────

class ModelService:
    """
    Loads and serves the single deep XGBoost phishing model.

    Call load() at startup (done by app/main.py lifespan).
    Call predict(feature_dict) for inference.
    """

    def __init__(self) -> None:
        self._pipeline: DeepModelBundle | None = None
        self._version:  str | None = None
        self._loaded:   bool = False
        self._feature_cols:  list[str] = []
        self._feature_stats: dict[str, dict] = {}

    # ── Loading ───────────────────────────────────────────────────────────────

    def load(self) -> None:
        """Load model + metadata from disk. Raises on failure (fatal at startup)."""
        model_path = settings.model_path
        cols_path  = settings.feature_cols_path
        stats_path = settings.feature_stats_path

        if not model_path.exists():
            raise FileNotFoundError(
                f"Deep model not found at {model_path}. "
                "Run: python -m training.train_deep"
            )

        logger.info("Loading model from %s", model_path)
        t0 = time.perf_counter()
        self._pipeline = joblib.load(model_path)
        elapsed = (time.perf_counter() - t0) * 1000

        # Feature columns (canonical order for vector building)
        if cols_path.exists():
            with open(cols_path) as f:
                self._feature_cols = json.load(f)
            logger.info("Feature cols loaded: %d features", len(self._feature_cols))
        else:
            logger.warning("deep_feature_cols.json not found — using built-in FEATURE_COLS")
            from app.utils.deep_feature_extractor import FEATURE_COLS
            self._feature_cols = FEATURE_COLS

        # Feature stats (drift guard baseline)
        if stats_path.exists():
            with open(stats_path) as f:
                self._feature_stats = json.load(f)
            logger.info("Feature stats loaded — drift guard active")
        else:
            logger.warning("deep_feature_stats.json not found — drift guard disabled")

        self._version = settings.MODEL_VERSION
        self._loaded  = True
        logger.info("Model loaded in %.1f ms (version=%s)", elapsed, self._version)

    def reload(self) -> None:
        """Hot-reload model from disk (called by /reload-model endpoint)."""
        logger.info("Hot-reloading model...")
        self._loaded = False
        self.load()

    # ── Drift Guard ───────────────────────────────────────────────────────────

    def _check_drift(self, feature_dict: dict[str, Any]) -> None:
        """Log a WARNING for any feature > 3σ outside its training distribution.
        Sentinel -1 values are excluded (they indicate 'unavailable')."""
        if not self._feature_stats:
            return
        for col, val in feature_dict.items():
            if val == -1:
                continue
            stats = self._feature_stats.get(col)
            if not stats:
                continue
            mean, std = stats["mean"], stats["std"]
            if std > 0 and abs(val - mean) > 3 * std:
                logger.warning(
                    "DRIFT  feature=%s  val=%.4f  train_mean=%.4f  train_std=%.4f"
                    "  train_range=[%.4f, %.4f]",
                    col, val, mean, std, stats["min"], stats["max"],
                )

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, feature_dict: dict[str, Any]) -> dict:
        """
        Run deep model inference on a 111-feature dict.

        Args:
            feature_dict: Output of DeepFeatureExtractor.extract().

        Returns:
            dict with keys: prediction, label, confidence, risk_level, latency_ms.

        Raises:
            RuntimeError: If model is not loaded.
        """
        if not self._loaded or self._pipeline is None:
            raise RuntimeError("Model not loaded. Call load() first.")

        # ── Feature vector validation ─────────────────────────────────────────
        from app.utils.deep_feature_extractor import to_vector
        vec = to_vector(feature_dict, self._feature_cols)
        if len(vec) != 111:
            logger.error(
                "Feature vector length mismatch: expected 111, got %d. "
                "Check deep_feature_cols.json matches FEATURE_COLS.",
                len(vec),
            )

        # ── Drift guard ───────────────────────────────────────────────────────
        self._check_drift(feature_dict)

        # ── Inference ─────────────────────────────────────────────────────────
        X = np.array(vec, dtype=np.float64).reshape(1, -1)
        t0 = time.perf_counter()
        proba = self._pipeline.predict_proba(X)[0]
        latency_ms = (time.perf_counter() - t0) * 1000

        phishing_proba = float(proba[1])
        label      = _label_from_proba(phishing_proba, settings.PHISHING_THRESHOLD)
        confidence = float(proba[label])
        prediction = "phishing" if label == 1 else "safe"
        risk       = _risk_level(confidence, label)

        logger.info(
            "PREDICT  pred=%s  conf=%.4f  phishing_proba=%.4f  latency=%.2fms",
            prediction, confidence, phishing_proba, latency_ms,
        )
        return {
            "prediction": prediction,
            "label":      label,
            "confidence": round(confidence, 4),
            "risk_level": risk,
            "latency_ms": round(latency_ms, 2),
        }

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def version(self) -> str | None:
        return self._version


# ── Singleton + FastAPI dependency ────────────────────────────────────────────

_model_service = ModelService()


def get_model_service() -> ModelService:
    """FastAPI dependency — injects the global ModelService singleton."""
    return _model_service
