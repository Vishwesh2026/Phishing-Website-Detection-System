"""
app/services/model_service.py
─────────────────────────────────────────────────────────────
ModelService encapsulates all ML inference logic.

• Loads a versioned sklearn pipeline from models/ at startup.
• Provides predict() which returns label, confidence, and latency.
• Exposes a FastAPI dependency (get_model_service) for injection.
• Supports hot-reload via reload() method.

Security note
─────────────
We use joblib (not raw pickle) which gives slightly better safety guarantees.
For truly hardened production systems, consider exporting the model with
skops (https://skops.readthedocs.io) or ONNX, which avoids arbitrary code
execution risks entirely.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

import joblib
import numpy as np

from app.config import settings

logger = logging.getLogger(__name__)


# ── Risk level thresholds ─────────────────────────────────────────────────────

def _confidence_to_risk(confidence: float, label: int) -> str:
    """Map prediction confidence to a human-readable risk level."""
    if label == 1:                    # phishing
        if confidence >= 0.85:
            return "HIGH"
        if confidence >= 0.60:
            return "MEDIUM"
        return "LOW"
    return "LOW"                      # safe URLs always LOW risk


# ── URL cleaning ──────────────────────────────────────────────────────────────

def _clean_url(url: str) -> str:
    """Remove protocol + optional www for consistent tokenisation.

    Kept here so it mirrors the exact logic used during training/train.py.
    """
    return re.sub(r"^https?://(www\.)?", "", url)


# ── Service class ─────────────────────────────────────────────────────────────

class ModelService:
    """
    Singleton service that manages model lifecycle and inference.

    The pipeline stored in the .pkl file is a complete sklearn Pipeline
    (preprocessor + classifier) built by feature_engineering.build_pipeline().
    """

    def __init__(self) -> None:
        self._pipeline = None
        self._version: str | None = None
        self._loaded: bool = False

    # ── Loading ───────────────────────────────────────────────────────────────

    def load(self) -> None:
        """Load model pipeline from disk.  Called once at application startup."""
        model_path: Path = settings.model_path

        # Fallback: if new-style pipeline doesn't exist, load legacy pkl pair
        if not model_path.exists():
            logger.warning(
                "Versioned model %s not found. Falling back to legacy phishing.pkl + vectorizer.pkl",
                model_path,
            )
            self._load_legacy()
            return

        logger.info("Loading model pipeline from %s", model_path)
        t0 = time.perf_counter()
        loaded_obj = joblib.load(model_path)
        elapsed = (time.perf_counter() - t0) * 1000

        # If object is a full sklearn Pipeline, use it directly.
        # If it's a raw classifier (legacy copy), wrap with vectorizer.
        if hasattr(loaded_obj, "steps"):
            # Full sklearn Pipeline built by build_pipeline() — use directly
            self._pipeline = loaded_obj
        else:
            # Raw classifier — wrap with legacy vectorizer for compatibility
            logger.warning(
                "Loaded object is not a full Pipeline (type=%s). "
                "Wrapping with legacy vectorizer.pkl.",
                type(loaded_obj).__name__,
            )
            self._pipeline = self._wrap_with_vectorizer(loaded_obj)

        self._version = settings.MODEL_VERSION
        self._loaded = True
        logger.info("Model loaded in %.1f ms  (version=%s)", elapsed, self._version)

    def _load_legacy(self) -> None:
        """
        Backward-compatible loader for the old two-file format
        (vectorizer.pkl + phishing.pkl).  Wraps them in a tiny callable.
        """
        import pickle
        from pathlib import Path

        root = settings.MODEL_DIR.parent          # project root
        vec_path = root / "vectorizer.pkl"
        mdl_path = root / "phishing.pkl"

        if not vec_path.exists() or not mdl_path.exists():
            raise FileNotFoundError(
                f"Could not find model files. Expected either "
                f"{settings.model_path} or legacy vectorizer.pkl + phishing.pkl"
            )

        with open(vec_path, "rb") as f:
            vectorizer = pickle.load(f)
        with open(mdl_path, "rb") as f:
            model = pickle.load(f)

        class _LegacyPipeline:
            def predict(self, urls):
                cleaned = [re.sub(r"^https?://(www\.)?", "", u) for u in urls]
                return model.predict(vectorizer.transform(cleaned))

            def predict_proba(self, urls):
                cleaned = [re.sub(r"^https?://(www\.)?", "", u) for u in urls]
                try:
                    return model.predict_proba(vectorizer.transform(cleaned))
                except AttributeError:
                    labels = self.predict(urls)
                    proba = np.zeros((len(labels), 2))
                    for i, lbl in enumerate(labels):
                        lbl_int = 1 if lbl in ("bad", 1, "phishing") else 0
                        proba[i, lbl_int] = 1.0
                    return proba

        self._pipeline = _LegacyPipeline()
        self._version = "v1-legacy"
        self._loaded = True
        logger.info("Legacy model loaded (vectorizer.pkl + phishing.pkl)")

    def _wrap_with_vectorizer(self, model) -> object:
        """
        Wraps a raw sklearn classifier with the legacy vectorizer.pkl
        so it behaves like a Pipeline with predict() / predict_proba()
        that accepts raw URL strings.
        """
        import pickle
        root = settings.MODEL_DIR.parent
        vec_path = root / "vectorizer.pkl"
        if not vec_path.exists():
            raise FileNotFoundError(
                f"vectorizer.pkl not found at {vec_path}. "
                "Cannot wrap raw model without the vectorizer."
            )
        with open(vec_path, "rb") as f:
            vectorizer = pickle.load(f)

        class _WrappedPipeline:
            def predict(self, urls):
                cleaned = [re.sub(r"^https?://(www\.)?", "", u) for u in urls]
                return model.predict(vectorizer.transform(cleaned))

            def predict_proba(self, urls):
                cleaned = [re.sub(r"^https?://(www\.)?", "", u) for u in urls]
                try:
                    return model.predict_proba(vectorizer.transform(cleaned))
                except AttributeError:
                    labels = self.predict(urls)
                    proba = np.zeros((len(labels), 2))
                    for i, lbl in enumerate(labels):
                        lbl_int = 1 if lbl in ("bad", 1, "phishing") else 0
                        proba[i, lbl_int] = 1.0
                    return proba

        return _WrappedPipeline()



    def reload(self) -> None:
        """Hot-reload the model from disk (e.g. after retraining)."""
        logger.info("Hot-reloading model...")
        self.load()

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, url: str) -> dict:
        """
        Run phishing inference on a URL.

        Returns:
            {
                "prediction": "phishing" | "safe",
                "label":      1          | 0,
                "confidence": float,     # probability of predicted class
                "risk_level": "HIGH" | "MEDIUM" | "LOW",
                "latency_ms": float,
            }
        """
        if not self._loaded or self._pipeline is None:
            raise RuntimeError("Model is not loaded. Call load() first.")

        t0 = time.perf_counter()
        urls = [url]

        raw_pred = self._pipeline.predict(urls)[0]
        label = int(raw_pred in ("bad", 1, "phishing", True))

        # Probability / confidence
        try:
            proba = self._pipeline.predict_proba(urls)[0]
            confidence = float(proba[label])
        except Exception:
            confidence = 1.0 if label else 0.0

        latency_ms = (time.perf_counter() - t0) * 1000
        prediction = "phishing" if label == 1 else "safe"
        risk_level = _confidence_to_risk(confidence, label)

        logger.info(
            "url=%s  prediction=%s  confidence=%.4f  latency=%.2fms",
            url, prediction, confidence, latency_ms,
        )

        return {
            "prediction": prediction,
            "label": label,
            "confidence": round(confidence, 4),
            "risk_level": risk_level,
            "latency_ms": round(latency_ms, 2),
        }

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def version(self) -> str | None:
        return self._version


# ── Module-level singleton + FastAPI dependency ───────────────────────────────

_model_service = ModelService()


def get_model_service() -> ModelService:
    """FastAPI dependency — injects the global ModelService singleton."""
    return _model_service
