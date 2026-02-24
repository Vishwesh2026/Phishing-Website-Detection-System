"""
app/routers/predict.py
─────────────────────────────────────────────────────────────
All API endpoints for the Phishing Detection service.

Routes:
  POST /api/v1/predict   — run inference on a URL
  GET  /health           — liveness + readiness check
  POST /reload-model     — hot-reload model from disk
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.prediction_schema import (
    HealthResponse,
    PredictRequest,
    PredictResponse,
)
from app.services.model_service import ModelService, get_model_service
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


# ── POST /api/v1/predict ──────────────────────────────────────────────────────

@router.post(
    "/api/v1/predict",
    response_model=PredictResponse,
    status_code=status.HTTP_200_OK,
    summary="Predict whether a URL is phishing or safe",
    tags=["Prediction"],
)
async def predict(
    data: PredictRequest,
    svc: ModelService = Depends(get_model_service),
) -> PredictResponse:
    """
    Analyse a URL and return:
    - **prediction**: `phishing` or `safe`
    - **label**: `1` (phishing) or `0` (safe)
    - **confidence**: probability of the predicted class (0.0 – 1.0)
    - **risk_level**: `HIGH`, `MEDIUM`, or `LOW`
    - **model_version**: active model version
    - **latency_ms**: inference latency in milliseconds
    """
    if not svc.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded. Please try again shortly.",
        )

    try:
        result = svc.predict(data.url)
    except Exception as exc:
        logger.exception("Prediction failed for url=%s: %s", data.url, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction pipeline encountered an internal error.",
        ) from exc

    return PredictResponse(
        url=data.url,
        prediction=result["prediction"],
        label=result["label"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        model_version=svc.version or settings.MODEL_VERSION,
        latency_ms=result["latency_ms"],
    )


# ── GET /health ───────────────────────────────────────────────────────────────

@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health / readiness check",
    tags=["Operations"],
)
async def health_check(
    svc: ModelService = Depends(get_model_service),
) -> HealthResponse:
    """Returns API health and model loaded status."""
    return HealthResponse(
        status="healthy" if svc.is_loaded else "degraded",
        model_loaded=svc.is_loaded,
        model_version=svc.version,
        app_env=settings.APP_ENV,
    )


# ── POST /reload-model ────────────────────────────────────────────────────────

@router.post(
    "/reload-model",
    status_code=status.HTTP_200_OK,
    summary="Hot-reload model from disk",
    tags=["Operations"],
)
async def reload_model(
    svc: ModelService = Depends(get_model_service),
) -> dict:
    """
    Triggers a live reload of the ML model from disk.

    Useful after retraining to pick up the new model without
    restarting the server.

    > **Note**: In production, protect this endpoint with an API key / internal
    > network restriction. Do not expose it publicly.
    """
    try:
        svc.reload()
        logger.info("Model reloaded via /reload-model endpoint")
        return {
            "status": "success",
            "message": f"Model reloaded (version={svc.version})",
            "model_version": svc.version,
        }
    except Exception as exc:
        logger.exception("Failed to reload model: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model reload failed: {exc}",
        ) from exc
