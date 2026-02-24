"""
app/routers/predict.py
─────────────────────────────────────────────────────────────
All API endpoints for the Phishing Detection service.

Routes:
  POST /api/v1/predict   — run inference + WHOIS domain info
  GET  /health           — liveness + readiness check
  POST /reload-model     — hot-reload model from disk
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.schemas.prediction_schema import (
    DomainInfo,
    HealthResponse,
    PredictRequest,
    PredictResponse,
)
from app.services.model_service import ModelService, get_model_service
from app.services.whois_service import get_domain_info
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Templates setup ───────────────────────────────────────────────────────────
# Located in project root / templates
templates = Jinja2Templates(directory=Path(settings.MODEL_DIR).parent / "templates")


# ── GET / ─────────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(
    request: Request,
    url: Optional[str] = None,
    svc: ModelService = Depends(get_model_service),
):
    """
    Serve the main web interface.
    If a URL is passed in the query string, automatically trigger a check.
    """
    context = {"request": request, "url": url}
    
    if url:
        try:
            # Basic validation for query param
            if not url.startswith(("http://", "https://")):
                raise ValueError("URL must start with http:// or https://")
            
            result = await _perform_prediction(url, svc)
            context.update({
                "result": result,
                "is_phishing": result["label"] == 1,
            })
        except Exception as exc:
            logger.warning("Deep analysis auto-check failed: %s", exc)
            context["error"] = str(exc)

    return templates.TemplateResponse("index.html", context)


@router.post(
    "/api/v1/predict",
    response_model=PredictResponse,
    status_code=status.HTTP_200_OK,
    summary="Predict whether a URL is phishing or safe",
    tags=["Prediction"],
)
async def predict_api(
    data: PredictRequest,
    svc: ModelService = Depends(get_model_service),
) -> PredictResponse:
    """JSON API endpoint for programmatic access (e.g. Chrome Extension)."""
    result = await _perform_prediction(data.url, svc)
    return PredictResponse(**result)


# ── POST /predict (Web Form) ──────────────────────────────────────────────────

@router.post(
    "/predict",
    response_class=HTMLResponse,
    include_in_schema=False
)
async def predict_web(
    request: Request,
    url: str = Form(...),
    svc: ModelService = Depends(get_model_service),
):
    """
    Handle standard HTML form submission.
    Returns the rendered index.html with result context.
    """
    try:
        # Basic validation for form input
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        
        result = await _perform_prediction(url, svc)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "url": url,
                "result": result,
                "is_phishing": result["label"] == 1,
            }
        )
    except Exception as exc:
        logger.warning("Web prediction failed: %s", exc)
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": str(exc),
                "url": url
            }
        )


async def _perform_prediction(url: str, svc: ModelService) -> dict:
    """Helper to run ML inference + WHOIS concurrently."""
    if not svc.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded. Please try again shortly.",
        )

    ml_task    = asyncio.to_thread(svc.predict, url)
    whois_task = get_domain_info(url)

    ml_result, whois_result = await asyncio.gather(
        ml_task, whois_task,
        return_exceptions=True,
    )

    if isinstance(ml_result, Exception):
        logger.exception("Prediction failed: %s", ml_result)
        raise ml_result

    # Fallback for whois
    if isinstance(whois_result, Exception):
        logger.warning("WHOIS gather error: %s", whois_result)
        whois_result = {
            "domain": None, "registrar": None, "creation_date": None,
            "expiration_date": None, "updated_date": None, "domain_age": None,
            "is_new_domain": False, "is_expiring_soon": False,
            "name_servers": [], "status": [], "country": None, "org": None,
            "whois_available": False, "error": str(whois_result),
        }

    return {
        "url": url,
        "prediction": ml_result["prediction"],
        "label": ml_result["label"],
        "confidence": ml_result["confidence"],
        "risk_level": ml_result["risk_level"],
        "model_version": svc.version or settings.MODEL_VERSION,
        "latency_ms": ml_result["latency_ms"],
        "domain_info": whois_result,
    }


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

    > **Note**: In production, protect this endpoint with an API key / internal
    > network restriction. Do not expose it publicly.
    """
    try:
        await asyncio.to_thread(svc.reload)
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
