"""
app/routers/predict.py
─────────────────────────────────────────────────────────────
All API endpoints for the single-model Phishing Detection service.

Routes:
  POST /api/v1/analyze  — Deep XGBoost analysis (primary endpoint)
  GET  /                — Web UI (index.html)
  POST /predict         — HTML form submission (web UI)
  GET  /health          — Liveness + readiness check
  POST /reload-model    — Hot-reload model from disk
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.schemas.prediction_schema import (
    AnalyzeResponse,
    DomainInfo,
    HealthResponse,
    InfrastructureFeatures,
    PredictRequest,
)
from app.services.model_service import ModelService, get_model_service
from app.services.whois_service import get_domain_info
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Circuit breaker — limits concurrent analyses ────────────────────────────
_semaphore: asyncio.Semaphore | None = None

def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT)
    return _semaphore


# ── Templates ────────────────────────────────────────────────────────────────
templates = Jinja2Templates(directory=Path(settings.MODEL_DIR).parent / "templates")


# ── Infrastructure field names to surface in the response ────────────────────
_INFRA_FIELDS = [
    "tls_ssl_certificate", "qty_ip_resolved", "qty_nameservers",
    "qty_mx_servers", "ttl_hostname", "time_response", "domain_spf",
    "asn_ip", "time_domain_activation", "time_domain_expiration",
    "qty_redirects", "url_google_index", "domain_google_index",
]


# ── Core analysis helper ──────────────────────────────────────────────────────

async def _run_analysis(url: str, svc: ModelService) -> dict:
    """
    Extract features + run deep model + fetch WHOIS concurrently.
    Returns a flat dict suitable for building AnalyzeResponse.
    Never raises (graceful degradation on infra/WHOIS failures).
    """
    if not svc.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded. Please try again shortly.",
        )

    sem = _get_semaphore()

    # ── Fast-path: circuit breaker at capacity ────────────────────────────────
    if sem._value == 0:
        logger.warning("Circuit breaker TRIPPED for %s — returning degraded response", url)
        return {
            "url": url,
            "prediction": "unknown",
            "label": -1,
            "confidence": 0.0,
            "risk_level": "UNKNOWN",
            "infrastructure": None,
            "domain_info": None,
            "degraded": True,
            "latency_ms": 0.0,
            "model_version": svc.version or settings.MODEL_VERSION,
        }

    async with sem:
        from app.utils.deep_feature_extractor import extract as extract_features
        t_start = time.perf_counter()

        # Run feature extraction + WHOIS concurrently (both are async + network-bound)
        feature_dict, whois_result = await asyncio.gather(
            extract_features(url, infra_timeout=settings.TIMEOUT_SECS),
            get_domain_info(url),
            return_exceptions=True,
        )

        # Graceful fallback for infrastructure extraction failure
        if isinstance(feature_dict, Exception):
            logger.error("Feature extraction failed for %s: %s", url, feature_dict)
            feature_dict = {}

        # Graceful fallback for WHOIS failure
        if isinstance(whois_result, Exception):
            logger.warning("WHOIS failed for %s: %s", url, whois_result)
            whois_result = {"whois_available": False, "error": str(whois_result)}

        # ── Deep model inference ──────────────────────────────────────────────
        try:
            ml_result = await asyncio.to_thread(svc.predict, feature_dict)
        except Exception as exc:
            logger.exception("Deep model inference failed for %s: %s", url, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Model inference failed: {exc}",
            ) from exc

        total_ms = round((time.perf_counter() - t_start) * 1000, 2)

        # ── Build infrastructure subset ───────────────────────────────────────
        infra_dict = {k: feature_dict.get(k) for k in _INFRA_FIELDS} if feature_dict else {}

        return {
            "url":            url,
            "prediction":     ml_result["prediction"],
            "label":          ml_result["label"],
            "confidence":     ml_result["confidence"],
            "risk_level":     ml_result["risk_level"],
            "infrastructure": infra_dict or None,
            "domain_info":    whois_result if isinstance(whois_result, dict) else None,
            "degraded":       False,
            "latency_ms":     total_ms,
            "model_version":  svc.version or settings.MODEL_VERSION,
        }


# ── POST /api/v1/analyze ──────────────────────────────────────────────────────

@router.post(
    "/api/v1/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a URL for phishing (XGBoost deep model)",
    tags=["Prediction"],
)
async def analyze(
    data: PredictRequest,
    svc: ModelService = Depends(get_model_service),
) -> AnalyzeResponse:
    """
    Full phishing analysis via the deep XGBoost model.

    1. Extracts 111 features (lexical + DNS / SSL / WHOIS).
    2. Runs calibrated XGBoost inference.
    3. Returns verdict, confidence, infrastructure signals, and WHOIS metadata.

    Feature extraction and WHOIS lookup run concurrently.
    Bounded by asyncio.Semaphore (MAX_CONCURRENT) and TIMEOUT_SECS.
    """
    result = await _run_analysis(data.url, svc)

    infra = None
    if result["infrastructure"]:
        # Filter out None-valued keys before constructing the schema
        clean_infra = {k: v for k, v in result["infrastructure"].items() if v is not None}
        infra = InfrastructureFeatures(**clean_infra) if clean_infra else None

    domain_info = None
    if isinstance(result["domain_info"], dict):
        domain_info = DomainInfo(**result["domain_info"])

    return AnalyzeResponse(
        url=result["url"],
        prediction=result["prediction"],
        label=result["label"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        infrastructure=infra,
        domain_info=domain_info,
        degraded=result["degraded"],
        latency_ms=result["latency_ms"],
        model_version=result["model_version"],
    )


# ── GET / (Web UI) ────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(
    request: Request,
    url: Optional[str] = None,
    svc: ModelService = Depends(get_model_service),
):
    context = {"request": request, "url": url}
    if url:
        try:
            if not url.startswith(("http://", "https://")):
                raise ValueError("URL must start with http:// or https://")
            result = await _run_analysis(url, svc)
            context.update({"result": result, "is_phishing": result["label"] == 1})
        except Exception as exc:
            logger.warning("Web UI analysis failed: %s", exc)
            context["error"] = str(exc)
    return templates.TemplateResponse("index.html", context)


# ── POST /predict (HTML form) ─────────────────────────────────────────────────

@router.post("/predict", response_class=HTMLResponse, include_in_schema=False)
async def predict_web(
    request: Request,
    url: str = Form(...),
    svc: ModelService = Depends(get_model_service),
):
    try:
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        result = await _run_analysis(url, svc)
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "url": url,
             "result": result, "is_phishing": result["label"] == 1},
        )
    except Exception as exc:
        logger.warning("Web form prediction failed: %s", exc)
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "url": url, "error": str(exc)},
        )


# ── GET /health ───────────────────────────────────────────────────────────────

@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health / readiness check",
    tags=["Operations"],
)
async def health_check(svc: ModelService = Depends(get_model_service)) -> HealthResponse:
    return HealthResponse(
        status="healthy" if svc.is_loaded else "degraded",
        model_loaded=svc.is_loaded,
        model_version=svc.version,
        app_env=settings.APP_ENV,
    )


# ── GET /api/v1/metrics ───────────────────────────────────────────────────────

@router.get(
    "/api/v1/metrics",
    status_code=status.HTTP_200_OK,
    summary="Training evaluation metrics (read-only)",
    tags=["Operations"],
)
async def get_metrics() -> dict:
    """
    Returns the latest model evaluation metrics from experiments/metrics.json.
    This file is written by training/train_deep.py after each training run.
    Returns 404 if no training has been run yet.
    Completely separate from /api/v1/analyze — inference is never touched.
    """
    metrics_path = settings.EXPERIMENTS_DIR / "metrics.json"
    if not metrics_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metrics not available. Run training/train_deep.py first.",
        )
    try:
        with open(metrics_path) as f:
            return json.load(f)
    except Exception as exc:
        logger.exception("Failed to read metrics.json: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read metrics file.",
        ) from exc


# ── POST /reload-model ────────────────────────────────────────────────────────

@router.post(
    "/reload-model",
    status_code=status.HTTP_200_OK,
    summary="Hot-reload model from disk",
    tags=["Operations"],
)
async def reload_model(svc: ModelService = Depends(get_model_service)) -> dict:
    """Reload the model from disk without restarting the server."""
    try:
        await asyncio.to_thread(svc.reload)
        logger.info("Model reloaded via /reload-model")
        return {"status": "success", "model_version": svc.version}
    except Exception as exc:
        logger.exception("Model reload failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model reload failed: {exc}",
        ) from exc
