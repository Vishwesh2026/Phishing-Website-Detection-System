"""
app/main.py
─────────────────────────────────────────────────────────────
FastAPI application factory.

Features:
  • Lifespan event: model loaded once on startup
  • CORS middleware (configurable via settings)
  • Request-size limit middleware (prevents large-body attacks)
  • Global exception handler returning JSON errors
  • Structured JSON-style logging
  • Prometheus metrics stub (enable by uncommenting)
  • Swagger / ReDoc docs at /docs and /redoc

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import socket
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers.predict import router
from app.services.model_service import get_model_service


# ── Logging setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Lifespan (replaces deprecated on_event) ───────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: load model.  Shutdown: clean up."""
    logger.info("=== Phishing Detection API starting up ===")
    svc = get_model_service()
    try:
        svc.load()
    except Exception as exc:                          # noqa: BLE001
        logger.critical("FATAL — model failed to load: %s", exc)
        # Do NOT raise here so the app still starts; /health will report degraded.

    # Print accessible URLs (helpful in development)
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        logger.info("Local:   http://127.0.0.1:%d", settings.API_PORT)
        logger.info("Network: http://%s:%d", local_ip, settings.API_PORT)
        logger.info("Docs:    http://127.0.0.1:%d/docs", settings.API_PORT)
    except Exception:
        pass

    yield  # ─── application is now running ────────────────────────────────────

    logger.info("=== Phishing Detection API shutting down ===")


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Production-grade ML API for real-time phishing URL detection. "
            "Returns prediction label, confidence score, and risk level."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request-size limit middleware ─────────────────────────────────────────
    @application.middleware("http")
    async def limit_request_size(request: Request, call_next) -> Response:
        """
        Reject requests whose body exceeds MAX_REQUEST_BODY_BYTES.
        Prevents memory exhaustion / large-payload attacks.
        """
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "Request body too large.",
                    "max_bytes": settings.MAX_REQUEST_BODY_BYTES,
                },
            )
        return await call_next(request)

    # ── Latency logging middleware ─────────────────────────────────────────────
    @application.middleware("http")
    async def log_requests(request: Request, call_next) -> Response:
        t0 = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "method=%s path=%s status=%d latency=%.2fms",
            request.method, request.url.path, response.status_code, duration_ms,
        )
        response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
        return response

    # ── Global exception handler ───────────────────────────────────────────────
    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception for %s %s: %s", request.method, request.url, exc)
        return JSONResponse(
            status_code=500,
            content={"error": "An unexpected internal error occurred.", "detail": str(exc)},
        )

    # ── Prometheus metrics (stub — uncomment to enable) ───────────────────────
    # from prometheus_fastapi_instrumentator import Instrumentator
    # Instrumentator().instrument(application).expose(application)

    # ── Register routes ───────────────────────────────────────────────────────
    application.include_router(router)

    return application


# ── Module-level app instance (used by Uvicorn / Gunicorn) ────────────────────
app = create_app()
