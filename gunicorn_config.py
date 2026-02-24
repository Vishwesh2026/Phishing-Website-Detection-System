"""
gunicorn_config.py
─────────────────────────────────────────────────────────────
Gunicorn configuration for running FastAPI via Uvicorn workers.

Usage:
    gunicorn app.main:app --config gunicorn_config.py

Worker formula: (2 * CPU_COUNT) + 1  is the standard recommendation.
"""

import multiprocessing
import os

# ── Binding ───────────────────────────────────────────────────────────────────
host = os.getenv("API_HOST", "0.0.0.0")
port = os.getenv("API_PORT", "8000")
bind = f"{host}:{port}"

# ── Workers ───────────────────────────────────────────────────────────────────
# For CPU-bound ML inference, keep workers = (2 * cpu) + 1
# For async IO-bound apps, fewer workers with async is fine
workers = int(os.getenv("GUNICORN_WORKERS", (2 * multiprocessing.cpu_count()) + 1))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000

# ── Timeouts ──────────────────────────────────────────────────────────────────
# ML inference can take a few hundred ms — set generous timeout
timeout = 120          # Kill worker after 120s (catches infinite loops)
keepalive = 5          # Keep connection alive for 5s after request
graceful_timeout = 30  # Time for workers to finish outstanding requests on SIGTERM

# ── Logging ───────────────────────────────────────────────────────────────────
loglevel = os.getenv("LOG_LEVEL", "info").lower()
accesslog  = "-"    # stdout
errorlog   = "-"    # stdout
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" %(D)sµs'

# ── Process naming ────────────────────────────────────────────────────────────
proc_name = "phishing-detector"

# ── Pre-load app (loads model once per worker via lifespan) ───────────────────
preload_app = False    # Keep False — lifespan events handle model loading
