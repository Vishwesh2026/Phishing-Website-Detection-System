# ─────────────────────────────────────────────────────────────
# Dockerfile — Production-Ready Multi-Stage Build
# ─────────────────────────────────────────────────────────────
# Stage 1: builder  — installs Python deps
# Stage 2: runtime  — slim image, non-root user
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Dependency builder ───────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools for native extensions (xgboost, scipy)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for layer caching
COPY requirements.txt .

# Create a virtual environment inside the builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip --no-cache-dir && \
    pip install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime image ────────────────────────────────────
FROM python:3.11-slim AS runtime

# Security: run as non-root
RUN groupadd --gid 1001 appgroup && \
    useradd  --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install libgomp1 runtime (required by XGBoost / scikit-learn)
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy application source
COPY --chown=appuser:appgroup app/          ./app/
COPY --chown=appuser:appgroup models/       ./models/
COPY --chown=appuser:appgroup gunicorn_config.py .
COPY --chown=appuser:appgroup .env.example  .env

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Start Gunicorn with Uvicorn workers
CMD ["gunicorn", "app.main:app", \
     "--config", "gunicorn_config.py"]
