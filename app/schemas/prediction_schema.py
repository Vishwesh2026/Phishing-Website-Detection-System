"""
app/schemas/prediction_schema.py
─────────────────────────────────────────────────────────────
Pydantic v2 request / response schemas for the prediction API.
"""

from pydantic import BaseModel, field_validator, HttpUrl
from typing import Optional


# ── Request ───────────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    """Validated input URL for phishing detection."""

    url: str

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(v.strip())
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                "URL must start with http:// or https://"
            )
        if not parsed.netloc:
            raise ValueError("URL must have a valid domain.")
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum allowed length of 2048 characters.")
        return v.strip()

    model_config = {"json_schema_extra": {"example": {"url": "https://www.google.com"}}}


# ── Response ──────────────────────────────────────────────────────────────────

class PredictResponse(BaseModel):
    """Structured prediction result returned by the API."""

    url: str
    prediction: str          # "phishing" | "safe"
    label: int               # 1 = phishing, 0 = safe
    confidence: float        # 0.0 – 1.0 (probability of the predicted class)
    risk_level: str          # "HIGH" | "MEDIUM" | "LOW"
    model_version: str
    latency_ms: float        # End-to-end inference time

    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "https://www.google.com",
                "prediction": "safe",
                "label": 0,
                "confidence": 0.97,
                "risk_level": "LOW",
                "model_version": "v1",
                "latency_ms": 12.4,
            }
        }
    }


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: Optional[str]
    app_env: str
