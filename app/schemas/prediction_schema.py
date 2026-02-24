"""
app/schemas/prediction_schema.py
─────────────────────────────────────────────────────────────
Pydantic v2 request / response schemas for the prediction API.
"""

from pydantic import BaseModel, field_validator
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


# ── Domain Info ───────────────────────────────────────────────────────────────

class DomainInfo(BaseModel):
    """WHOIS-derived domain metadata. All fields are optional (WHOIS may be unavailable)."""

    domain:           Optional[str]       = None
    registrar:        Optional[str]       = None
    creation_date:    Optional[str]       = None   # ISO date string 'YYYY-MM-DD'
    expiration_date:  Optional[str]       = None
    updated_date:     Optional[str]       = None
    domain_age:       Optional[str]       = None   # Human-readable: '3 years, 2 months'
    is_new_domain:    bool                = False  # True if < 1 year old
    is_expiring_soon: bool                = False  # True if expires within 30 days
    name_servers:     list[str]           = []
    status:           list[str]           = []
    country:          Optional[str]       = None
    org:              Optional[str]       = None
    whois_available:  bool                = False  # False if lookup failed
    error:            Optional[str]       = None   # Error message if lookup failed

    model_config = {
        "json_schema_extra": {
            "example": {
                "domain": "google.com",
                "registrar": "MarkMonitor Inc.",
                "creation_date": "1997-09-15",
                "expiration_date": "2028-09-14",
                "updated_date": "2023-09-07",
                "domain_age": "27 years, 5 months",
                "is_new_domain": False,
                "is_expiring_soon": False,
                "name_servers": ["ns1.google.com", "ns2.google.com"],
                "status": ["clientdeleteprohibited", "clienttransferprohibited"],
                "country": "US",
                "org": "Google LLC",
                "whois_available": True,
                "error": None,
            }
        }
    }


# ── Prediction Response ───────────────────────────────────────────────────────

class PredictResponse(BaseModel):
    """Structured prediction result returned by the API."""

    url:           str
    prediction:    str             # "phishing" | "safe"
    label:         int             # 1 = phishing, 0 = safe
    confidence:    float           # 0.0 – 1.0 (probability of the predicted class)
    risk_level:    str             # "HIGH" | "MEDIUM" | "LOW"
    model_version: str
    latency_ms:    float           # End-to-end inference time (ms)
    domain_info:   Optional[DomainInfo] = None  # WHOIS data (None if unavailable)

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
                "domain_info": {
                    "domain": "google.com",
                    "registrar": "MarkMonitor Inc.",
                    "creation_date": "1997-09-15",
                    "domain_age": "27 years, 5 months",
                    "is_new_domain": False,
                    "is_expiring_soon": False,
                    "whois_available": True,
                    "error": None,
                },
            }
        }
    }


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: Optional[str]
    app_env: str
