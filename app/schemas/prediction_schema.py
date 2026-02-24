"""
app/schemas/prediction_schema.py
─────────────────────────────────────────────────────────────
Pydantic v2 request / response schemas for the single-model API.
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
            raise ValueError("URL must start with http:// or https://")
        if not parsed.netloc:
            raise ValueError("URL must have a valid domain.")
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum allowed length of 2048 characters.")
        return v.strip()

    model_config = {"json_schema_extra": {"example": {"url": "https://www.google.com"}}}


# ── Shared sub-schemas ────────────────────────────────────────────────────────

class DomainInfo(BaseModel):
    """WHOIS-derived domain metadata. All fields are optional."""
    domain:           Optional[str]  = None
    registrar:        Optional[str]  = None
    creation_date:    Optional[str]  = None
    expiration_date:  Optional[str]  = None
    updated_date:     Optional[str]  = None
    domain_age:       Optional[str]  = None
    is_new_domain:    bool           = False
    is_expiring_soon: bool           = False
    name_servers:     list[str]      = []
    status:           list[str]      = []
    country:          Optional[str]  = None
    org:              Optional[str]  = None
    whois_available:  bool           = False
    error:            Optional[str]  = None


class InfrastructureFeatures(BaseModel):
    """Selected infrastructure signals from the deep feature extractor."""
    tls_ssl_certificate:    Optional[int]   = None  # 1=valid, 0=invalid, -1=error
    qty_ip_resolved:        Optional[int]   = None
    qty_nameservers:        Optional[int]   = None
    qty_mx_servers:         Optional[int]   = None
    ttl_hostname:           Optional[int]   = None
    time_response:          Optional[float] = None  # seconds
    domain_spf:             Optional[int]   = None  # 1=present, 0=absent
    asn_ip:                 Optional[int]   = None
    time_domain_activation: Optional[int]   = None  # days since activation
    time_domain_expiration: Optional[int]   = None  # days until expiration
    qty_redirects:          Optional[int]   = None
    url_google_index:       int = -1                # sentinel at runtime
    domain_google_index:    int = -1                # sentinel at runtime


# ── Unified Analysis Response ─────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    """Response for POST /api/v1/analyze (single deep model)."""
    url:            str
    prediction:     str             # "phishing" | "safe"
    label:          int             # 1 = phishing, 0 = safe
    confidence:     float           # calibrated probability (0–1)
    risk_level:     str             # "HIGH" | "MEDIUM" | "LOW"
    infrastructure: Optional[InfrastructureFeatures] = None
    domain_info:    Optional[DomainInfo]             = None
    degraded:       bool  = False   # True if circuit breaker tripped
    latency_ms:     float = 0.0     # total end-to-end ms
    model_version:  str   = "v1"

    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "https://suspicious-login.xyz",
                "prediction": "phishing",
                "label": 1,
                "confidence": 0.97,
                "risk_level": "HIGH",
                "infrastructure": {
                    "tls_ssl_certificate": 0, "qty_nameservers": 1,
                    "ttl_hostname": 120, "time_response": 1.2
                },
                "domain_info": {
                    "domain": "suspicious-login.xyz", "is_new_domain": True,
                    "whois_available": True,
                },
                "degraded": False,
                "latency_ms": 1840.7,
                "model_version": "v1",
            }
        }
    }


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status:        str
    model_loaded:  bool
    model_version: Optional[str]
    app_env:       str
