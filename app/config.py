"""
app/config.py
─────────────────────────────────────────────────────────────
Centralised configuration using Pydantic v2 BaseSettings.
All values can be overridden via environment variables or a .env file.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Resolve project root so paths work regardless of cwd ──────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application-wide settings. Override via .env or environment variables."""

    # ── App meta ──────────────────────────────────────────────────────────────
    APP_NAME: str = "Phishing Website Detection API"
    APP_VERSION: str = "3.0.0"
    APP_ENV: str = "development"          # development | staging | production
    DEBUG: bool = False

    # ── Server ────────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # ── Model ─────────────────────────────────────────────────────────────────
    # Deep XGBoost model (the only model in the system)
    MODEL_VERSION: str = "v1"
    MODEL_DIR: Path = _PROJECT_ROOT / "models"

    @property
    def model_path(self) -> Path:
        return self.MODEL_DIR / f"phishing_deep_{self.MODEL_VERSION}.pkl"

    @property
    def feature_cols_path(self) -> Path:
        return self.MODEL_DIR / "deep_feature_cols.json"

    @property
    def feature_stats_path(self) -> Path:
        return self.MODEL_DIR / "deep_feature_stats.json"

    # ── Classification threshold (tunable without retraining) ────────────────
    PHISHING_THRESHOLD: float = 0.5      # probability ≥ this → phishing

    # ── Inference circuit breaker ─────────────────────────────────────────────
    MAX_CONCURRENT: int   = 10           # max simultaneous analyses
    TIMEOUT_SECS:   float = 15.0         # per-check infrastructure timeout

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"              # DEBUG | INFO | WARNING | ERROR

    # ── Security / Rate limits ────────────────────────────────────────────────
    MAX_REQUEST_BODY_BYTES: int = 8_192  # 8 KB — prevents large-payload attacks

    ALLOWED_ORIGINS: str = "*"

    @property
    def allowed_origins_list(self) -> list[str]:
        """Parse ALLOWED_ORIGINS string into a list for CORSMiddleware."""
        raw = self.ALLOWED_ORIGINS.strip()
        if not raw:
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    # ── Experiments ───────────────────────────────────────────────────────────
    EXPERIMENTS_DIR: Path = _PROJECT_ROOT / "experiments"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


# ── Module-level singleton ─────────────────────────────────────────────────────
settings = Settings()
