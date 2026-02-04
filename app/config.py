"""
Centralized configuration using pydantic-settings.
Supports environment-aware settings for development, staging, and production.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── API Keys ──
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-flash-latest"

    # ── Vector Database ──
    CHROMA_PERSIST_DIR: str = "./chroma_data"
    CHROMA_COLLECTION_NAME: str = "email_samples"
    TOP_K_RESULTS: int = 5

    # ── Risk Scoring Weights (without metadata) ──
    HEURISTIC_WEIGHT: float = 0.3
    VECTOR_WEIGHT: float = 0.3
    LLM_WEIGHT: float = 0.4

    # ── Risk Scoring Weights (with metadata) ──
    HEURISTIC_WEIGHT_META: float = 0.2
    VECTOR_WEIGHT_META: float = 0.2
    LLM_WEIGHT_META: float = 0.3
    METADATA_WEIGHT: float = 0.3

    # ── Environment & Deployment ──
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = "*"
    WORKERS: int = 1

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def cors_origin_list(self) -> list:
        """Parse CORS_ORIGINS string into a list."""
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()
