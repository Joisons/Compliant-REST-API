"""
Application configuration.

All values are overridable via environment variables (see .env.example).
Defaults are safe for local demo/simulation use only -- the JWT secret in
particular MUST be replaced with a securely generated value before any
deployment beyond a local demo.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "Compliant FinTech Data API"
    app_version: str = "1.0.0"
    environment: str = "development"

    # --- Auth / JWT ---
    jwt_secret_key: str = "CHANGE_ME_INSECURE_DEMO_SECRET_DO_NOT_USE_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # --- Database ---
    database_url: str = "sqlite:///./compliant_api.db"

    # --- Rate limiting (requests per rolling 60-second window, by role) ---
    rate_limit_viewer: int = 30
    rate_limit_analyst: int = 60
    rate_limit_auditor: int = 100
    rate_limit_admin: int = 200
    rate_limit_window_seconds: int = 60

    # --- Audit log ---
    audit_log_genesis_hash: str = "0" * 64


@lru_cache
def get_settings() -> Settings:
    return Settings()
