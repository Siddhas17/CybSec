"""Backend configuration, loaded from the project-root .env (the same file
ml/preprocessing/config.py's environment variables live in -- one source
of truth, not a backend-local .env). Never hard-code secrets; this module
only reads them.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=PROJECT_ROOT / ".env", extra="ignore")

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Database
    database_url: str
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_database: str = "attack_graph_app"
    mysql_user: str = "attack_graph_app"
    mysql_password: str = ""

    # Auth
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    admin_username: str = "admin"
    admin_password: str = ""

    # Analytical-core artifact paths (relative to PROJECT_ROOT unless absolute)
    model_path: str = "ml/models/artifacts/autoencoder"
    risk_config_path: str = "risk_engine/output/config.json"

    log_level: str = "INFO"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def model_path_absolute(self) -> Path:
        p = Path(self.model_path)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def risk_config_path_absolute(self) -> Path:
        p = Path(self.risk_config_path)
        return p if p.is_absolute() else PROJECT_ROOT / p


settings = Settings()
