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
    knn_model_path: str = "ml/models/artifacts/knn"
    risk_config_path: str = "risk_engine/output/config.json"

    # Generated security-report PDFs (gitignored, regenerated via POST /reports/generate)
    reports_output_dir: str = "backend/storage/reports"

    log_level: str = "INFO"

    # Phase 7: controlled lab response (backend.app.services.prevention).
    # Master switch, independent of dry_run below -- mirrors sensor/config.py's
    # TELEMETRY_ENABLED "defense in depth" pattern exactly: with this false,
    # the response layer does not evaluate anything, real or simulated.
    prevention_enabled: bool = False
    # With prevention_enabled=true, dry_run still defaults true -- an
    # operator must flip BOTH before any real adapter.block() call is ever
    # attempted. See docs/prevention.md "Safety defaults".
    prevention_dry_run: bool = True

    # Response policy thresholds on the existing 1-10 risk_engine scale
    # (risk_engine.config.RISK_LEVELS) -- not claimed to be objectively
    # correct, see docs/prevention.md "Response thresholds" for the
    # documented rationale. Configurable, not hard-coded into the policy.
    response_alert_threshold: float = 7.0
    response_block_threshold: float = 9.0

    # Lab-only scope (section 6): comma-separated CIDRs a response action's
    # target IP must fall inside. Never hard-coded into validation logic.
    lab_network_cidrs: str = "192.168.56.0/24"
    # Loopback is rejected by default even when the sensor is loopback-only
    # (docs/live_telemetry.md section 1) -- must be explicitly opted into,
    # never implied by LAB_NETWORK_CIDRS membership.
    lab_allow_loopback_target: bool = False

    # victim_agent (Phase 1): one-time shared secret distributed
    # out-of-band to each victim laptop, checked only by POST
    # /agents/register -- never reused after that (see
    # backend/app/api/v1/agents.py). Empty by default so an operator who
    # forgets to set it gets a hard refusal rather than a silently-open
    # registration endpoint.
    agent_enrollment_key: str = ""
    # How stale `agents.last_seen` can be before GET /agents reports an
    # agent as offline -- computed at read time, never stored (docs/
    # victim_agent.md). Independent of the agent's own heartbeat interval,
    # which the backend doesn't own or trust.
    agent_offline_threshold_seconds: int = 45

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def model_path_absolute(self) -> Path:
        p = Path(self.model_path)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def knn_model_path_absolute(self) -> Path:
        p = Path(self.knn_model_path)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def reports_output_dir_absolute(self) -> Path:
        p = Path(self.reports_output_dir)
        return p if p.is_absolute() else PROJECT_ROOT / p

    @property
    def risk_config_path_absolute(self) -> Path:
        p = Path(self.risk_config_path)
        return p if p.is_absolute() else PROJECT_ROOT / p


settings = Settings()
