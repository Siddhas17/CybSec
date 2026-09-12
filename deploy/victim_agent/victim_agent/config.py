"""victim_agent configuration -- deliberately NOT pydantic-settings (unlike
backend/app/core/config.py and sensor/config.py, both of which run inside
the backend's WSL2 conda env alongside the full ML stack). victim_agent
runs standalone on a separate Windows victim laptop with only psutil,
httpx, and python-dotenv installed -- a hand-rolled os.environ +
python-dotenv reader is required here instead.

Never hardcodes the Admin's IP/URL -- ADMIN_BASE_URL has no default and
must be set in victim_agent/.env (or the real process environment)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_THIS_DIR = Path(__file__).resolve().parent


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


@dataclass(frozen=True)
class AgentConfig:
    admin_base_url: str
    agent_enrollment_key: str
    agent_id: str | None
    heartbeat_interval_seconds: int
    telemetry_interval_seconds: int
    request_timeout_seconds: int
    max_queue_size: int
    identity_file_path: Path
    log_level: str

    @property
    def api_base_url(self) -> str:
        return self.admin_base_url.rstrip("/") + "/api/v1"


def load_config(env_file: Path | None = None) -> AgentConfig:
    load_dotenv(dotenv_path=env_file or (_THIS_DIR / ".env"))

    admin_base_url = os.environ.get("ADMIN_BASE_URL", "").strip()
    if not admin_base_url:
        raise RuntimeError("ADMIN_BASE_URL is not set -- configure victim_agent/.env (see .env.example). The Admin's address is never hardcoded.")

    identity_file = os.environ.get("IDENTITY_FILE_PATH", "").strip()
    identity_path = Path(identity_file) if identity_file else _THIS_DIR / ".agent_identity.json"

    return AgentConfig(
        admin_base_url=admin_base_url,
        agent_enrollment_key=os.environ.get("AGENT_ENROLLMENT_KEY", "").strip(),
        agent_id=os.environ.get("AGENT_ID", "").strip() or None,
        heartbeat_interval_seconds=_env_int("HEARTBEAT_INTERVAL_SECONDS", 15),
        telemetry_interval_seconds=_env_int("TELEMETRY_INTERVAL_SECONDS", 5),
        request_timeout_seconds=_env_int("REQUEST_TIMEOUT_SECONDS", 5),
        max_queue_size=_env_int("MAX_QUEUE_SIZE", 1000),
        identity_file_path=identity_path,
        log_level=os.environ.get("LOG_LEVEL", "INFO").strip().upper(),
    )
