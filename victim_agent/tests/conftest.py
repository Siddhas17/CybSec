from __future__ import annotations

from pathlib import Path

import pytest

from victim_agent.config import AgentConfig


@pytest.fixture()
def make_config(tmp_path: Path):
    def _make(agent_id: str | None = None, max_queue_size: int = 3, identity_file_path: Path | None = None) -> AgentConfig:
        return AgentConfig(
            admin_base_url="http://admin.invalid:8000",
            agent_enrollment_key="test-key",
            agent_id=agent_id,
            heartbeat_interval_seconds=15,
            telemetry_interval_seconds=5,
            request_timeout_seconds=5,
            max_queue_size=max_queue_size,
            identity_file_path=identity_file_path or (tmp_path / "identity.json"),
            log_level="INFO",
        )

    return _make
