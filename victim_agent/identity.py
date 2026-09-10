"""Local, stable agent identity. The agent_id (and, once obtained, the
per-agent secret token) are persisted to a local JSON file so restarting
the process never regenerates a new identity -- only deleting the file (or
explicitly overriding AGENT_ID) does. The token is never logged."""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from victim_agent.config import AgentConfig

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    agent_id: str
    token: str | None = None


def load_or_create_identity(config: AgentConfig) -> AgentIdentity:
    path = config.identity_file_path
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            identity = AgentIdentity(agent_id=data["agent_id"], token=data.get("token"))
            if config.agent_id and config.agent_id != identity.agent_id:
                logger.warning("AGENT_ID=%s in config differs from persisted identity %s -- keeping the persisted one (delete %s to reset)", config.agent_id, identity.agent_id, path)
            return identity
        except (json.JSONDecodeError, KeyError, OSError) as exc:
            logger.warning("Identity file %s is unreadable (%s) -- generating a new identity", path, exc)

    agent_id = config.agent_id or str(uuid.uuid4())
    identity = AgentIdentity(agent_id=agent_id, token=None)
    _save(path, identity)
    logger.info("Generated new stable agent identity: %s", agent_id)
    return identity


def save_token(config: AgentConfig, identity: AgentIdentity, token: str) -> None:
    identity.token = token
    _save(config.identity_file_path, identity)


def _save(path: Path, identity: AgentIdentity) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(identity)), encoding="utf-8")
    try:
        os.chmod(path, 0o600)  # best-effort on Windows; no-op if unsupported
    except OSError:
        pass
