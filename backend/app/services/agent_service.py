"""victim_agent identity/registration/heartbeat/telemetry-persistence logic
(Phase 1). Mirrors auth_service.py's shape -- a thin, deliberately simple
module (single-admin-app-grade, not enterprise IAM), reusing the existing
bcrypt wrappers in core.security rather than introducing a second hashing
primitive."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from backend.app.core.security import hash_password, verify_password
from backend.app.models.agent import Agent
from backend.app.models.agent_telemetry_event import AgentTelemetryEvent
from backend.app.schemas.agent import AgentRegisterIn
from backend.app.schemas.telemetry import TelemetryBatchIn


def get_agent_by_agent_id(db: Session, agent_id: str) -> Agent | None:
    return db.query(Agent).filter(Agent.agent_id == agent_id).first()


def generate_agent_token() -> str:
    # secrets.token_urlsafe(32) -> 43 chars, well under bcrypt's 72-byte
    # input limit (core.security.hash_password truncates silently past
    # that -- not a concern here, but noted since it would matter for a
    # much longer token).
    return secrets.token_urlsafe(32)


def register_agent(db: Session, payload: AgentRegisterIn) -> tuple[Agent, str, bool]:
    """Creates a new agent, or -- if agent_id already exists -- rotates its
    token (200, not 409). A victim laptop can be re-imaged or lose its
    local identity file; requiring manual DB surgery to recover would be
    worse than just issuing a fresh credential for the same logical agent.
    Returns (agent, plaintext_token, rotated)."""
    token = generate_agent_token()
    token_hash = hash_password(token)

    existing = get_agent_by_agent_id(db, payload.agent_id)
    if existing is not None:
        existing.token_hash = token_hash
        existing.hostname = payload.hostname
        existing.ip_address = payload.ip_address
        existing.agent_version = payload.agent_version
        existing.last_seen = datetime.now(UTC)
        db.commit()
        db.refresh(existing)
        return existing, token, True

    agent = Agent(
        agent_id=payload.agent_id,
        hostname=payload.hostname,
        token_hash=token_hash,
        ip_address=payload.ip_address,
        agent_version=payload.agent_version,
        status="active",
        last_seen=datetime.now(UTC),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent, token, False


def authenticate_agent(db: Session, agent_id: str, token: str) -> Agent | None:
    agent = get_agent_by_agent_id(db, agent_id)
    if agent is None or not verify_password(token, agent.token_hash):
        return None
    return agent


def touch_last_seen(db: Session, agent: Agent, ip_address: str | None = None, agent_version: str | None = None) -> None:
    agent.last_seen = datetime.now(UTC)
    if ip_address:
        agent.ip_address = ip_address
    if agent_version:
        agent.agent_version = agent_version
    db.commit()


def is_online(agent: Agent, threshold_seconds: int) -> bool:
    if agent.last_seen is None:
        return False
    last_seen = agent.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age = (datetime.now(UTC) - last_seen).total_seconds()
    return age <= threshold_seconds


def ingest_telemetry_batch(db: Session, agent: Agent, payload: TelemetryBatchIn) -> int:
    """Persists raw connection telemetry only -- never scored, never
    written to events/detections/risk_assessments (section 19's explicit
    ML firewall)."""
    rows = [
        AgentTelemetryEvent(
            agent_id=agent.id,
            collected_at=payload.timestamp,
            hostname=payload.hostname,
            local_ip=conn.local_ip,
            local_port=conn.local_port,
            remote_ip=conn.remote_ip,
            remote_port=conn.remote_port,
            protocol=conn.protocol,
            connection_status=conn.status,
        )
        for conn in payload.connections
    ]
    db.add_all(rows)
    agent.last_seen = datetime.now(UTC)
    agent.ip_address = payload.local_ip
    db.commit()
    return len(rows)
