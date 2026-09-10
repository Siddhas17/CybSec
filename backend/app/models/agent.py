from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class Agent(Base):
    """A victim-laptop identity (victim_agent/ Phase 1). Machine-auth only --
    never a User row, never authenticated via JWT. `token_hash` is a bcrypt
    hash of a random per-agent secret (backend.app.core.security.hash_password
    reused as-is -- it's a generic bcrypt wrapper, not user-password-specific);
    the plaintext token is only ever returned once, at registration.

    `status` is an administrative lifecycle flag ("active"/"disabled"),
    distinct from the online/offline indicator shown in the dashboard --
    that is always computed from `last_seen` at read time (see
    agent_service.is_online), never stored, so it can never go stale.

    `last_seen` is the one mutable field in this schema (bumped by every
    authenticated agent call, not just /heartbeat) -- everywhere else in
    this project's schema is append-only/audit-log-style; a live machine's
    liveness genuinely needs an update-in-place field."""

    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
