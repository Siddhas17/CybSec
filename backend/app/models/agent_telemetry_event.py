from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class AgentTelemetryEvent(Base):
    """Raw, unscored OS-connection telemetry reported by a victim_agent
    (Phase 1) -- one row per observed connection, matching Event's "one row
    per flow" convention. Deliberately NOT the events/detections/
    risk_assessments tables and never touched by AnalyticalPipeline.score():
    a point-in-time psutil connection has nothing resembling the trained
    autoencoder's 67 CICIDS2017-style features, so scoring it would silently
    fabricate an anomaly/risk score against near-all-imputed input. A future
    phase will build a real feature extractor bridging this raw data to that
    pipeline; this table is ingestion-only.

    `protocol` is deliberately a string ("TCP"/"UDP", psutil's own
    vocabulary) rather than Event.protocol's IANA integer -- these are
    different, disclosed data models, not an inconsistency.

    `collected_at` (agent's own clock) is kept separate from `received_at`
    (server insert time) so telemetry delayed by the victim_agent's bounded
    retry queue after an Admin outage is observable after the fact."""

    __tablename__ = "agent_telemetry_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)

    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)

    hostname: Mapped[str] = mapped_column(String(255), nullable=False)

    local_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    local_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Null is correct for a LISTEN socket -- it has no peer yet, never fabricated.
    remote_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    connection_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
