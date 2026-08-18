from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class EventSource(str, enum.Enum):
    """Where an event came from -- always shown in the UI (section 19: be
    precise about what's demo/test vs. real). LIVE is reserved for the
    future sensor phase (section 18) and not produced by anything in
    Phase 5."""

    OFFLINE_DEMO = "offline_demo"
    TEST_EVENT = "test_event"
    LIVE = "live"


class Event(Base):
    """Raw event data only -- source/destination/protocol/timestamp and
    which real dataset category (if known) it came from. Derived ML
    results, graph context, and risk assessments are separate tables
    (Detection, RiskAssessment) joined by event_id -- never merged into
    one opaque object (section 5)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_uid: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Ground truth, only populated for offline-demo events sourced from the
    # labeled CICIDS2017 data -- never available for a genuinely unknown
    # future live event.
    canonical_attack_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    traffic_class: Mapped[str | None] = mapped_column(String(16), nullable=True)

    source: Mapped[EventSource] = mapped_column(Enum(EventSource), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="processed")

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False, index=True)
