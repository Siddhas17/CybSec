from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class PreventionAction(Base):
    """Response/prevention audit trail (section 9/10 of the phase
    instructions) -- every dry-run, alert, block, unblock, and rejected
    attempt this project's response layer ever produces, real or
    simulated. Never deleted when an IP is later unblocked (section 10) --
    `unblock` is its own new row, not an edit of the original `block` row,
    so the history stays intact."""

    __tablename__ = "prevention_actions"

    id: Mapped[int] = mapped_column(primary_key=True)

    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True)
    detection_id: Mapped[int | None] = mapped_column(ForeignKey("detections.id", ondelete="SET NULL"), nullable=True)
    risk_assessment_id: Mapped[int | None] = mapped_column(ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True)
    # Null for a policy-driven automatic action (no operator involved);
    # set for a manually-triggered dry-run/block/unblock API call.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # What was asked for: "alert" | "dry_run" | "block" | "unblock".
    requested_action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # What actually happened: "alerted" | "would_block" | "blocked" |
    # "unblocked" | "rejected" | "failed" -- may differ from
    # requested_action (e.g. requested "block", actual "rejected" because
    # the target IP failed lab-scope validation).
    actual_action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    # Which configured lab CIDR matched, or the loopback-exception label;
    # null when the target was rejected before a scope could be determined.
    target_scope: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False, index=True)
