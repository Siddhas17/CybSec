from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class Detection(Base):
    """Derived ML result only (the autoencoder's output) -- kept separate
    from RiskAssessment (section 5): a detection is "this flow's
    reconstruction error and whether it crosses the Phase 3 threshold",
    nothing about graph context or the combined risk score."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    reconstruction_error: Mapped[float] = mapped_column(Float, nullable=False)  # identical value, see docs/autoencoder.md section 8
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    threshold_used: Mapped[float] = mapped_column(Float, nullable=False)

    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
