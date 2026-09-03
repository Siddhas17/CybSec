from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class SecurityReport(Base):
    """One row per PDF security-report generation attempt -- created even
    when generation fails (mirrors PreventionAction's "always record, even
    failures" convention), so admins can see and diagnose a failed run
    instead of it silently vanishing."""

    __tablename__ = "security_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    generated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    generation_status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # "complete" | "failed"
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    file_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    report_period_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    report_period_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    summary_stats: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    model_version_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False, index=True)
