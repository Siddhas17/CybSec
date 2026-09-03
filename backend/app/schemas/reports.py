from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SecurityReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    generated_by_user_id: int | None
    generation_status: str
    error_message: str | None
    file_path: str | None
    file_size_bytes: int | None
    report_period_start: datetime | None
    report_period_end: datetime | None
    summary_stats: dict | None
    model_version_snapshot: dict | None
    created_at: datetime
