"""Audit logging helper (section 12)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.app.models.system_log import SystemLog


def log(db: Session, level: str, category: str, message: str, user_id: int | None = None, metadata: dict | None = None) -> None:
    db.add(SystemLog(level=level, category=category, message=message, user_id=user_id, log_metadata=metadata))
    db.commit()
