"""Pydantic schemas for the response/prevention API (section 11 of the
phase instructions)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PreventionActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int | None
    detection_id: int | None
    risk_assessment_id: int | None
    user_id: int | None
    source_ip: str
    risk_score: float | None
    risk_level: str | None
    requested_action: str
    actual_action: str
    dry_run: bool
    success: bool
    reason: str
    adapter: str
    target_scope: str | None
    created_at: datetime


class PreventionRequestIn(BaseModel):
    """Input for POST /prevention/{dry-run,block}. `reason` defaults to a
    generic label if omitted -- never fabricated as if it came from an
    automatic policy decision (those set their own precise reason)."""

    source_ip: str
    reason: str | None = None


class UnblockRequestIn(BaseModel):
    source_ip: str
