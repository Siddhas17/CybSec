"""Controlled response endpoints (section 11 of the phase instructions).
Deliberately thin -- every call here goes straight into response_service;
no firewall/shell command and no validation logic lives in this file
(section 2's explicit requirement, matching sensor.py's own precedent)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.user import User
from backend.app.schemas.prevention import PreventionActionOut, PreventionRequestIn, UnblockRequestIn
from backend.app.services.prevention import response_service
from backend.app.services.prevention.response_service import DryRunModeError, PreventionDisabledError

router = APIRouter(prefix="/prevention", tags=["prevention"])


@router.post("/dry-run", response_model=PreventionActionOut)
async def dry_run(
    payload: PreventionRequestIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PreventionAction:
    loop = asyncio.get_running_loop()
    try:
        return response_service.manual_dry_run(
            db, source_ip=payload.source_ip, reason=payload.reason or "manual operator dry-run", user=current_user, loop=loop
        )
    except PreventionDisabledError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/block", response_model=PreventionActionOut)
async def block(
    payload: PreventionRequestIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PreventionAction:
    loop = asyncio.get_running_loop()
    try:
        return response_service.manual_block(
            db, source_ip=payload.source_ip, reason=payload.reason or "manual operator block", user=current_user, loop=loop
        )
    except (PreventionDisabledError, DryRunModeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/unblock", response_model=PreventionActionOut)
async def unblock(
    payload: UnblockRequestIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PreventionAction:
    loop = asyncio.get_running_loop()
    try:
        return response_service.manual_unblock(db, source_ip=payload.source_ip, user=current_user, loop=loop)
    except PreventionDisabledError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/actions", response_model=list[PreventionActionOut])
def list_actions(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[PreventionAction]:
    return db.query(PreventionAction).order_by(PreventionAction.created_at.desc()).offset(offset).limit(limit).all()
