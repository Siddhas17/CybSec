"""Live sensor control/health (section 10/14). Deliberately thin -- every
call here just starts/stops/reads backend.app.services.live_sensor_service;
no ML code lives in this file (section 10's explicit requirement)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.user import User
from backend.app.services import audit
from backend.app.services.live_sensor_service import live_sensor_service
from sqlalchemy.orm import Session

router = APIRouter(prefix="/sensor", tags=["sensor"])


@router.get("/health")
def sensor_health(_current_user: User = Depends(get_current_user)) -> dict:
    return live_sensor_service.health().__dict__


@router.post("/start")
async def start_sensor(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    try:
        live_sensor_service.start(asyncio.get_running_loop())
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    audit.log(db, "INFO", "sensor", "Live sensor started", user_id=current_user.id)
    return {"status": "started", "health": live_sensor_service.health().__dict__}


@router.post("/stop")
def stop_sensor(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    live_sensor_service.stop()
    audit.log(db, "INFO", "sensor", "Live sensor stopped", user_id=current_user.id)
    return {"status": "stopped", "health": live_sensor_service.health().__dict__}
