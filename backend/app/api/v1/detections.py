from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.detection import Detection
from backend.app.models.user import User
from backend.app.schemas.event import DetectionOut

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("", response_model=list[DetectionOut])
def list_detections(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    is_anomaly: bool | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[Detection]:
    q = db.query(Detection)
    if is_anomaly is not None:
        q = q.filter(Detection.is_anomaly == is_anomaly)
    return q.order_by(Detection.id.desc()).offset(offset).limit(limit).all()
