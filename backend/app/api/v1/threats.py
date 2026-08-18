from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.user import User
from backend.app.schemas.threat import ThreatRowOut

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=list[ThreatRowOut])
def list_threats(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    min_risk_score: float | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[ThreatRowOut]:
    q = (
        db.query(Event, Detection, RiskAssessment)
        .outerjoin(Detection, Detection.event_id == Event.id)
        .outerjoin(RiskAssessment, RiskAssessment.event_id == Event.id)
    )
    if min_risk_score is not None:
        q = q.filter(RiskAssessment.risk_score >= min_risk_score)
    rows = q.order_by(Event.timestamp.desc()).offset(offset).limit(limit).all()

    return [
        ThreatRowOut(
            event_id=event.id,
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            source_port=event.source_port,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            protocol=event.protocol,
            canonical_attack_label=event.canonical_attack_label,
            anomaly_score=detection.anomaly_score if detection else None,
            is_anomaly=detection.is_anomaly if detection else None,
            risk_score=risk.risk_score if risk else None,
            risk_level=risk.risk_level if risk else None,
            event_source=event.source.value,
        )
        for event, detection, risk in rows
    ]
