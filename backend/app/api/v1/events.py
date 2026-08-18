from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.detection import Detection
from backend.app.models.event import Event, EventSource
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.user import User
from backend.app.schemas.event import DetectionOut, EventDetailOut, EventOut, GraphContextOut, RiskAssessmentOut
from backend.app.services.graph_service import get_edge_context

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=list[EventOut])
def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source: str | None = None,
    traffic_class: str | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[Event]:
    q = db.query(Event)
    if source:
        try:
            q = q.filter(Event.source == EventSource(source))
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Invalid source {source!r}, expected one of {[s.value for s in EventSource]}")
    if traffic_class:
        q = q.filter(Event.traffic_class == traffic_class)
    return q.order_by(Event.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/{event_id}", response_model=EventDetailOut)
def get_event(event_id: int, db: Session = Depends(get_db), _current_user: User = Depends(get_current_user)) -> EventDetailOut:
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Event not found")

    detection = db.query(Detection).filter(Detection.event_id == event_id).first()
    risk = db.query(RiskAssessment).filter(RiskAssessment.event_id == event_id).first()
    graph_context = get_edge_context(db, event.source_ip, event.destination_ip)

    return EventDetailOut(
        **EventOut.model_validate(event).model_dump(),
        detection=DetectionOut.model_validate(detection) if detection else None,
        risk_assessment=RiskAssessmentOut.model_validate(risk) if risk else None,
        graph_context=GraphContextOut(**graph_context.__dict__) if not graph_context.is_empty() else None,
    )
