from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.model_version import ModelVersion
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.user import User
from backend.app.schemas.event import RiskAssessmentOut

router = APIRouter(prefix="/risks", tags=["risks"])


@router.get("", response_model=list[RiskAssessmentOut])
def list_risks(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    min_risk_score: float | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[RiskAssessment]:
    q = db.query(RiskAssessment)
    if min_risk_score is not None:
        q = q.filter(RiskAssessment.risk_score >= min_risk_score)
    return q.order_by(RiskAssessment.risk_score.desc()).offset(offset).limit(limit).all()


@router.get("/{event_id}", response_model=RiskAssessmentOut)
def get_risk_for_event(event_id: int, db: Session = Depends(get_db), _current_user: User = Depends(get_current_user)) -> RiskAssessment:
    risk = db.query(RiskAssessment).filter(RiskAssessment.event_id == event_id).first()
    if risk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No risk assessment for this event")
    return risk
