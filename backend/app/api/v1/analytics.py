from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.user import User
from backend.app.schemas.analytics import (
    AttacksByTypeOut,
    ModelInfoOut,
    RiskDistributionBucket,
    SummaryOut,
    TimelinePoint,
    TopNodeOut,
)
from backend.app.services import analytics_service
from backend.app.services.model_registry import (
    ATTACK_GRAPH_VERSION,
    AUTOENCODER_VERSION,
    PREPROCESSING_VERSION,
    get_predictor,
    get_risk_config,
)

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/summary", response_model=SummaryOut)
def summary(db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> SummaryOut:
    return SummaryOut(**analytics_service.get_summary(db))


@router.get("/attacks-by-type", response_model=list[AttacksByTypeOut])
def attacks_by_type(db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> list[AttacksByTypeOut]:
    return [AttacksByTypeOut(**row) for row in analytics_service.get_attacks_by_type(db)]


@router.get("/risk-distribution", response_model=list[RiskDistributionBucket])
def risk_distribution(db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> list[RiskDistributionBucket]:
    return [RiskDistributionBucket(**row) for row in analytics_service.get_risk_distribution(db)]


@router.get("/timeline", response_model=list[TimelinePoint])
def timeline(db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> list[TimelinePoint]:
    return [TimelinePoint(**row) for row in analytics_service.get_timeline(db)]


@router.get("/top-sources", response_model=list[TopNodeOut])
def top_sources(limit: int = 10, db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> list[TopNodeOut]:
    return [TopNodeOut(**row) for row in analytics_service.get_top_sources(db, limit)]


@router.get("/top-destinations", response_model=list[TopNodeOut])
def top_destinations(limit: int = 10, db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> list[TopNodeOut]:
    return [TopNodeOut(**row) for row in analytics_service.get_top_destinations(db, limit)]


@router.get("/anomaly-score-distribution")
def anomaly_score_distribution(db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> list[dict]:
    return analytics_service.get_anomaly_score_distribution(db)


@router.get("/risk-score-distribution")
def risk_score_distribution(db: Session = Depends(get_db), _u: User = Depends(get_current_user)) -> list[dict]:
    return analytics_service.get_risk_score_distribution(db)


@router.get("/model-info", response_model=ModelInfoOut)
def model_info(_u: User = Depends(get_current_user)) -> ModelInfoOut:
    predictor = get_predictor()
    risk_config = get_risk_config()
    return ModelInfoOut(
        preprocessing_version=PREPROCESSING_VERSION,
        autoencoder_version=AUTOENCODER_VERSION,
        autoencoder_threshold=predictor.threshold,
        attack_graph_version=ATTACK_GRAPH_VERSION,
        risk_engine_version=risk_config.version,
        risk_engine_weights=risk_config.weights,
    )
