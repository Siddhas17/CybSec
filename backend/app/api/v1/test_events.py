"""POST /api/v1/test-events: a controlled test event, scored through the
real AnalyticalPipeline (never fabricated) and persisted with
source=EventSource.TEST_EVENT -- always distinguishable from offline-demo
or (future) live events (section 10/19)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.detection import Detection
from backend.app.models.event import Event, EventSource
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.user import User
from backend.app.schemas.event import TestEventCreate
from backend.app.services.analytical_pipeline import AnalyticalPipeline, TelemetryEvent
from backend.app.services.graph_service import get_edge_context
from backend.app.services.model_registry import ensure_all_model_versions, get_predictor, get_risk_config
from backend.app.websocket.manager import manager

router = APIRouter(prefix="/test-events", tags=["test-events"])


@router.post("")
async def create_test_event(
    payload: TestEventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    versions = ensure_all_model_versions(db)
    pipeline = AnalyticalPipeline(get_predictor(), get_risk_config())

    graph_context = get_edge_context(db, payload.source_ip, payload.destination_ip)
    telemetry = TelemetryEvent(
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        source_port=payload.source_port,
        destination_port=payload.destination_port,
        protocol=payload.protocol,
        features=payload.features,
        canonical_attack_label=payload.canonical_attack_label,
    )
    result = pipeline.score(telemetry, graph_context)

    event = Event(
        event_uid=f"test-event-{uuid.uuid4()}",
        timestamp=datetime.now(UTC),
        source_ip=payload.source_ip,
        source_port=payload.source_port,
        destination_ip=payload.destination_ip,
        destination_port=payload.destination_port,
        protocol=payload.protocol,
        canonical_attack_label=payload.canonical_attack_label,
        traffic_class=None,
        source=EventSource.TEST_EVENT,
        status="processed",
    )
    db.add(event)
    db.flush()

    detection = Detection(
        event_id=event.id,
        anomaly_score=result.anomaly_score,
        reconstruction_error=result.reconstruction_error,
        is_anomaly=result.is_anomaly,
        threshold_used=result.threshold_used,
        model_version_id=versions["autoencoder"].id,
    )
    db.add(detection)
    db.flush()

    risk_assessment = RiskAssessment(
        event_id=event.id,
        detection_id=detection.id,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        factors=result.factors,
        rules_applied=result.rules_applied,
        reason=result.reason,
        risk_config_version_id=versions["risk_engine"].id,
    )
    db.add(risk_assessment)
    db.commit()

    response = {
        "event_id": event.id,
        "event_uid": event.event_uid,
        "source": "test_event",
        "anomaly_score": result.anomaly_score,
        "is_anomaly": result.is_anomaly,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "factors": result.factors,
        "rules_applied": result.rules_applied,
        "reason": result.reason,
        "imputed_features": result.imputed_features,
        "graph_context_found": not graph_context.is_empty(),
    }

    await manager.broadcast(
        "new_threat",
        {
            "event_id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "event_source": "test_event",
        },
    )

    return response
