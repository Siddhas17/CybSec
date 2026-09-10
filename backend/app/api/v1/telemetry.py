"""Raw victim_agent connection telemetry ingestion (Phase 1). Deliberately
does NOT call backend.app.services.analytical_pipeline.AnalyticalPipeline
-- see backend/app/models/agent_telemetry_event.py's docstring and
docs/victim_agent.md for why. This endpoint only validates and persists;
it never scores anything."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_agent, get_db, require_admin
from backend.app.models.agent import Agent
from backend.app.models.agent_telemetry_event import AgentTelemetryEvent
from backend.app.models.user import User
from backend.app.schemas.telemetry import TelemetryBatchIn, TelemetryBatchOut, TelemetryEventOut
from backend.app.services import agent_service

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.post("/events", response_model=TelemetryBatchOut)
def ingest_telemetry(
    payload: TelemetryBatchIn,
    db: Session = Depends(get_db),
    current_agent: Agent = Depends(get_current_agent),
) -> TelemetryBatchOut:
    if payload.agent_id != current_agent.agent_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="agent_id does not match authenticated agent")
    count = agent_service.ingest_telemetry_batch(db, current_agent, payload)
    return TelemetryBatchOut(accepted=True, connections_received=count, agent_id=current_agent.agent_id, timestamp=payload.timestamp)


@router.get("/events", response_model=list[TelemetryEventOut])
def list_telemetry(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    agent_id: str | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin),
) -> list[AgentTelemetryEvent]:
    q = db.query(AgentTelemetryEvent)
    if agent_id:
        agent = agent_service.get_agent_by_agent_id(db, agent_id)
        if agent is None:
            return []
        q = q.filter(AgentTelemetryEvent.agent_id == agent.id)
    return q.order_by(AgentTelemetryEvent.received_at.desc()).offset(offset).limit(limit).all()
