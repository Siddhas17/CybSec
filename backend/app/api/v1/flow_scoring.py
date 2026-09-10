"""POST /api/v1/agents/flow-score -- SCORE-ONLY endpoint for a completed
victim_agent Flow's already-computed 67-feature vector.

This is the networked twin of backend.app.services.
victim_agent_flow_bridge.score_victim_agent_flow(): that function converts
an in-process victim_agent.flow.Flow object, which only makes sense when
capture/flow-reconstruction and scoring share one process (see
scripts/validate_live_flow_risk.py). A real victim_agent runs on a
separate machine with only psutil/httpx/scapy installed -- Flow.
to_cicids_features() runs there (lightweight, no backend/ML deps), and
only its output (this endpoint's request body) crosses the network. This
handler reconstructs the same TelemetryEvent shape from that output and
reuses victim_agent_flow_bridge.protocol_name_to_iana() for protocol
mapping, so the mapping logic still lives in exactly one place -- not
duplicated here.

Deliberately does NOT persist anything (no Event/Detection/RiskAssessment
row), does NOT broadcast over WebSocket, and does NOT call the prevention
response layer -- unlike test_events.py's /test-events, which does all
three. This checkpoint is score-only by explicit instruction; a later
phase can decide whether/how live victim-agent detections should be
persisted and whether they should feed the same automatic ALERT/
BLOCK_CANDIDATE response live_sensor_service.py already has for the
loopback sensor. KNN is never invoked -- same as every other scoring path
in this codebase (see ml.models.knn_inference.KNNPredictor's own
docstring).

The only database write this endpoint causes at all is the agents.
last_seen touch get_current_agent() already performs for every
agent-authenticated endpoint (register/heartbeat/telemetry) as a side
effect of authentication -- not something this endpoint adds.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_agent, get_db
from backend.app.models.agent import Agent
from backend.app.schemas.flow_scoring import VictimFlowScoreIn, VictimFlowScoreOut
from backend.app.services import graph_service
from backend.app.services.analytical_pipeline import AnalyticalPipeline, TelemetryEvent
from backend.app.services.model_registry import get_predictor, get_risk_config
from backend.app.services.victim_agent_flow_bridge import protocol_name_to_iana

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/flow-score", response_model=VictimFlowScoreOut)
def score_agent_flow(
    payload: VictimFlowScoreIn,
    db: Session = Depends(get_db),
    _current_agent: Agent = Depends(get_current_agent),
) -> VictimFlowScoreOut:
    telemetry = TelemetryEvent(
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        source_port=payload.source_port,
        destination_port=payload.destination_port,
        protocol=protocol_name_to_iana(payload.protocol),
        timestamp=payload.timestamp,
        features=payload.features,
    )
    graph_context = graph_service.get_edge_context(db, payload.source_ip, payload.destination_ip)

    pipeline = AnalyticalPipeline(get_predictor(), get_risk_config())
    result = pipeline.score(telemetry, graph_context)

    return VictimFlowScoreOut(
        anomaly_score=result.anomaly_score,
        reconstruction_error=result.reconstruction_error,
        is_anomaly=result.is_anomaly,
        threshold_used=result.threshold_used,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        factors=result.factors,
        rules_applied=result.rules_applied,
        reason=result.reason,
        imputed_features=result.imputed_features,
        graph_context_used=not graph_context.is_empty(),
    )
