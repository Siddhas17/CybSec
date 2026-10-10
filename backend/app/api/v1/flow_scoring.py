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
row), broadcast over the global WebSocket, or call the prevention response
layer -- unlike test_events.py's /test-events, which does all three. A
transient result is broadcast only through the separate Admin-authenticated
WebSocket channel. KNN is never invoked -- same as every other scoring
path in this codebase (see ml.models.knn_inference.KNNPredictor's own
docstring).

The only database write this endpoint causes at all is the agents.
last_seen touch get_current_agent() already performs for every
agent-authenticated endpoint (register/heartbeat/telemetry) as a side
effect of authentication -- not something this endpoint adds.

LiveGraph integration (bounded in-memory graph context for pairs the
offline graph has never seen): a process-local sensor.live_graph.LiveGraph
instance -- separate from live_sensor_service.py's own instance; victim-
agent traffic and loopback-sensor traffic are never mixed into one graph
-- supplies graph context ONLY when graph_service.get_edge_context()
(the historical, MySQL-persisted graph) returns empty for this exact
pair, AND only once that edge has accumulated at least
LIVE_GRAPH_MIN_FLOWS observations of its own. This is a PRECEDENCE rule,
not a merge: historical evidence, when present, is used exactly as
before, unchanged; live evidence is a fallback for unseen pairs, never
blended with historical evidence for the same pair. The minimum-sample
gate determines when observed-flow counts and timestamps are supplied as
context; LiveGraph does not treat verdicts or risk scores as attack
evidence. Its attack-specific context fields remain unset. record_flow()
is called after scoring regardless of result, storing the observation
only. Still zero MySQL writes for anything graph-related: LiveGraph is
pure in-memory and is reset on every process restart.
"""

from __future__ import annotations

import time
from functools import lru_cache

from anyio import from_thread
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_agent, get_db
from backend.app.models.agent import Agent
from backend.app.schemas.flow_scoring import VictimFlowScoreIn, VictimFlowScoreOut
from backend.app.services import graph_service
from backend.app.services.analytical_pipeline import AnalyticalPipeline, GraphContext, TelemetryEvent
from backend.app.services.model_registry import get_predictor, get_risk_config
from backend.app.services.victim_agent_flow_bridge import protocol_name_to_iana
from backend.app.websocket.manager import manager
from sensor.config import sensor_config
from sensor.live_graph import LiveGraph

router = APIRouter(prefix="/agents", tags=["agents"])

# Minimum observed flows on an edge before its observational LiveGraph
# context is used. This is a history-size gate, not a claim that the edge
# has any confirmed attack activity.
LIVE_GRAPH_MIN_FLOWS = 10


@lru_cache(maxsize=1)
def _get_victim_live_graph() -> LiveGraph:
    """One process-wide, in-memory LiveGraph for victim-agent flows --
    mirrors backend.app.services.model_registry's existing
    @lru_cache(maxsize=1) singleton pattern for the predictor/risk config.
    Reuses the same sensor.config knobs live_sensor_service.py's own
    LiveGraph already uses; this is a SEPARATE instance from that one."""
    return LiveGraph(window_seconds=sensor_config.live_graph_window_seconds, max_edges=sensor_config.live_graph_max_edges)


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

    live_graph = _get_victim_live_graph()

    # Historical (offline, MySQL-persisted) graph context takes precedence,
    # completely unchanged from before. Live context is only ever a
    # fallback for a pair the historical graph has never seen -- never
    # merged with historical evidence for the same pair.
    graph_context = graph_service.get_edge_context(db, payload.source_ip, payload.destination_ip)
    if graph_context.is_empty():
        live_graph.cleanup(time.time())
        live_context = live_graph.get_context(payload.source_ip, payload.destination_ip)
        if (live_context.edge_flow_count or 0) >= LIVE_GRAPH_MIN_FLOWS:
            graph_context = GraphContext(
                edge_flow_count=live_context.edge_flow_count,
                edge_first_seen=live_context.edge_first_seen,
                edge_last_seen=live_context.edge_last_seen,
            )

    pipeline = AnalyticalPipeline(get_predictor(), get_risk_config())
    result = pipeline.score(telemetry, graph_context)

    live_graph.record_flow(
        payload.source_ip,
        payload.destination_ip,
        payload.source_port,
        payload.destination_port,
        telemetry.protocol,
        payload.timestamp.timestamp(),
    )

    from_thread.run(
        manager.broadcast_admin_flow_score,
        {
            "agent_id": _current_agent.agent_id,
            "source_ip": payload.source_ip,
            "destination_ip": payload.destination_ip,
            "protocol": payload.protocol,
            "timestamp": payload.timestamp.isoformat(),
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "is_anomaly": result.is_anomaly,
            "graph_context_used": not graph_context.is_empty(),
        },
    )

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
