"""Bridges victim_agent/ (Npcap/Scapy capture -> flow reconstruction ->
67-feature CICIDS2017 extraction) into the exact same
TelemetryEvent -> AnalyticalPipeline.score() -> DetectionResult path
test-events, offline ingestion, and the loopback live sensor
(live_sensor_service.py's _process_flow()) already use -- this module
contains zero scoring logic of its own, matching that precedent's own
"no second ML implementation for live traffic" rule.

Deliberately minimal: unlike live_sensor_service.py's _process_flow(),
this module does NOT persist an Event/Detection/RiskAssessment, does NOT
broadcast over WebSocket, and does NOT call the prevention response layer
-- it only converts a completed victim_agent.flow.Flow into a
DetectionResult in memory. A caller that wants the full live-sensor
behavior (persistence, broadcast, automatic ALERT/BLOCK_CANDIDATE
response) must add that itself; nothing here enables it implicitly.

KNN is intentionally never called from here -- ml.models.knn_inference.
KNNPredictor and backend.app.services.model_registry.get_knn_predictor()
are both explicit that KNN stays offline-evaluation-only.
"""

from __future__ import annotations

import re

from victim_agent.flow import Flow

from backend.app.services.analytical_pipeline import AnalyticalPipeline, DetectionResult, GraphContext, TelemetryEvent

# The 3 protocols victim_agent.capture currently names explicitly (see
# capture.py's PacketMetadata.protocol / _IP_PROTOCOL_NAMES). Mapped to
# their real IANA protocol numbers -- the same values
# sensor.normalization.flow_reconstruction.RawFlow.protocol already uses
# (an int), which is what TelemetryEvent.protocol expects.
_PROTOCOL_NAME_TO_IANA: dict[str, int] = {"TCP": 6, "UDP": 17, "ICMP": 1}

# capture.py falls back to this exact "IP-PROTO-<n>" format for any IP
# protocol number it doesn't have a friendly name for -- the real IANA
# number is already encoded in the string, so recovering it here is exact
# recovery of known data, not a guess.
_IP_PROTO_FALLBACK_RE = re.compile(r"^IP-PROTO-(\d+)$")


def protocol_name_to_iana(protocol_name: str) -> int | None:
    """TCP -> 6, UDP -> 17, ICMP -> 1, "IP-PROTO-<n>" -> n (exact recovery
    of the number victim_agent.capture already determined). Returns None
    -- never a fabricated/guessed number -- for any other named protocol
    (e.g. "IGMP", "GRE"): TelemetryEvent.protocol already accepts None."""
    if protocol_name in _PROTOCOL_NAME_TO_IANA:
        return _PROTOCOL_NAME_TO_IANA[protocol_name]
    match = _IP_PROTO_FALLBACK_RE.match(protocol_name)
    if match:
        return int(match.group(1))
    return None


def flow_to_telemetry_event(flow: Flow) -> TelemetryEvent:
    """Converts one completed victim_agent Flow into the same TelemetryEvent
    shape live_sensor_service._process_flow() builds from a sensor RawFlow
    -- source/destination IP+port, numeric protocol, start timestamp, and
    the full 67-name feature dict from Flow.to_cicids_features() (already
    verified compatible with AnalyticalPipeline's feature ordering in the
    prior read-only ML integration test)."""
    return TelemetryEvent(
        source_ip=flow.source_ip,
        destination_ip=flow.destination_ip,
        source_port=flow.source_port,
        destination_port=flow.destination_port,
        protocol=protocol_name_to_iana(flow.protocol),
        timestamp=flow.start_timestamp,
        features=flow.to_cicids_features(),
    )


def score_victim_agent_flow(flow: Flow, pipeline: AnalyticalPipeline, graph_context: GraphContext | None = None) -> DetectionResult:
    """Scores one completed victim_agent Flow through the existing,
    unmodified AnalyticalPipeline (autoencoder + risk_engine). KNN is
    never invoked here.

    graph_context is not looked up by this function -- reuse the existing
    mechanism instead: a caller with a live DB session should call
    backend.app.services.graph_service.get_edge_context(db, flow.source_ip,
    flow.destination_ip) and pass its result here, the same way
    live_sensor_service.py does with its own (in-memory LIVE_GRAPH)
    equivalent. Omitting graph_context (or passing None) scores on
    anomaly evidence alone, using the risk engine's own documented neutral
    defaults for the missing graph signals -- see risk_engine/schemas.py.
    """
    telemetry = flow_to_telemetry_event(flow)
    return pipeline.score(telemetry, graph_context)
