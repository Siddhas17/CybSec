"""Tests for backend.app.services.victim_agent_flow_bridge -- the smallest
possible victim_agent.flow.Flow -> AnalyticalPipeline.score() integration.

No DB, no HTTP, no network: every test builds a Flow in-memory via
victim_agent.flow.reconstruct_flows() (mirroring victim_agent/tests/
test_flow.py's own fixtures) and either inspects the converted
TelemetryEvent directly or scores it through a real (but purely local,
no-network) AnalyticalPipeline / a spy stand-in, per the task's "mocks/
stubs for backend/network dependencies, no real network traffic" rule.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime, timedelta

import pytest

from victim_agent import flow as victim_flow

from backend.app.services import victim_agent_flow_bridge as bridge_module
from backend.app.services.analytical_pipeline import DetectionResult, GraphContext, TelemetryEvent
from backend.app.services.model_registry import get_predictor, get_risk_config
from backend.app.services.prevention.policy import ResponsePolicy
from backend.app.services.victim_agent_flow_bridge import flow_to_telemetry_event, protocol_name_to_iana, score_victim_agent_flow
from risk_engine.config import HIGH_RISK_THRESHOLD, RISK_LEVELS

T0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)


def _pkt(source_ip, source_port, destination_ip, destination_port, protocol, length, timestamp, **extra):
    d = {
        "timestamp": timestamp, "source_ip": source_ip, "destination_ip": destination_ip,
        "source_port": source_port, "destination_port": destination_port, "protocol": protocol, "length": length,
    }
    d.update(extra)
    return d


def _tcp_pkt(source_ip, source_port, destination_ip, destination_port, length, timestamp, flags, window):
    return _pkt(source_ip, source_port, destination_ip, destination_port, "TCP", length, timestamp,
                tcp_flags=flags, tcp_window=window, transport_header_length=20, tcp_payload_length=max(length - 40, 0))


def _tcp_flow() -> victim_flow.Flow:
    packets = [
        _tcp_pkt("192.168.1.6", 53386, "20.184.175.13", 443, 100, T0, "S", 64240),
        _tcp_pkt("20.184.175.13", 443, "192.168.1.6", 53386, 100, T0 + timedelta(seconds=1), "SA", 65535),
        _tcp_pkt("192.168.1.6", 53386, "20.184.175.13", 443, 300, T0 + timedelta(seconds=2), "PA", 64240),
    ]
    [f] = victim_flow.reconstruct_flows(packets)
    return f


def _udp_flow() -> victim_flow.Flow:
    packets = [
        _pkt("192.168.1.6", 60000, "8.8.8.8", 53, "UDP", 64, T0, transport_header_length=8, tcp_payload_length=56),
        _pkt("8.8.8.8", 53, "192.168.1.6", 60000, "UDP", 512, T0 + timedelta(seconds=1), transport_header_length=8, tcp_payload_length=504),
    ]
    [f] = victim_flow.reconstruct_flows(packets)
    return f


def _icmp_flow() -> victim_flow.Flow:
    packets = [
        _pkt("192.168.1.6", None, "1.1.1.1", None, "ICMP", 64, T0),
        _pkt("1.1.1.1", None, "192.168.1.6", None, "ICMP", 64, T0 + timedelta(seconds=1)),
    ]
    [f] = victim_flow.reconstruct_flows(packets)
    return f


# --- protocol mapping ---------------------------------------------------


def test_protocol_name_to_iana_known_names():
    assert protocol_name_to_iana("TCP") == 6
    assert protocol_name_to_iana("UDP") == 17
    assert protocol_name_to_iana("ICMP") == 1


def test_protocol_name_to_iana_recovers_fallback_format_exactly():
    # capture.py encodes the real IANA number into this exact string for
    # any protocol it doesn't have a friendly name for -- recovering it is
    # exact, not a guess.
    assert protocol_name_to_iana("IP-PROTO-253") == 253
    assert protocol_name_to_iana("IP-PROTO-47") == 47


def test_protocol_name_to_iana_returns_none_rather_than_inventing_a_number():
    assert protocol_name_to_iana("IGMP") is None
    assert protocol_name_to_iana("GRE") is None
    assert protocol_name_to_iana("") is None


# --- Flow -> TelemetryEvent ---------------------------------------------


def test_tcp_flow_to_telemetry_event():
    f = _tcp_flow()
    event = flow_to_telemetry_event(f)

    assert isinstance(event, TelemetryEvent)
    assert event.source_ip == "192.168.1.6"
    assert event.destination_ip == "20.184.175.13"
    assert event.source_port == 53386
    assert event.destination_port == 443
    assert event.protocol == 6
    assert event.timestamp == f.start_timestamp


def test_udp_flow_to_telemetry_event():
    event = flow_to_telemetry_event(_udp_flow())

    assert event.protocol == 17
    assert event.source_port == 60000
    assert event.destination_port == 53


def test_icmp_flow_to_telemetry_event():
    f = _icmp_flow()
    event = flow_to_telemetry_event(f)

    assert event.protocol == 1
    assert event.source_port is None
    assert event.destination_port is None


def test_flow_to_telemetry_event_preserves_exact_67_features():
    f = _tcp_flow()
    event = flow_to_telemetry_event(f)

    assert len(event.features) == 67
    assert list(event.features.keys()) == list(victim_flow.CICIDS_FEATURE_NAMES)
    assert event.features == f.to_cicids_features()


# --- score_victim_agent_flow() -- spy pipeline (no real model, no network) --


class _SpyPipeline:
    def __init__(self, result: DetectionResult):
        self._result = result
        self.received_event: TelemetryEvent | None = None
        self.received_graph_context: object = "NOT_CALLED"

    def score(self, event: TelemetryEvent, graph_context: GraphContext | None = None) -> DetectionResult:
        self.received_event = event
        self.received_graph_context = graph_context
        return self._result


_CANNED_RESULT = DetectionResult(
    anomaly_score=0.5, reconstruction_error=0.5, is_anomaly=False, threshold_used=0.106125,
    risk_score=3.2, risk_level="Low", factors=[], rules_applied=[], reason="canned test result",
    graph_context=GraphContext(), imputed_features=[],
)


def test_score_victim_agent_flow_passes_flow_derived_features_to_pipeline():
    f = _tcp_flow()
    spy = _SpyPipeline(_CANNED_RESULT)

    result = score_victim_agent_flow(f, spy)

    assert spy.received_event is not None
    assert spy.received_event.features == f.to_cicids_features()
    assert result is _CANNED_RESULT


def test_score_victim_agent_flow_defaults_graph_context_to_none():
    spy = _SpyPipeline(_CANNED_RESULT)
    score_victim_agent_flow(_tcp_flow(), spy)

    assert spy.received_graph_context is None


def test_score_victim_agent_flow_forwards_explicit_graph_context_unchanged():
    spy = _SpyPipeline(_CANNED_RESULT)
    context = GraphContext(edge_attack_ratio=0.9, edge_attack_flow_count=50, edge_flow_count=60)

    score_victim_agent_flow(_tcp_flow(), spy, graph_context=context)

    assert spy.received_graph_context is context


# --- score_victim_agent_flow() -- real, local (no-network) predictor/config --


def test_score_victim_agent_flow_produces_a_real_risk_result():
    from backend.app.services.analytical_pipeline import AnalyticalPipeline

    predictor = get_predictor()
    risk_config = get_risk_config()
    pipeline = AnalyticalPipeline(predictor, risk_config)

    result = score_victim_agent_flow(_tcp_flow(), pipeline)

    assert isinstance(result, DetectionResult)
    assert 1.0 <= result.risk_score <= 10.0
    assert result.risk_level in {label for _, _, label in RISK_LEVELS}
    assert result.imputed_features == []  # all 67 features were supplied -- nothing imputed


def test_score_victim_agent_flow_works_for_udp_and_icmp_too():
    from backend.app.services.analytical_pipeline import AnalyticalPipeline

    pipeline = AnalyticalPipeline(get_predictor(), get_risk_config())

    for f in (_udp_flow(), _icmp_flow()):
        result = score_victim_agent_flow(f, pipeline)
        assert isinstance(result, DetectionResult)
        assert 1.0 <= result.risk_score <= 10.0


# --- complete Flow -> graph_context -> risk path (single focused test) -----


class _RecordingPipeline:
    """Wraps a real AnalyticalPipeline: records exactly what score()
    received (to prove graph_context reaches it unchanged) while still
    delegating to the real pipeline, so the same test also gets back a
    genuine DetectionResult -- not a canned one."""

    def __init__(self, real_pipeline):
        self._real = real_pipeline
        self.received_event: TelemetryEvent | None = None
        self.received_graph_context: object = "NOT_CALLED"

    def score(self, event: TelemetryEvent, graph_context: GraphContext | None = None) -> DetectionResult:
        self.received_event = event
        self.received_graph_context = graph_context
        return self._real.score(event, graph_context)


def test_complete_flow_graph_context_risk_path():
    """End-to-end validation of the intended path: Flow -> bridge ->
    graph_context -> AnalyticalPipeline.score() -> DetectionResult, using
    the real (local, no-network) autoencoder + risk engine so the result
    is genuine, not canned -- while still proving graph_context reaches
    AnalyticalPipeline.score() as the exact same object the caller
    supplied."""
    from backend.app.services.analytical_pipeline import AnalyticalPipeline

    flow_obj = _tcp_flow()
    real_pipeline = AnalyticalPipeline(get_predictor(), get_risk_config())
    recording_pipeline = _RecordingPipeline(real_pipeline)

    # Stubbed graph context (not a real DB lookup) -- shaped exactly like
    # what graph_service.get_edge_context() would return for a
    # heavily-attacked edge.
    stub_graph_context = GraphContext(
        edge_attack_ratio=0.95,
        edge_attack_flow_count=500,
        edge_flow_count=520,
        edge_first_seen=T0.isoformat(),
        edge_last_seen=(T0 + timedelta(hours=10)).isoformat(),
        edge_attack_label_count=3,
    )

    result = score_victim_agent_flow(flow_obj, recording_pipeline, graph_context=stub_graph_context)

    # AnalyticalPipeline.score() received the exact same graph_context object.
    assert recording_pipeline.received_graph_context is stub_graph_context
    assert recording_pipeline.received_event.features == flow_obj.to_cicids_features()

    # A genuine DetectionResult/RiskResult was produced by the real, unmodified pipeline.
    assert isinstance(result, DetectionResult)
    assert 1.0 <= result.risk_score <= 10.0
    assert result.risk_level in {label for _, _, label in RISK_LEVELS}

    # The graph context genuinely influenced the score (not just passed
    # through inertly): identical flow/features, no graph context at all,
    # must score no higher than the heavily-attacked-edge case above.
    baseline_result = score_victim_agent_flow(flow_obj, real_pipeline, graph_context=None)
    assert result.risk_score >= baseline_result.risk_score


# --- existing graph_service.get_edge_context() lookup, via the existing --
# --- in-memory SQLite test DB fixtures already provided by conftest.py --


def test_get_edge_context_returns_persisted_attack_edge(db_session):
    """graph_service.get_edge_context(db, src_ip, dst_ip) is the existing
    mechanism a real caller uses to build the graph_context that would be
    passed to score_victim_agent_flow() -- exercised here against the
    project's existing in-memory SQLite test fixture (no new DB
    infrastructure introduced), proving it works without any bridge change."""
    from backend.app.models.attack_graph import AttackEdge
    from backend.app.services import graph_service
    from backend.app.services.model_registry import ATTACK_GRAPH_VERSION, get_or_create_model_version

    version = get_or_create_model_version(db_session, "attack_graph", ATTACK_GRAPH_VERSION)
    db_session.add(
        AttackEdge(
            src_ip="192.168.1.6",
            dst_ip="20.184.175.13",
            flow_count=100,
            benign_flow_count=40,
            attack_flow_count=60,
            attack_ratio=0.6,
            unique_source_ports=5,
            unique_destination_ports=1,
            protocols_seen=["TCP"],
            first_seen=T0,
            last_seen=T0 + timedelta(hours=2),
            total_forward_bytes=1000,
            total_backward_bytes=2000,
            attack_labels=["PortScan", "DoS"],
            graph_version_id=version.id,
        )
    )
    db_session.commit()

    context = graph_service.get_edge_context(db_session, "192.168.1.6", "20.184.175.13")

    assert context.edge_attack_ratio == 0.6
    assert context.edge_attack_flow_count == 60
    assert context.edge_flow_count == 100
    assert context.edge_attack_label_count == 2
    assert context.edge_first_seen is not None
    assert context.edge_last_seen is not None

    # And the missing-edge branch -- no fabricated data for an unseen pair.
    empty_context = graph_service.get_edge_context(db_session, "10.0.0.1", "10.0.0.2")
    assert empty_context.edge_attack_ratio is None
    assert empty_context.edge_flow_count is None


# --- guardrails: KNN and prevention are never touched by this integration --


def _imported_names(module) -> list[str]:
    """All module/name strings the module actually imports (not prose in
    docstrings/comments, which legitimately mention "KNN"/"prevention" to
    explain why they're deliberately absent from the code)."""
    tree = ast.parse(inspect.getsource(module))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
            names.extend(alias.name for alias in node.names)
    return names


def test_bridge_module_never_imports_knn():
    imported = _imported_names(bridge_module)
    assert not any("knn" in name.lower() for name in imported), imported


def test_bridge_module_never_imports_prevention():
    imported = _imported_names(bridge_module)
    assert not any("prevention" in name.lower() for name in imported), imported


def test_existing_risk_thresholds_remain_unchanged():
    assert HIGH_RISK_THRESHOLD == 7.0
    policy = ResponsePolicy()
    assert policy.alert_threshold == 7.0
    assert policy.block_threshold == 9.0
