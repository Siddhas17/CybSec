"""POST /api/v1/agents/flow-score -- the score-only victim-agent flow
integration endpoint. Uses the real AutoencoderPredictor/RiskEngineConfig
(same convention as the rest of backend/tests, see conftest.py's own
docstring) so results are genuine, not canned. No live capture, no real
network beyond the FastAPI TestClient itself."""

from __future__ import annotations

import ast
import inspect
import time
from datetime import UTC, datetime, timedelta

import pytest

from victim_agent import flow as victim_flow

from backend.app.api.v1 import flow_scoring as flow_scoring_route
from backend.app.core.config import settings
from backend.app.models.attack_graph import AttackEdge, AttackNode
from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.schemas import flow_scoring as flow_scoring_schema
from backend.app.services.analytical_pipeline import AnalyticalPipeline
from backend.app.services.model_registry import ATTACK_GRAPH_VERSION, get_or_create_model_version
from risk_engine.config import HIGH_RISK_THRESHOLD

ENROLLMENT_KEY = "test-enrollment-key-do-not-use-in-prod"
T0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)


@pytest.fixture()
def agent_headers(client, monkeypatch):
    monkeypatch.setattr(settings, "agent_enrollment_key", ENROLLMENT_KEY)
    reg = client.post(
        "/api/v1/agents/register",
        headers={"X-Enrollment-Key": ENROLLMENT_KEY},
        json={"agent_id": "victim-01", "hostname": "VICTIM-PC1"},
    ).json()
    return {"X-Agent-Id": "victim-01", "Authorization": f"Bearer {reg['agent_token']}"}


@pytest.fixture(autouse=True)
def _reset_victim_live_graph():
    """The victim-agent LiveGraph is a process-wide @lru_cache(maxsize=1)
    singleton (backend.app.api.v1.flow_scoring._get_victim_live_graph) --
    without this, edges recorded by one test would leak into the next."""
    flow_scoring_route._get_victim_live_graph.cache_clear()
    yield
    flow_scoring_route._get_victim_live_graph.cache_clear()


@pytest.fixture()
def capture_pipeline_score(monkeypatch):
    """Spies on AnalyticalPipeline.score() while still delegating to the
    real implementation, so a test can inspect exactly what TelemetryEvent/
    GraphContext the endpoint built while still getting a genuine result."""
    captured: dict = {}
    original_score = AnalyticalPipeline.score

    def _spy(self, event, graph_context=None):
        captured["event"] = event
        captured["graph_context"] = graph_context
        return original_score(self, event, graph_context)

    monkeypatch.setattr(AnalyticalPipeline, "score", _spy)
    return captured


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


def _payload(f: victim_flow.Flow) -> dict:
    return {
        "source_ip": f.source_ip,
        "destination_ip": f.destination_ip,
        "source_port": f.source_port,
        "destination_port": f.destination_port,
        "protocol": f.protocol,
        "timestamp": f.start_timestamp.isoformat(),
        "features": f.to_cicids_features(),
    }


# --- authentication -----------------------------------------------------


def test_flow_score_requires_agent_auth(client):
    response = client.post("/api/v1/agents/flow-score", json=_payload(_tcp_flow()))
    assert response.status_code == 401


# --- happy path + protocol mapping through the real HTTP path ------------


def test_flow_score_valid_tcp_request_returns_detection_result(client, agent_headers):
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))

    assert response.status_code == 200, response.text
    body = response.json()
    assert 1.0 <= body["risk_score"] <= 10.0
    assert body["risk_level"] in {"Very Low", "Low", "Moderate", "High", "Critical"}
    assert isinstance(body["is_anomaly"], bool)
    assert body["imputed_features"] == []  # all 67 features were supplied


def test_flow_score_broadcasts_one_admin_only_transient_message(client, agent_headers, auth_headers):
    admin_token = auth_headers["Authorization"].removeprefix("Bearer ")
    flow_payload = _payload(_tcp_flow())

    with (
        client.websocket_connect(f"/ws/admin/victim-flow-scores?token={admin_token}") as admin_ws,
        client.websocket_connect("/ws/events") as global_ws,
    ):
        global_ws.receive_json()  # existing global connection handshake
        response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=flow_payload)

        assert response.status_code == 200, response.text
        message = admin_ws.receive_json()
        assert message["type"] == "victim_flow_score"
        assert message["data"] == {
            "agent_id": "victim-01",
            "source_ip": flow_payload["source_ip"],
            "destination_ip": flow_payload["destination_ip"],
            "protocol": flow_payload["protocol"],
            "timestamp": flow_payload["timestamp"],
            "risk_score": response.json()["risk_score"],
            "risk_level": response.json()["risk_level"],
            "is_anomaly": response.json()["is_anomaly"],
            "graph_context_used": response.json()["graph_context_used"],
        }

        # An extra event would arrive before the pong.
        global_ws.send_text("ping")
        assert global_ws.receive_text() == "pong"
        admin_ws.send_text("ping")
        assert admin_ws.receive_text() == "pong"


def test_flow_score_tcp_protocol_maps_to_iana_6(client, agent_headers, capture_pipeline_score):
    client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
    assert capture_pipeline_score["event"].protocol == 6


def test_flow_score_udp_protocol_maps_to_iana_17(client, agent_headers, capture_pipeline_score):
    client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_udp_flow()))
    assert capture_pipeline_score["event"].protocol == 17


def test_flow_score_icmp_protocol_maps_to_iana_1(client, agent_headers, capture_pipeline_score):
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_icmp_flow()))
    assert response.status_code == 200, response.text
    assert capture_pipeline_score["event"].protocol == 1
    assert capture_pipeline_score["event"].source_port is None
    assert capture_pipeline_score["event"].destination_port is None


def test_flow_score_preserves_exact_67_features(client, agent_headers, capture_pipeline_score):
    f = _tcp_flow()
    client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(f))
    assert capture_pipeline_score["event"].features == f.to_cicids_features()


# --- validation -----------------------------------------------------------


def test_flow_score_rejects_missing_feature(client, agent_headers):
    payload = _payload(_tcp_flow())
    del payload["features"]["Destination Port"]

    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=payload)

    assert response.status_code == 422
    assert "Destination Port" in response.text


def test_flow_score_rejects_unexpected_extra_feature(client, agent_headers):
    payload = _payload(_tcp_flow())
    payload["features"]["Not A Real Feature"] = 1.0

    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=payload)

    assert response.status_code == 422
    assert "Not A Real Feature" in response.text


def test_flow_score_rejects_non_numeric_feature_value(client, agent_headers):
    payload = _payload(_tcp_flow())
    payload["features"]["Flow Duration"] = "not-a-number"

    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=payload)

    assert response.status_code == 422


# --- graph context ----------------------------------------------------------


def test_flow_score_passes_real_graph_context_to_pipeline(client, agent_headers, capture_pipeline_score, db_session):
    version = get_or_create_model_version(db_session, "attack_graph", ATTACK_GRAPH_VERSION)
    db_session.add(
        AttackEdge(
            src_ip="192.168.1.6", dst_ip="20.184.175.13",
            flow_count=100, benign_flow_count=40, attack_flow_count=60, attack_ratio=0.6,
            unique_source_ports=5, unique_destination_ports=1, protocols_seen=["TCP"],
            first_seen=T0, last_seen=T0 + timedelta(hours=2),
            total_forward_bytes=1000, total_backward_bytes=2000,
            attack_labels=["PortScan", "DoS"], graph_version_id=version.id,
        )
    )
    db_session.commit()

    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))

    assert response.status_code == 200, response.text
    received_context = capture_pipeline_score["graph_context"]
    assert received_context is not None
    assert received_context.edge_attack_ratio == 0.6
    assert received_context.edge_attack_flow_count == 60
    assert response.json()["graph_context_used"] is True


def test_flow_score_graph_context_used_false_for_unseen_edge(client, agent_headers):
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_icmp_flow()))
    assert response.status_code == 200, response.text
    assert response.json()["graph_context_used"] is False


# --- LiveGraph integration ---------------------------------------------------


def _seed_live_graph(count, src_ip="192.168.1.6", dst_ip="20.184.175.13", start_ts=None):
    """Directly pre-populates the real victim-agent LiveGraph singleton
    with `count` all-benign prior flows on (src_ip, dst_ip) -- exercises
    the real record_flow()/get_context() implementation, not a fake."""
    live_graph = flow_scoring_route._get_victim_live_graph()
    if start_ts is None:
        start_ts = time.time()
    for i in range(count):
        live_graph.record_flow(src_ip, dst_ip, 40000 + i, 443, 6, start_ts + i, is_flagged=False)
    return live_graph


def test_flow_score_live_graph_with_zero_prior_flows_is_neutral(client, agent_headers, capture_pipeline_score):
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
    assert response.status_code == 200, response.text
    assert capture_pipeline_score["graph_context"].is_empty()
    assert response.json()["graph_context_used"] is False


def test_flow_score_expired_live_graph_edge_does_not_provide_context(client, agent_headers, capture_pipeline_score):
    window_seconds = flow_scoring_route.sensor_config.live_graph_window_seconds
    _seed_live_graph(
        flow_scoring_route.LIVE_GRAPH_MIN_FLOWS,
        start_ts=time.time() - window_seconds - 10,
    )

    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))

    assert response.status_code == 200, response.text
    assert capture_pipeline_score["graph_context"].is_empty()
    assert response.json()["graph_context_used"] is False


def test_flow_score_live_graph_with_one_prior_flow_is_neutral(client, agent_headers, capture_pipeline_score):
    _seed_live_graph(1)
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
    assert response.status_code == 200, response.text
    assert capture_pipeline_score["graph_context"].is_empty()
    assert response.json()["graph_context_used"] is False


def test_flow_score_live_graph_with_nine_prior_flows_is_neutral(client, agent_headers, capture_pipeline_score):
    _seed_live_graph(flow_scoring_route.LIVE_GRAPH_MIN_FLOWS - 1)
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
    assert response.status_code == 200, response.text
    assert capture_pipeline_score["graph_context"].is_empty()
    assert response.json()["graph_context_used"] is False


def test_flow_score_live_graph_with_ten_prior_flows_is_used(client, agent_headers, capture_pipeline_score):
    _seed_live_graph(flow_scoring_route.LIVE_GRAPH_MIN_FLOWS)
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
    assert response.status_code == 200, response.text
    received_context = capture_pipeline_score["graph_context"]
    assert not received_context.is_empty()
    assert received_context.edge_flow_count == flow_scoring_route.LIVE_GRAPH_MIN_FLOWS
    assert received_context.edge_attack_flow_count == 0
    assert received_context.edge_attack_ratio == 0.0
    assert received_context.edge_attack_label_count == 0  # live traffic never has ground-truth labels
    assert response.json()["graph_context_used"] is True


def test_flow_score_records_current_flow_into_live_graph_after_scoring(client, agent_headers):
    src_ip, dst_ip = "192.168.1.6", "20.184.175.13"
    live_graph = flow_scoring_route._get_victim_live_graph()
    assert live_graph.get_context(src_ip, dst_ip).is_empty()

    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
    assert response.status_code == 200, response.text

    context_after = live_graph.get_context(src_ip, dst_ip)
    assert not context_after.is_empty()
    assert context_after.edge_flow_count == 1
    # This synthetic TCP flow's reconstruction error is far above threshold
    # (is_anomaly=True, established in prior live validation), so it must
    # be recorded as flagged -- following is_anomaly or
    # risk_score >= HIGH_RISK_THRESHOLD, not a new/invented rule.
    assert response.json()["is_anomaly"] is True
    assert context_after.edge_attack_flow_count == 1


def test_flow_score_historical_graph_takes_precedence_over_live_graph(client, agent_headers, capture_pipeline_score, db_session):
    src_ip, dst_ip = "192.168.1.6", "20.184.175.13"
    version = get_or_create_model_version(db_session, "attack_graph", ATTACK_GRAPH_VERSION)
    db_session.add(
        AttackEdge(
            src_ip=src_ip, dst_ip=dst_ip,
            flow_count=100, benign_flow_count=40, attack_flow_count=60, attack_ratio=0.6,
            unique_source_ports=5, unique_destination_ports=1, protocols_seen=["TCP"],
            first_seen=T0, last_seen=T0 + timedelta(hours=2),
            total_forward_bytes=1000, total_backward_bytes=2000,
            attack_labels=["PortScan", "DoS"], graph_version_id=version.id,
        )
    )
    db_session.commit()
    _seed_live_graph(50, src_ip=src_ip, dst_ip=dst_ip)  # far past the 10-flow gate

    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))

    assert response.status_code == 200, response.text
    received_context = capture_pipeline_score["graph_context"]
    # The HISTORICAL edge's numbers win, unchanged from
    # test_flow_score_passes_real_graph_context_to_pipeline -- proves
    # precedence, not a blend with the live edge's 50 all-benign flows.
    assert received_context.edge_attack_ratio == 0.6
    assert received_context.edge_attack_flow_count == 60
    assert received_context.edge_flow_count == 100
    assert response.json()["graph_context_used"] is True


def test_flow_score_live_graph_introduces_no_database_writes(client, agent_headers, db_session):
    before = (
        db_session.query(Event).count(),
        db_session.query(Detection).count(),
        db_session.query(RiskAssessment).count(),
        db_session.query(AttackEdge).count(),
        db_session.query(AttackNode).count(),
    )

    _seed_live_graph(flow_scoring_route.LIVE_GRAPH_MIN_FLOWS - 1)
    for _ in range(3):  # crosses the 10-flow gate mid-sequence
        response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
        assert response.status_code == 200, response.text

    after = (
        db_session.query(Event).count(),
        db_session.query(Detection).count(),
        db_session.query(RiskAssessment).count(),
        db_session.query(AttackEdge).count(),
        db_session.query(AttackNode).count(),
    )
    assert before == after


# --- risk thresholds --------------------------------------------------------


def test_existing_risk_thresholds_unchanged():
    from backend.app.services.prevention.policy import ResponsePolicy

    assert HIGH_RISK_THRESHOLD == 7.0
    policy = ResponsePolicy()
    assert policy.alert_threshold == 7.0
    assert policy.block_threshold == 9.0


# --- persistence guardrail --------------------------------------------------


def test_flow_score_does_not_persist_any_records(client, agent_headers, db_session):
    before = (db_session.query(Event).count(), db_session.query(Detection).count(), db_session.query(RiskAssessment).count())
    response = client.post("/api/v1/agents/flow-score", headers=agent_headers, json=_payload(_tcp_flow()))
    assert response.status_code == 200, response.text
    after = (db_session.query(Event).count(), db_session.query(Detection).count(), db_session.query(RiskAssessment).count())
    assert before == after


# --- guardrails: KNN, prevention, logging -----------------------------------


def _imported_names(module) -> list[str]:
    tree = ast.parse(inspect.getsource(module))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
            names.extend(alias.name for alias in node.names)
    return names


@pytest.mark.parametrize("module", [flow_scoring_route, flow_scoring_schema])
def test_flow_score_modules_never_import_knn(module):
    imported = _imported_names(module)
    assert not any("knn" in name.lower() for name in imported), imported


@pytest.mark.parametrize("module", [flow_scoring_route, flow_scoring_schema])
def test_flow_score_modules_never_import_prevention(module):
    imported = _imported_names(module)
    assert not any("prevention" in name.lower() for name in imported), imported


def test_flow_score_route_never_imports_logging():
    # No `logging` import at all in the route module -- nothing there can
    # log the feature vector, headers, or credentials, intentionally or by
    # accident (checked via imports, not a raw text search, since the
    # module's own docstring legitimately contains the substring "logic").
    imported = _imported_names(flow_scoring_route)
    assert "logging" not in imported, imported
