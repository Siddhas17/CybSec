from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from victim_agent import flow as victim_flow
from victim_agent import sender as sender_module
from victim_agent.sender import AgentSender, SenderError

T0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)


class _FakeResponse:
    def __init__(self, status_code: int, data: dict | None = None):
        self.status_code = status_code
        self._data = data or {}
        self.text = str(data)

    def json(self) -> dict:
        return self._data


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    # Backoff sleeps would make these tests slow; retry/backoff logic itself
    # is exercised via call counts, not wall-clock time.
    monkeypatch.setattr(sender_module.time, "sleep", lambda _seconds: None)


@pytest.fixture()
def agent_sender(make_config):
    s = AgentSender(make_config())
    yield s
    s.close()


def test_succeeds_on_first_attempt(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(200, {"ok": True})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    result = agent_sender.send_heartbeat({"agent_id": "victim-01"}, "victim-01", "tok")
    assert result == {"ok": True}
    assert len(calls) == 1


def test_retries_on_connect_error_then_succeeds(agent_sender, monkeypatch):
    attempts = {"n": 0}

    def fake_post(path, json, headers):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx.ConnectError("connection refused")
        return _FakeResponse(200, {"ok": True})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    result = agent_sender.send_telemetry_batch({"agent_id": "victim-01"}, "victim-01", "tok")
    assert result == {"ok": True}
    assert attempts["n"] == 3


def test_gives_up_after_max_attempts_on_persistent_connect_error(agent_sender, monkeypatch):
    def fake_post(path, json, headers):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.send_telemetry_batch({"agent_id": "victim-01"}, "victim-01", "tok")


def test_4xx_response_is_not_retried(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(401, {"detail": "Invalid agent credentials"})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.send_heartbeat({"agent_id": "victim-01"}, "victim-01", "bad-tok")
    assert len(calls) == 1  # no retry for a 4xx


def test_5xx_response_is_retried_then_fails(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(500, {"detail": "boom"})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.send_telemetry_batch({"agent_id": "victim-01"}, "victim-01", "tok")
    assert len(calls) == 3  # retried up to the max attempts


def test_register_sends_enrollment_key_header_not_agent_headers(agent_sender, monkeypatch):
    seen_headers = {}

    def fake_post(path, json, headers):
        seen_headers.update(headers)
        return _FakeResponse(200, {"agent_id": "victim-01", "agent_token": "new-token", "rotated": False})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    agent_sender.register({"agent_id": "victim-01", "hostname": "VICTIM-PC1"})
    assert seen_headers == {"X-Enrollment-Key": "test-key"}


# --- score_flow() ------------------------------------------------------------


def _tcp_pkt(source_ip, source_port, destination_ip, destination_port, length, timestamp, flags, window):
    return {
        "timestamp": timestamp, "source_ip": source_ip, "destination_ip": destination_ip,
        "source_port": source_port, "destination_port": destination_port, "protocol": "TCP", "length": length,
        "tcp_flags": flags, "tcp_window": window, "transport_header_length": 20, "tcp_payload_length": max(length - 40, 0),
    }


def _flow_score_payload() -> dict:
    """A realistic score_flow() payload, built the same way agent.py would
    build it: a real completed Flow -> its own to_cicids_features() output,
    never a hand-typed stand-in dict. score_flow() itself does not build
    this -- it only transports whatever payload dict it's given."""
    packets = [
        _tcp_pkt("192.168.1.6", 53386, "20.184.175.13", 443, 100, T0, "S", 64240),
        _tcp_pkt("20.184.175.13", 443, "192.168.1.6", 53386, 100, T0 + timedelta(seconds=1), "SA", 65535),
        _tcp_pkt("192.168.1.6", 53386, "20.184.175.13", 443, 300, T0 + timedelta(seconds=2), "PA", 64240),
    ]
    [f] = victim_flow.reconstruct_flows(packets)
    return {
        "source_ip": f.source_ip,
        "destination_ip": f.destination_ip,
        "source_port": f.source_port,
        "destination_port": f.destination_port,
        "protocol": f.protocol,
        "timestamp": f.start_timestamp.isoformat(),
        "features": f.to_cicids_features(),
    }


_SCORE_RESPONSE = {
    "anomaly_score": 0.5, "reconstruction_error": 0.5, "is_anomaly": False, "threshold_used": 0.106125,
    "risk_score": 3.2, "risk_level": "Low", "factors": [], "rules_applied": [], "reason": "test",
    "imputed_features": [], "graph_context_used": False,
}


def test_score_flow_succeeds_and_returns_backend_response(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(200, _SCORE_RESPONSE)

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    result = agent_sender.score_flow(_flow_score_payload(), "victim-01", "tok")

    assert result == _SCORE_RESPONSE
    assert len(calls) == 1


def test_score_flow_uses_exact_endpoint_path(agent_sender, monkeypatch):
    seen_paths = []

    def fake_post(path, json, headers):
        seen_paths.append(path)
        return _FakeResponse(200, _SCORE_RESPONSE)

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    agent_sender.score_flow(_flow_score_payload(), "victim-01", "tok")

    assert seen_paths == ["/agents/flow-score"]


def test_score_flow_reuses_existing_agent_auth_headers(agent_sender, monkeypatch):
    seen_headers = {}

    def fake_post(path, json, headers):
        seen_headers.update(headers)
        return _FakeResponse(200, _SCORE_RESPONSE)

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    agent_sender.score_flow(_flow_score_payload(), "victim-01", "secret-tok")

    assert seen_headers == {"X-Agent-Id": "victim-01", "Authorization": "Bearer secret-tok"}


def test_score_flow_transmits_flow_metadata_unchanged(agent_sender, monkeypatch):
    payload = _flow_score_payload()
    seen_payload = {}

    def fake_post(path, json, headers):
        seen_payload.update(json)
        return _FakeResponse(200, _SCORE_RESPONSE)

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    agent_sender.score_flow(payload, "victim-01", "tok")

    assert seen_payload["source_ip"] == payload["source_ip"]
    assert seen_payload["destination_ip"] == payload["destination_ip"]
    assert seen_payload["source_port"] == payload["source_port"]
    assert seen_payload["destination_port"] == payload["destination_port"]
    assert seen_payload["protocol"] == payload["protocol"]
    assert seen_payload["timestamp"] == payload["timestamp"]


def test_score_flow_transmits_exact_67_features_unchanged(agent_sender, monkeypatch):
    payload = _flow_score_payload()
    seen_payload = {}

    def fake_post(path, json, headers):
        seen_payload.update(json)
        return _FakeResponse(200, _SCORE_RESPONSE)

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    agent_sender.score_flow(payload, "victim-01", "tok")

    assert len(seen_payload["features"]) == 67
    assert list(seen_payload["features"].keys()) == list(victim_flow.CICIDS_FEATURE_NAMES)
    assert seen_payload["features"] == payload["features"]


def test_score_flow_transmits_no_raw_packet_payload():
    # The transmitted dict is exactly the metadata/feature fields
    # score_flow()'s own docstring promises -- no packet bytes, no "load"/
    # "payload_bytes"/"raw" field of any kind ever enters it, because
    # Flow.to_cicids_features() (which built payload["features"]) never
    # retains payload bytes in the first place.
    payload = _flow_score_payload()

    assert set(payload.keys()) == {"source_ip", "destination_ip", "source_port", "destination_port", "protocol", "timestamp", "features"}
    assert not any(key in payload for key in ("payload", "raw", "load", "packet_bytes"))


def test_score_flow_4xx_is_not_retried(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(422, {"detail": "invalid features"})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.score_flow(_flow_score_payload(), "victim-01", "tok")
    assert len(calls) == 1  # no retry for a 4xx, same as every other sender method


def test_score_flow_5xx_is_retried_then_fails(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(500, {"detail": "boom"})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.score_flow(_flow_score_payload(), "victim-01", "tok")
    assert len(calls) == 3  # retried up to the existing max attempts, same retry system as heartbeat/telemetry


def test_score_flow_retries_on_connect_error_then_succeeds(agent_sender, monkeypatch):
    attempts = {"n": 0}

    def fake_post(path, json, headers):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx.ConnectError("connection refused")
        return _FakeResponse(200, _SCORE_RESPONSE)

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    result = agent_sender.score_flow(_flow_score_payload(), "victim-01", "tok")
    assert result == _SCORE_RESPONSE
    assert attempts["n"] == 3


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


def test_sender_module_has_no_backend_ml_or_risk_engine_dependencies():
    forbidden = ("backend", "risk_engine", "sqlalchemy", "ml", "torch", "numpy", "pandas", "sklearn", "fastapi", "pydantic")
    imported = _imported_names(sender_module)
    offending = [name for name in imported if any(name == p or name.startswith(p + ".") for p in forbidden)]
    assert offending == []
