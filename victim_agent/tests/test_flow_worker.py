"""Tests for FlowScoringWorker -- orchestration and boundary behavior only.

Never performs real packet capture or real HTTP: capture_fn is always a
fake/spy injected via the constructor, and the sender is a fake that never
opens a socket. The real capture path (Npcap/Scapy) has already been
proven live by scripts/validate_victim_agent_flow_submission.py; that
script -- not pytest -- is the place for a real capture run.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime, timedelta

import pytest

from victim_agent import flow as victim_flow
from victim_agent import flow_worker
from victim_agent.flow_worker import (
    DEFAULT_MAX_FLOWS_PER_RUN,
    MAX_CAPTURE_DURATION_SECONDS,
    FlowScoringWorker,
)
from victim_agent.sender import SenderError

T0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)


def _tcp_pkt(source_ip, source_port, destination_ip, destination_port, length, timestamp, flags, window):
    return {
        "timestamp": timestamp, "source_ip": source_ip, "destination_ip": destination_ip,
        "source_port": source_port, "destination_port": destination_port, "protocol": "TCP", "length": length,
        "tcp_flags": flags, "tcp_window": window, "transport_header_length": 20, "tcp_payload_length": max(length - 40, 0),
    }


def _flow_packets(source_ip, source_port, destination_ip, destination_port, base_ts):
    """Three real packets (SYN, SYN-ACK, PSH-ACK) that reconstruct_flows()
    groups into exactly one bidirectional Flow -- the same shape
    test_sender.py's _flow_score_payload() uses, so the resulting features
    are genuine Flow.to_cicids_features() output, never a hand-typed
    stand-in dict."""
    return [
        _tcp_pkt(source_ip, source_port, destination_ip, destination_port, 100, base_ts, "S", 64240),
        _tcp_pkt(destination_ip, destination_port, source_ip, source_port, 100, base_ts + timedelta(seconds=1), "SA", 65535),
        _tcp_pkt(source_ip, source_port, destination_ip, destination_port, 300, base_ts + timedelta(seconds=2), "PA", 64240),
    ]


class _FakeSender:
    """Fake AgentSender -- records every score_flow() call and returns a
    canned response, or raises SenderError for calls matching fail_on.
    Never opens a real HTTP connection."""

    def __init__(self, fail_on=None):
        self.calls: list[dict] = []
        self._fail_on = fail_on or set()

    def score_flow(self, payload: dict, agent_id: str, token: str) -> dict:
        self.calls.append({"payload": payload, "agent_id": agent_id, "token": token})
        key = (payload["source_ip"], payload["destination_ip"])
        if key in self._fail_on:
            raise SenderError(f"simulated failure for {key}")
        return {"risk_score": 1.0, "risk_level": "Low", "is_anomaly": False}


@pytest.fixture()
def fake_sender():
    return _FakeSender()


def _capture_fn_returning(packets, seen_kwargs=None):
    def _fake(duration_seconds, iface=None):
        if seen_kwargs is not None:
            seen_kwargs["duration_seconds"] = duration_seconds
            seen_kwargs["iface"] = iface
        return packets

    return _fake


# --- 1 + 2: bounded capture invoked with the configured duration ------------


def test_run_once_invokes_capture_with_configured_duration(fake_sender):
    seen: dict = {}
    worker = FlowScoringWorker(
        sender=fake_sender, agent_id="victim-01", token="tok",
        capture_duration_seconds=7, capture_fn=_capture_fn_returning([], seen),
    )
    worker.run_once()
    assert seen["duration_seconds"] == 7


def test_run_once_passes_configured_interface_through_unchanged(fake_sender):
    seen: dict = {}
    sentinel_iface = object()
    worker = FlowScoringWorker(
        sender=fake_sender, agent_id="victim-01", token="tok",
        interface=sentinel_iface, capture_fn=_capture_fn_returning([], seen),
    )
    worker.run_once()
    assert seen["iface"] is sentinel_iface


def test_default_interface_is_none_never_hardcoded(fake_sender):
    seen: dict = {}
    worker = FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_fn=_capture_fn_returning([], seen))
    worker.run_once()
    assert seen["iface"] is None


# --- 3: existing reconstruction path is used --------------------------------


def test_run_once_reconstructs_flows_via_existing_flow_module(fake_sender):
    packets = _flow_packets("192.168.1.6", 53386, "20.184.175.13", 443, T0)
    calls: list[list] = []
    real_reconstruct = victim_flow.reconstruct_flows

    def _spy_reconstruct(pkts):
        calls.append(list(pkts))
        return real_reconstruct(pkts)

    worker = FlowScoringWorker(
        sender=fake_sender, agent_id="victim-01", token="tok",
        capture_fn=_capture_fn_returning(packets), reconstruct_fn=_spy_reconstruct,
    )
    result = worker.run_once()

    assert calls == [packets]
    assert result.flows_reconstructed == 1


# --- 4, 5, 6: payload shape and real 67-feature output ----------------------


def test_run_once_builds_exact_payload_shape_with_real_features(fake_sender):
    packets = _flow_packets("192.168.1.6", 53386, "20.184.175.13", 443, T0)
    worker = FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_fn=_capture_fn_returning(packets))
    worker.run_once()

    assert len(fake_sender.calls) == 1
    payload = fake_sender.calls[0]["payload"]
    assert set(payload.keys()) == {"source_ip", "destination_ip", "source_port", "destination_port", "protocol", "timestamp", "features"}

    [expected_flow] = victim_flow.reconstruct_flows(packets)
    assert payload["source_ip"] == expected_flow.source_ip
    assert payload["destination_ip"] == expected_flow.destination_ip
    assert payload["source_port"] == expected_flow.source_port
    assert payload["destination_port"] == expected_flow.destination_port
    assert payload["protocol"] == expected_flow.protocol
    assert payload["timestamp"] == expected_flow.start_timestamp.isoformat()
    assert payload["features"] == expected_flow.to_cicids_features()
    assert list(payload["features"].keys()) == list(victim_flow.CICIDS_FEATURE_NAMES)
    assert len(payload["features"]) == 67


# --- 7: AgentSender.score_flow() receives the expected payload/credentials --


def test_run_once_calls_score_flow_with_agent_credentials(fake_sender):
    packets = _flow_packets("192.168.1.6", 53386, "20.184.175.13", 443, T0)
    worker = FlowScoringWorker(sender=fake_sender, agent_id="victim-77", token="secret-tok", capture_fn=_capture_fn_returning(packets))
    worker.run_once()

    call = fake_sender.calls[0]
    assert call["agent_id"] == "victim-77"
    assert call["token"] == "secret-tok"


# --- 8: maximum submitted-flow bound is enforced ----------------------------


def test_run_once_enforces_max_flows_per_run(fake_sender):
    packets = (
        _flow_packets("10.0.0.1", 1111, "8.8.8.8", 53, T0)
        + _flow_packets("10.0.0.2", 2222, "8.8.4.4", 53, T0 + timedelta(seconds=10))
        + _flow_packets("10.0.0.3", 3333, "1.1.1.1", 53, T0 + timedelta(seconds=20))
    )
    worker = FlowScoringWorker(
        sender=fake_sender, agent_id="victim-01", token="tok",
        capture_fn=_capture_fn_returning(packets), max_flows_per_run=2,
    )
    result = worker.run_once()

    assert result.flows_reconstructed == 3
    assert result.flows_considered == 2
    assert result.flows_submitted == 2
    assert len(fake_sender.calls) == 2


def test_default_max_flows_per_run_is_conservative():
    assert DEFAULT_MAX_FLOWS_PER_RUN == 10


def test_non_positive_max_flows_per_run_is_rejected(fake_sender):
    with pytest.raises(ValueError):
        FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", max_flows_per_run=0)


# --- 9: zero captured packets produces a safe empty result ------------------


def test_run_once_with_zero_packets_produces_safe_empty_result(fake_sender):
    worker = FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_fn=_capture_fn_returning([]))
    result = worker.run_once()

    assert result.packets_captured == 0
    assert result.flows_reconstructed == 0
    assert result.flows_considered == 0
    assert result.flows_submitted == 0
    assert result.flows_failed == 0
    assert result.outcomes == []
    assert fake_sender.calls == []


# --- 10: one flow's failure never hides the others --------------------------


def test_run_once_one_flow_failure_does_not_drop_other_flows(fake_sender):
    packets = (
        _flow_packets("10.0.0.1", 1111, "8.8.8.8", 53, T0)
        + _flow_packets("10.0.0.2", 2222, "8.8.4.4", 53, T0 + timedelta(seconds=10))
    )
    failing_sender = _FakeSender(fail_on={("10.0.0.1", "8.8.8.8")})
    worker = FlowScoringWorker(sender=failing_sender, agent_id="victim-01", token="tok", capture_fn=_capture_fn_returning(packets))
    result = worker.run_once()

    assert result.flows_reconstructed == 2
    assert result.flows_considered == 2
    assert result.flows_submitted == 1
    assert result.flows_failed == 1

    outcomes_by_dest = {outcome.flow.destination_ip: outcome for outcome in result.outcomes}
    assert outcomes_by_dest["8.8.8.8"].submitted is False
    assert outcomes_by_dest["8.8.8.8"].error is not None
    assert outcomes_by_dest["8.8.4.4"].submitted is True
    assert outcomes_by_dest["8.8.4.4"].response is not None


# --- 11: no raw packet payload bytes are ever submitted ---------------------


def test_run_once_submits_no_raw_packet_payload(fake_sender):
    packets = _flow_packets("192.168.1.6", 53386, "20.184.175.13", 443, T0)
    worker = FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_fn=_capture_fn_returning(packets))
    worker.run_once()

    payload = fake_sender.calls[0]["payload"]
    assert not any(key in payload for key in ("payload", "raw", "load", "packet_bytes"))


# --- 12: run_once() performs exactly one bounded capture, then returns ------


def test_run_once_performs_exactly_one_capture_call(fake_sender):
    call_count = {"n": 0}

    def _counting_capture(duration_seconds, iface=None):
        call_count["n"] += 1
        return []

    worker = FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_fn=_counting_capture)
    worker.run_once()
    assert call_count["n"] == 1


def test_run_once_is_synchronous_not_a_coroutine():
    assert not inspect.iscoroutinefunction(FlowScoringWorker.run_once)


# --- hard capture-duration bound enforcement --------------------------------


def test_capture_duration_exceeding_hard_bound_is_rejected(fake_sender):
    with pytest.raises(ValueError):
        FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_duration_seconds=MAX_CAPTURE_DURATION_SECONDS + 1)


def test_capture_duration_at_hard_bound_is_accepted(fake_sender):
    FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_duration_seconds=MAX_CAPTURE_DURATION_SECONDS)


def test_non_positive_capture_duration_is_rejected(fake_sender):
    with pytest.raises(ValueError):
        FlowScoringWorker(sender=fake_sender, agent_id="victim-01", token="tok", capture_duration_seconds=0)


# --- 13 + 14: no concurrency/scheduling, no backend/ML deps -----------------


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


def test_flow_worker_module_has_no_backend_ml_or_risk_engine_dependencies():
    forbidden = ("backend", "risk_engine", "sqlalchemy", "ml", "torch", "numpy", "pandas", "sklearn", "fastapi", "pydantic")
    imported = _imported_names(flow_worker)
    offending = [name for name in imported if any(name == p or name.startswith(p + ".") for p in forbidden)]
    assert offending == []


def test_flow_worker_module_has_no_concurrency_or_scheduling_dependencies():
    forbidden = ("threading", "asyncio", "concurrent", "sched", "time")
    imported = _imported_names(flow_worker)
    offending = [name for name in imported if any(name == p or name.startswith(p + ".") for p in forbidden)]
    assert offending == []


def test_flow_worker_module_contains_no_infinite_loop():
    tree = ast.parse(inspect.getsource(flow_worker))
    for node in ast.walk(tree):
        if isinstance(node, ast.While):
            if isinstance(node.test, ast.Constant) and node.test.value:
                pytest.fail("flow_worker.py must not contain a `while True`-style infinite loop")


def test_flow_worker_module_never_calls_sleep():
    tree = ast.parse(inspect.getsource(flow_worker))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else None)
            assert name != "sleep"


# --- 15 is verified by running the full victim_agent/tests suite separately.
