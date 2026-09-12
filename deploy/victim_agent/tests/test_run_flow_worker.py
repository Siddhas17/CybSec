"""Tests for deploy/victim_agent/run_flow_worker.py -- the one-shot manual
CLI entry point for FlowScoringWorker.

Never performs real capture, real HTTP, real registration, or real .env
file I/O: every victim_agent call run_flow_worker.py makes
(load_config/load_or_create_identity/ensure_registered/AgentSender/
FlowScoringWorker) is monkeypatched to a fake/spy here. This file also
never requires Npcap, a real network, or a running Admin server.
"""

from __future__ import annotations

import ast
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

# run_flow_worker.py lives one directory up from this tests/ folder (i.e.
# deploy/victim_agent/), exactly where it will sit once this whole
# deploy/victim_agent/ directory is copied to a Victim laptop and run as
# `python run_flow_worker.py` from that directory -- so prepending that
# same directory to sys.path here mirrors the real deployment layout,
# the same convention scripts/validate_victim_agent_flow_submission.py
# already uses for its own PROJECT_ROOT insertion.
DEPLOY_VICTIM_AGENT_DIR = Path(__file__).resolve().parents[1]
if str(DEPLOY_VICTIM_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(DEPLOY_VICTIM_AGENT_DIR))

import run_flow_worker  # noqa: E402
from victim_agent.config import AgentConfig  # noqa: E402
from victim_agent.flow import Flow  # noqa: E402
from victim_agent.flow_worker import FlowSubmissionOutcome, FlowWorkerRunResult  # noqa: E402
from victim_agent.identity import AgentIdentity  # noqa: E402

RUN_FLOW_WORKER_PATH = DEPLOY_VICTIM_AGENT_DIR / "run_flow_worker.py"

T0 = datetime(2026, 9, 12, 12, 0, 0, tzinfo=UTC)


def _make_config(**overrides) -> AgentConfig:
    defaults: dict = dict(
        admin_base_url="http://admin.invalid:8000",
        agent_enrollment_key="super-secret-enrollment-key",
        agent_id=None,
        heartbeat_interval_seconds=15,
        telemetry_interval_seconds=5,
        request_timeout_seconds=5,
        max_queue_size=10,
        identity_file_path=Path("unused-identity.json"),
        log_level="INFO",
    )
    defaults.update(overrides)
    return AgentConfig(**defaults)


def _make_flow(source_ip="10.0.0.5", source_port=1234, destination_ip="8.8.8.8", destination_port=53, protocol="TCP") -> Flow:
    return Flow(
        source_ip=source_ip, destination_ip=destination_ip, source_port=source_port, destination_port=destination_port,
        protocol=protocol, start_timestamp=T0, end_timestamp=T0,
    )


def _make_outcome(submitted: bool, response: dict | None = None, error: str | None = None, flow: Flow | None = None) -> FlowSubmissionOutcome:
    return FlowSubmissionOutcome(flow=flow or _make_flow(), submitted=submitted, payload=None, response=response, error=error)


class _FakeSender:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _install_fake_worker(monkeypatch: pytest.MonkeyPatch, result: FlowWorkerRunResult) -> dict:
    """Patches run_flow_worker.FlowScoringWorker with a fake that records
    its constructor args and how many times run_once() was called,
    returning the given canned result every time."""
    calls = {"constructed_with": [], "run_once_count": 0}

    class _FakeWorker:
        def __init__(self, sender, agent_id, token, **kwargs):
            calls["constructed_with"].append({"sender": sender, "agent_id": agent_id, "token": token, "kwargs": kwargs})

        def run_once(self) -> FlowWorkerRunResult:
            calls["run_once_count"] += 1
            return result

    monkeypatch.setattr(run_flow_worker, "FlowScoringWorker", _FakeWorker)
    return calls


def _install_happy_path(monkeypatch: pytest.MonkeyPatch, *, token: str = "super-secret-token-value", agent_id: str = "victim-01", enrollment_key: str = "super-secret-enrollment-key"):
    config = _make_config(agent_enrollment_key=enrollment_key)
    monkeypatch.setattr(run_flow_worker, "load_config", lambda: config)

    identity = AgentIdentity(agent_id=agent_id, token=token)
    monkeypatch.setattr(run_flow_worker, "load_or_create_identity", lambda cfg: identity)

    registered_calls = []
    monkeypatch.setattr(run_flow_worker, "ensure_registered", lambda cfg, ident, sender: registered_calls.append((cfg, ident, sender)))

    fake_sender = _FakeSender()
    monkeypatch.setattr(run_flow_worker, "AgentSender", lambda cfg: fake_sender)

    return config, identity, fake_sender, registered_calls


_EMPTY_RESULT = FlowWorkerRunResult(packets_captured=0, flows_reconstructed=0, flows_considered=0, flows_submitted=0, flows_failed=0, outcomes=[])


# --- worker invoked exactly once ---------------------------------------------


def test_main_invokes_worker_run_once_exactly_once(monkeypatch):
    _install_happy_path(monkeypatch)
    calls = _install_fake_worker(monkeypatch, _EMPTY_RESULT)

    exit_code = run_flow_worker.main()

    assert exit_code == 0
    assert calls["run_once_count"] == 1
    assert len(calls["constructed_with"]) == 1


def test_worker_is_constructed_with_agent_identity_and_sender(monkeypatch):
    config, identity, fake_sender, _ = _install_happy_path(monkeypatch, agent_id="victim-42", token="tok-42")
    calls = _install_fake_worker(monkeypatch, _EMPTY_RESULT)

    run_flow_worker.main()

    constructed = calls["constructed_with"][0]
    assert constructed["agent_id"] == "victim-42"
    assert constructed["token"] == "tok-42"
    assert constructed["sender"] is fake_sender


# --- ADMIN_BASE_URL configuration is required --------------------------------


def test_main_requires_admin_base_url_configuration(monkeypatch, capsys):
    def _raise_missing_admin_url():
        raise RuntimeError("ADMIN_BASE_URL is not set -- configure victim_agent/.env (see .env.example).")

    monkeypatch.setattr(run_flow_worker, "load_config", _raise_missing_admin_url)

    exit_code = run_flow_worker.main()

    captured = capsys.readouterr()
    assert exit_code != 0
    assert "ADMIN_BASE_URL" in captured.out


def test_main_stops_before_constructing_sender_when_config_fails(monkeypatch):
    sender_constructed = []
    monkeypatch.setattr(run_flow_worker, "load_config", lambda: (_ for _ in ()).throw(RuntimeError("ADMIN_BASE_URL is not set")))
    monkeypatch.setattr(run_flow_worker, "AgentSender", lambda cfg: sender_constructed.append(cfg))

    run_flow_worker.main()

    assert sender_constructed == []


# --- credentials are never printed -------------------------------------------


def test_main_never_prints_credentials(monkeypatch, capsys):
    config, identity, _fake_sender, _ = _install_happy_path(monkeypatch, token="super-secret-token-value", enrollment_key="super-secret-enrollment-key")
    result = FlowWorkerRunResult(
        packets_captured=1, flows_reconstructed=1, flows_considered=1, flows_submitted=1, flows_failed=0,
        outcomes=[_make_outcome(submitted=True, response={"risk_score": 4.2, "risk_level": "Medium", "is_anomaly": False})],
    )
    _install_fake_worker(monkeypatch, result)

    run_flow_worker.main()

    captured = capsys.readouterr()
    assert "super-secret-token-value" not in captured.out
    assert "super-secret-enrollment-key" not in captured.out
    assert config.agent_enrollment_key not in captured.out


def test_main_never_prints_credentials_on_registration_failure(monkeypatch, capsys):
    config, identity, fake_sender, _ = _install_happy_path(monkeypatch, token="super-secret-token-value", enrollment_key="super-secret-enrollment-key")
    monkeypatch.setattr(run_flow_worker, "ensure_registered", lambda cfg, ident, sender: (_ for _ in ()).throw(SystemExit(1)))

    run_flow_worker.main()

    captured = capsys.readouterr()
    assert "super-secret-token-value" not in captured.out
    assert "super-secret-enrollment-key" not in captured.out


# --- bounded worker result is displayed --------------------------------------


def test_main_prints_bounded_result_summary(monkeypatch, capsys):
    _install_happy_path(monkeypatch)
    outcome = _make_outcome(submitted=True, response={"risk_score": 7.5, "risk_level": "High", "is_anomaly": True})
    result = FlowWorkerRunResult(packets_captured=12, flows_reconstructed=3, flows_considered=3, flows_submitted=1, flows_failed=2, outcomes=[outcome])
    _install_fake_worker(monkeypatch, result)

    exit_code = run_flow_worker.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "packets captured:    12" in captured.out
    assert "flows reconstructed: 3" in captured.out
    assert "flows considered:    3" in captured.out
    assert "flows submitted:     1" in captured.out
    assert "flows failed:        2" in captured.out
    assert "risk_score=7.5" in captured.out
    assert "risk_level=High" in captured.out
    assert "anomaly=True" in captured.out


def test_main_reports_empty_result_cleanly(monkeypatch, capsys):
    _install_happy_path(monkeypatch)
    _install_fake_worker(monkeypatch, _EMPTY_RESULT)

    exit_code = run_flow_worker.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "packets captured:    0" in captured.out
    assert "no flows to report" in captured.out


# --- non-zero/failed results are handled cleanly -----------------------------


def test_main_handles_flow_failures_without_crashing(monkeypatch, capsys):
    _install_happy_path(monkeypatch)
    failed_outcome = _make_outcome(submitted=False, error="simulated network failure")
    result = FlowWorkerRunResult(packets_captured=5, flows_reconstructed=1, flows_considered=1, flows_submitted=0, flows_failed=1, outcomes=[failed_outcome])
    _install_fake_worker(monkeypatch, result)

    exit_code = run_flow_worker.main()

    captured = capsys.readouterr()
    # The run itself completed successfully -- a per-flow submission
    # failure is reported in the summary, not raised as a script crash.
    assert exit_code == 0
    assert "FAILED" in captured.out
    assert "simulated network failure" in captured.out


def test_main_handles_registration_failure_cleanly(monkeypatch, capsys):
    config, identity, fake_sender, _ = _install_happy_path(monkeypatch)
    monkeypatch.setattr(run_flow_worker, "ensure_registered", lambda cfg, ident, sender: (_ for _ in ()).throw(SystemExit(1)))

    exit_code = run_flow_worker.main()

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "STOP" in captured.out
    assert fake_sender.closed is True  # sender.close() still runs via finally


def test_main_handles_missing_token_after_registration_cleanly(monkeypatch, capsys):
    config, identity, fake_sender, _ = _install_happy_path(monkeypatch, token=None)

    exit_code = run_flow_worker.main()

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "STOP" in captured.out
    assert fake_sender.closed is True


# --- static checks: no concurrency, no backend/ML/DB dependency -------------


def _imported_names(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
            names.extend(alias.name for alias in node.names)
    return names


def test_run_flow_worker_has_no_concurrency_or_scheduling_imports():
    forbidden = ("threading", "asyncio", "concurrent", "sched")
    imported = _imported_names(RUN_FLOW_WORKER_PATH)
    offending = [n for n in imported if any(n == p or n.startswith(p + ".") for p in forbidden)]
    assert offending == []


def test_run_flow_worker_has_no_backend_ml_or_db_imports():
    forbidden = ("backend", "risk_engine", "ml", "attack_graph", "sqlalchemy", "torch", "numpy", "pandas", "sklearn", "fastapi", "pydantic", "pymysql", "mysql", "uvicorn")
    imported = _imported_names(RUN_FLOW_WORKER_PATH)
    offending = [n for n in imported if any(n == p or n.startswith(p + ".") for p in forbidden)]
    assert offending == []


def test_run_flow_worker_contains_no_infinite_loop_or_sleep():
    tree = ast.parse(RUN_FLOW_WORKER_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.While):
            if isinstance(node.test, ast.Constant) and node.test.value:
                pytest.fail("run_flow_worker.py must not contain a `while True`-style infinite loop")
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else None)
            assert name != "sleep"


def test_run_flow_worker_does_not_override_the_bounded_defaults():
    """The script must not pass its own capture_duration_seconds/
    max_flows_per_run -- it should rely on FlowScoringWorker's own
    MAX_CAPTURE_DURATION_SECONDS/DEFAULT_MAX_FLOWS_PER_RUN bounds rather
    than hardcoding a second copy of those numbers."""
    source = RUN_FLOW_WORKER_PATH.read_text(encoding="utf-8")
    assert "capture_duration_seconds" not in source
    assert "max_flows_per_run" not in source
