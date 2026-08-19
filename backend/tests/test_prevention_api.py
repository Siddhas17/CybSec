"""Section 13 scenarios 7-13 (plus 1-3, 9-10 revisited at the API/service
level): prevention disabled, dry-run mode, audit record creation, auth
enforcement, adapter failure handling, duplicate block handling, unblock
behavior. Never uses real firewall modification -- a FakeAdapter stands in
for LabDryRunAdapter wherever a "real" block/unblock outcome is needed."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.detection import Detection
from backend.app.models.event import Event, EventSource
from backend.app.models.model_version import ModelVersion
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.services.prevention import response_service
from backend.app.services.prevention.adapters.base import AdapterResult, ResponseAdapter
from backend.app.services.prevention.response_service import DryRunModeError, PreventionDisabledError


class FakeAdapter(ResponseAdapter):
    """A safe stand-in for a real firewall backend -- section 13's "do not
    use real firewall modification during unit tests". Tracks calls so
    tests can assert dry-run mode never reaches block()/unblock()."""

    name = "fake_test_adapter"

    def __init__(self, block_succeeds: bool = True) -> None:
        self.block_succeeds = block_succeeds
        self.dry_run_calls: list[str] = []
        self.block_calls: list[str] = []
        self.unblock_calls: list[str] = []
        self._blocked: set[str] = set()

    def dry_run(self, target_ip: str, reason: str) -> AdapterResult:
        self.dry_run_calls.append(target_ip)
        return AdapterResult(success=True, actual_action="would_block", message=f"would block {target_ip}")

    def block(self, target_ip: str, reason: str) -> AdapterResult:
        self.block_calls.append(target_ip)
        if not self.block_succeeds:
            return AdapterResult(success=False, actual_action="failed", message="simulated adapter failure")
        if target_ip in self._blocked:
            return AdapterResult(success=True, actual_action="blocked", message=f"{target_ip} already blocked (no-op)")
        self._blocked.add(target_ip)
        return AdapterResult(success=True, actual_action="blocked", message=f"blocked {target_ip}")

    def unblock(self, target_ip: str) -> AdapterResult:
        self.unblock_calls.append(target_ip)
        if target_ip not in self._blocked:
            return AdapterResult(success=False, actual_action="failed", message=f"{target_ip} was not blocked")
        self._blocked.discard(target_ip)
        return AdapterResult(success=True, actual_action="unblocked", message=f"unblocked {target_ip}")


@pytest.fixture(autouse=True)
def prevention_defaults(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "prevention_enabled", True)
    monkeypatch.setattr(settings, "prevention_dry_run", True)
    monkeypatch.setattr(settings, "response_alert_threshold", 7.0)
    monkeypatch.setattr(settings, "response_block_threshold", 9.0)
    monkeypatch.setattr(settings, "lab_network_cidrs", "192.168.56.0/24")
    monkeypatch.setattr(settings, "lab_allow_loopback_target", False)


def _make_scored_event(db: Session, *, risk_score: float, source_ip: str = "192.168.56.10") -> tuple[Event, Detection, RiskAssessment]:
    """Builds a real, committed Event + Detection + RiskAssessment with a
    controlled risk_score -- the response layer only reads the already-
    scored result, so it does not need to re-run the real autoencoder/risk
    engine (those have their own dedicated tests elsewhere)."""
    version = ModelVersion(component="test", version="test-1")
    db.add(version)
    db.flush()

    event = Event(
        event_uid=f"test-live-{risk_score}-{source_ip}",
        timestamp=datetime.now(UTC),
        source_ip=source_ip,
        destination_ip="10.0.0.5",
        source=EventSource.LIVE,
        status="processed",
    )
    db.add(event)
    db.flush()

    detection = Detection(event_id=event.id, anomaly_score=0.5, reconstruction_error=0.5, is_anomaly=risk_score >= 7.0, threshold_used=0.1, model_version_id=version.id)
    db.add(detection)
    db.flush()

    risk = RiskAssessment(
        event_id=event.id,
        detection_id=detection.id,
        risk_score=risk_score,
        risk_level="Critical" if risk_score >= 8 else "High" if risk_score >= 6 else "Low",
        factors=[],
        rules_applied=[],
        reason="test fixture",
        risk_config_version_id=version.id,
    )
    db.add(risk)
    db.commit()
    db.refresh(event)
    db.refresh(detection)
    db.refresh(risk)
    return event, detection, risk


# -- 1-3: policy tiers through the real orchestration function --------------


def test_risk_below_threshold_creates_no_prevention_action(db_session: Session) -> None:
    event, detection, risk = _make_scored_event(db_session, risk_score=3.0)
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=FakeAdapter())
    assert result is None
    assert db_session.query(PreventionAction).filter(PreventionAction.event_id == event.id).count() == 0


def test_high_risk_creates_an_alert(db_session: Session) -> None:
    event, detection, risk = _make_scored_event(db_session, risk_score=7.5)
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=FakeAdapter())
    assert result is not None
    assert result.actual_action == "alerted"
    assert result.requested_action == "alert"
    assert result.success is True


def test_critical_risk_in_dry_run_mode_records_would_block(db_session: Session) -> None:
    adapter = FakeAdapter()
    event, detection, risk = _make_scored_event(db_session, risk_score=9.5)
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=adapter)
    assert result is not None
    assert result.actual_action == "would_block"
    assert result.dry_run is True
    assert adapter.block_calls == []  # scenario 8: dry-run mode never reaches block()


# -- 7: prevention disabled --------------------------------------------------


def test_prevention_disabled_takes_no_action(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "prevention_enabled", False)
    event, detection, risk = _make_scored_event(db_session, risk_score=9.9)
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=FakeAdapter())
    assert result is None
    assert db_session.query(PreventionAction).count() == 0


def test_manual_actions_raise_when_prevention_disabled(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.app.models.user import User

    monkeypatch.setattr(settings, "prevention_enabled", False)
    user = db_session.query(User).first() or User(username="x", hashed_password="x")
    with pytest.raises(PreventionDisabledError):
        response_service.manual_dry_run(db_session, source_ip="192.168.56.10", reason="test", user=user, adapter=FakeAdapter())
    with pytest.raises(PreventionDisabledError):
        response_service.manual_block(db_session, source_ip="192.168.56.10", reason="test", user=user, adapter=FakeAdapter())


# -- 4-6: validated identifier handling, revisited through evaluate_and_respond


def test_invalid_ip_rejected_and_audited(db_session: Session) -> None:
    event, detection, risk = _make_scored_event(db_session, risk_score=9.5, source_ip="not-an-ip")
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=FakeAdapter())
    assert result.actual_action == "rejected"
    assert result.success is False


def test_outside_lab_ip_rejected_and_audited(db_session: Session) -> None:
    event, detection, risk = _make_scored_event(db_session, risk_score=9.5, source_ip="8.8.8.8")
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=FakeAdapter())
    assert result.actual_action == "rejected"
    assert "outside the configured lab network scope" in result.reason


def test_localhost_rejected_by_default_and_audited(db_session: Session) -> None:
    event, detection, risk = _make_scored_event(db_session, risk_score=9.5, source_ip="127.0.0.1")
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=FakeAdapter())
    assert result.actual_action == "rejected"
    assert "loopback" in result.reason


# -- 9: audit record creation -----------------------------------------------


def test_audit_record_has_all_required_fields(db_session: Session) -> None:
    event, detection, risk = _make_scored_event(db_session, risk_score=9.5)
    result = response_service.evaluate_and_respond(db_session, event=event, detection=detection, risk_assessment=risk, adapter=FakeAdapter())
    row = db_session.get(PreventionAction, result.id)
    assert row.event_id == event.id
    assert row.source_ip == event.source_ip
    assert row.risk_score == 9.5
    assert row.risk_level == risk.risk_level
    assert row.requested_action == "block"
    assert row.actual_action == "would_block"
    assert row.dry_run is True
    assert row.success is True
    assert row.reason
    assert row.adapter == "fake_test_adapter"
    assert row.target_scope == "192.168.56.0/24"
    assert row.created_at is not None


# -- 10: authentication enforcement -----------------------------------------


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("post", "/api/v1/prevention/dry-run", {"source_ip": "192.168.56.10"}),
        ("post", "/api/v1/prevention/block", {"source_ip": "192.168.56.10"}),
        ("post", "/api/v1/prevention/unblock", {"source_ip": "192.168.56.10"}),
        ("get", "/api/v1/prevention/actions", None),
    ],
)
def test_prevention_endpoints_require_auth(client, method: str, path: str, body) -> None:
    call = getattr(client, method)
    response = call(path, json=body) if body is not None else call(path)
    assert response.status_code == 401


# -- API-level: dry-run mode refuses POST /prevention/block -----------------


def test_block_endpoint_refuses_while_dry_run_enabled(client, auth_headers) -> None:
    response = client.post("/api/v1/prevention/block", json={"source_ip": "192.168.56.10"}, headers=auth_headers)
    assert response.status_code == 400
    assert "DRY_RUN" in response.json()["detail"]


def test_dry_run_endpoint_works_end_to_end(client, auth_headers) -> None:
    response = client.post("/api/v1/prevention/dry-run", json={"source_ip": "192.168.56.10", "reason": "manual check"}, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["actual_action"] == "would_block"
    assert body["dry_run"] is True
    assert body["success"] is True


def test_list_actions_endpoint_returns_recorded_actions(client, auth_headers) -> None:
    client.post("/api/v1/prevention/dry-run", json={"source_ip": "192.168.56.11", "reason": "x"}, headers=auth_headers)
    response = client.get("/api/v1/prevention/actions", headers=auth_headers)
    assert response.status_code == 200
    assert any(a["source_ip"] == "192.168.56.11" for a in response.json())


# -- 11: adapter failure handling --------------------------------------------


def test_adapter_failure_is_recorded_not_raised(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.app.models.user import User

    monkeypatch.setattr(settings, "prevention_dry_run", False)
    failing_adapter = FakeAdapter(block_succeeds=False)
    user = db_session.query(User).first() or User(username="x", hashed_password="x")
    db_session.add(user)
    db_session.flush()

    result = response_service.manual_block(db_session, source_ip="192.168.56.12", reason="test", user=user, adapter=failing_adapter)
    assert result.success is False
    assert result.actual_action == "failed"
    assert "simulated adapter failure" in result.reason


# -- 12: duplicate block handling --------------------------------------------


def test_duplicate_block_does_not_error_and_is_recorded_twice(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.app.models.user import User

    monkeypatch.setattr(settings, "prevention_dry_run", False)
    adapter = FakeAdapter(block_succeeds=True)
    user = db_session.query(User).first() or User(username="x", hashed_password="x")
    db_session.add(user)
    db_session.flush()

    first = response_service.manual_block(db_session, source_ip="192.168.56.13", reason="first", user=user, adapter=adapter)
    second = response_service.manual_block(db_session, source_ip="192.168.56.13", reason="second", user=user, adapter=adapter)

    assert first.success is True
    assert second.success is True
    assert "already blocked" in second.reason
    assert first.id != second.id  # both audited, never overwritten (section 10)


# -- 13: unblock behavior -----------------------------------------------------


def test_unblock_reverses_a_real_block(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.app.models.user import User

    monkeypatch.setattr(settings, "prevention_dry_run", False)
    adapter = FakeAdapter(block_succeeds=True)
    user = db_session.query(User).first() or User(username="x", hashed_password="x")
    db_session.add(user)
    db_session.flush()

    response_service.manual_block(db_session, source_ip="192.168.56.14", reason="block", user=user, adapter=adapter)
    result = response_service.manual_unblock(db_session, source_ip="192.168.56.14", user=user, adapter=adapter)

    assert result.actual_action == "unblocked"
    assert result.success is True


def test_unblock_with_nothing_blocked_reports_failure_honestly(db_session: Session) -> None:
    from backend.app.models.user import User

    adapter = FakeAdapter()
    user = db_session.query(User).first() or User(username="x", hashed_password="x")
    db_session.add(user)
    db_session.flush()

    result = response_service.manual_unblock(db_session, source_ip="192.168.56.15", user=user, adapter=adapter)
    assert result.success is False
    assert result.actual_action == "failed"
