"""Raw victim_agent telemetry ingestion (Phase 1). The most important test
here is `test_telemetry_never_touches_the_scored_event_tables` -- it's the
regression test proving the explicit constraint that this endpoint must
never call AnalyticalPipeline.score() or write events/detections/
risk_assessments rows (see agent_telemetry_event.py's docstring)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.app.core.config import settings
from backend.app.models.agent_telemetry_event import AgentTelemetryEvent
from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.models.risk_assessment import RiskAssessment

ENROLLMENT_KEY = "test-enrollment-key-do-not-use-in-prod"


@pytest.fixture()
def agent_headers(client, monkeypatch):
    monkeypatch.setattr(settings, "agent_enrollment_key", ENROLLMENT_KEY)
    reg = client.post(
        "/api/v1/agents/register",
        headers={"X-Enrollment-Key": ENROLLMENT_KEY},
        json={"agent_id": "victim-01", "hostname": "VICTIM-PC1"},
    ).json()
    return {"X-Agent-Id": "victim-01", "Authorization": f"Bearer {reg['agent_token']}"}


def _batch(agent_id="victim-01", connections=None):
    if connections is None:
        connections = [
            {"local_ip": "192.168.56.101", "local_port": 51820, "remote_ip": "192.168.56.1", "remote_port": 443, "protocol": "TCP", "status": "ESTABLISHED"},
            {"local_ip": "192.168.56.101", "local_port": 3389, "remote_ip": None, "remote_port": None, "protocol": "TCP", "status": "LISTEN"},
        ]
    return {
        "agent_id": agent_id,
        "hostname": "VICTIM-PC1",
        "timestamp": datetime.now(UTC).isoformat(),
        "local_ip": "192.168.56.101",
        "connections": connections,
    }


def test_telemetry_requires_agent_auth(client):
    response = client.post("/api/v1/telemetry/events", json=_batch())
    assert response.status_code == 401


def test_telemetry_valid_batch_is_accepted_and_persisted(client, agent_headers, db_session):
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] is True
    assert body["connections_received"] == 2

    rows = db_session.query(AgentTelemetryEvent).all()
    assert len(rows) == 2
    protocols = {r.protocol for r in rows}
    assert protocols == {"TCP"}
    statuses = {r.connection_status for r in rows}
    assert statuses == {"ESTABLISHED", "LISTEN"}
    listen_row = next(r for r in rows if r.connection_status == "LISTEN")
    assert listen_row.remote_ip is None  # never fabricated for a LISTEN socket


def test_telemetry_never_touches_the_scored_event_tables(client, agent_headers, db_session):
    before = (db_session.query(Event).count(), db_session.query(Detection).count(), db_session.query(RiskAssessment).count())
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch())
    assert response.status_code == 200
    after = (db_session.query(Event).count(), db_session.query(Detection).count(), db_session.query(RiskAssessment).count())
    assert before == after


def test_telemetry_updates_agent_last_seen(client, agent_headers, auth_headers):
    client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch())
    listing = client.get("/api/v1/agents", headers=auth_headers)
    agent = next(a for a in listing.json() if a["agent_id"] == "victim-01")
    assert agent["last_seen"] is not None
    assert agent["online"] is True


def test_telemetry_rejects_mismatched_agent_id(client, agent_headers):
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch(agent_id="someone-else"))
    assert response.status_code == 400


def test_telemetry_rejects_invalid_ip(client, agent_headers):
    bad = [{"local_ip": "not-an-ip", "local_port": 1, "remote_ip": None, "remote_port": None, "protocol": "TCP", "status": "LISTEN"}]
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch(connections=bad))
    assert response.status_code == 422


def test_telemetry_rejects_invalid_port(client, agent_headers):
    bad = [{"local_ip": "192.168.56.101", "local_port": 70000, "remote_ip": None, "remote_port": None, "protocol": "TCP", "status": "LISTEN"}]
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch(connections=bad))
    assert response.status_code == 422


def test_telemetry_rejects_invalid_protocol(client, agent_headers):
    bad = [{"local_ip": "192.168.56.101", "local_port": 1, "remote_ip": None, "remote_port": None, "protocol": "ICMP", "status": "LISTEN"}]
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch(connections=bad))
    assert response.status_code == 422


def test_telemetry_rejects_invalid_status(client, agent_headers):
    bad = [{"local_ip": "192.168.56.101", "local_port": 1, "remote_ip": None, "remote_port": None, "protocol": "TCP", "status": "BOGUS"}]
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch(connections=bad))
    assert response.status_code == 422


def test_telemetry_accepts_empty_connections_list(client, agent_headers):
    response = client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch(connections=[]))
    assert response.status_code == 200
    assert response.json()["connections_received"] == 0


def test_list_telemetry_requires_admin(client, agent_headers):
    client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch())
    response = client.get("/api/v1/telemetry/events")
    assert response.status_code == 401


def test_list_telemetry_returns_persisted_rows(client, agent_headers, auth_headers):
    client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch())
    response = client.get("/api/v1/telemetry/events", headers=auth_headers)
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_list_telemetry_filters_by_agent_id(client, agent_headers, auth_headers):
    client.post("/api/v1/telemetry/events", headers=agent_headers, json=_batch())
    response = client.get("/api/v1/telemetry/events", headers=auth_headers, params={"agent_id": "no-such-agent"})
    assert response.status_code == 200
    assert response.json() == []
