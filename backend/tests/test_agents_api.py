"""victim_agent identity/registration/heartbeat (Phase 1). The real .env
deliberately has no AGENT_ENROLLMENT_KEY set (see docs/victim_agent.md) --
tests that need a configured key monkeypatch `settings.agent_enrollment_key`
directly rather than requiring a real one, exactly the way `db_session`
substitutes a real MySQL connection with an isolated SQLite one."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.core.config import settings
from backend.app.models.agent import Agent

ENROLLMENT_KEY = "test-enrollment-key-do-not-use-in-prod"


@pytest.fixture()
def enrollment_headers(monkeypatch):
    monkeypatch.setattr(settings, "agent_enrollment_key", ENROLLMENT_KEY)
    return {"X-Enrollment-Key": ENROLLMENT_KEY}


def _register(client, enrollment_headers, agent_id="victim-01", hostname="VICTIM-PC1"):
    response = client.post(
        "/api/v1/agents/register",
        headers=enrollment_headers,
        json={"agent_id": agent_id, "hostname": hostname, "operating_system": "Windows 11", "ip_address": "192.168.56.101", "agent_version": "0.1.0"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_register_requires_configured_enrollment_key(client):
    # settings.agent_enrollment_key is "" by default (unset in the real
    # .env) -- registration must refuse rather than silently accepting
    # any/no key.
    response = client.post("/api/v1/agents/register", json={"agent_id": "victim-01", "hostname": "VICTIM-PC1"})
    assert response.status_code == 503


def test_register_rejects_missing_enrollment_key(client, enrollment_headers):
    response = client.post("/api/v1/agents/register", json={"agent_id": "victim-01", "hostname": "VICTIM-PC1"})
    assert response.status_code == 401


def test_register_rejects_wrong_enrollment_key(client, enrollment_headers):
    response = client.post(
        "/api/v1/agents/register",
        headers={"X-Enrollment-Key": "wrong-key"},
        json={"agent_id": "victim-01", "hostname": "VICTIM-PC1"},
    )
    assert response.status_code == 401


def test_register_success_returns_token_once(client, enrollment_headers):
    body = _register(client, enrollment_headers)
    assert body["agent_id"] == "victim-01"
    assert body["rotated"] is False
    assert len(body["agent_token"]) > 20


def test_register_two_distinct_agent_ids_both_succeed(client, enrollment_headers):
    victim1 = _register(client, enrollment_headers, agent_id="victim-01", hostname="VICTIM-PC1")
    victim2 = _register(client, enrollment_headers, agent_id="victim-02", hostname="VICTIM-PC2")
    assert victim1["agent_id"] != victim2["agent_id"]
    assert victim1["agent_token"] != victim2["agent_token"]


def test_reregister_same_agent_id_rotates_token(client, enrollment_headers):
    first = _register(client, enrollment_headers)
    second = _register(client, enrollment_headers)
    assert second["rotated"] is True
    assert second["agent_token"] != first["agent_token"]


def test_reregister_invalidates_old_token(client, enrollment_headers):
    first = _register(client, enrollment_headers)
    _register(client, enrollment_headers)  # rotates
    response = client.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Agent-Id": "victim-01", "Authorization": f"Bearer {first['agent_token']}"},
        json={"agent_id": "victim-01", "hostname": "VICTIM-PC1", "timestamp": datetime.now(UTC).isoformat()},
    )
    assert response.status_code == 401


def test_heartbeat_requires_credentials(client):
    response = client.post("/api/v1/agents/heartbeat", json={"agent_id": "victim-01", "hostname": "VICTIM-PC1", "timestamp": datetime.now(UTC).isoformat()})
    assert response.status_code == 401


def test_heartbeat_rejects_bad_token(client, enrollment_headers):
    _register(client, enrollment_headers)
    response = client.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Agent-Id": "victim-01", "Authorization": "Bearer wrong-token"},
        json={"agent_id": "victim-01", "hostname": "VICTIM-PC1", "timestamp": datetime.now(UTC).isoformat()},
    )
    assert response.status_code == 401


def test_heartbeat_rejects_unknown_agent_id(client):
    response = client.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Agent-Id": "never-registered", "Authorization": "Bearer whatever"},
        json={"agent_id": "never-registered", "hostname": "X", "timestamp": datetime.now(UTC).isoformat()},
    )
    assert response.status_code == 401


def test_heartbeat_rejects_body_agent_id_mismatch(client, enrollment_headers):
    reg = _register(client, enrollment_headers)
    response = client.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Agent-Id": "victim-01", "Authorization": f"Bearer {reg['agent_token']}"},
        json={"agent_id": "someone-else", "hostname": "VICTIM-PC1", "timestamp": datetime.now(UTC).isoformat()},
    )
    assert response.status_code == 400


def test_heartbeat_updates_last_seen_ip_and_version(client, enrollment_headers, auth_headers, db_session):
    reg = _register(client, enrollment_headers)
    response = client.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Agent-Id": "victim-01", "Authorization": f"Bearer {reg['agent_token']}"},
        json={"agent_id": "victim-01", "hostname": "VICTIM-PC1", "timestamp": datetime.now(UTC).isoformat(), "ip_address": "192.168.56.201", "agent_version": "0.2.0"},
    )
    assert response.status_code == 200
    assert response.json()["accepted"] is True

    listing = client.get("/api/v1/agents", headers=auth_headers)
    assert listing.status_code == 200
    agents = {a["agent_id"]: a for a in listing.json()}
    assert agents["victim-01"]["ip_address"] == "192.168.56.201"
    assert agents["victim-01"]["agent_version"] == "0.2.0"
    assert agents["victim-01"]["last_seen"] is not None
    assert agents["victim-01"]["online"] is True


def test_list_agents_marks_stale_agent_offline(client, enrollment_headers, auth_headers, db_session):
    _register(client, enrollment_headers)
    agent = db_session.query(Agent).filter(Agent.agent_id == "victim-01").first()
    agent.last_seen = datetime.now(UTC) - timedelta(seconds=settings.agent_offline_threshold_seconds + 30)
    db_session.commit()

    listing = client.get("/api/v1/agents", headers=auth_headers)
    agents = {a["agent_id"]: a for a in listing.json()}
    assert agents["victim-01"]["online"] is False
