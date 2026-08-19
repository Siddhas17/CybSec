"""Section 16: sensor control/health endpoints. Never exercises real packet
capture here (that needs `unshare`/scapy and a real subprocess -- out of
scope for a fast unit test); only the auth gate, the TELEMETRY_ENABLED
master-switch refusal (docs/live_telemetry.md section 15/22), and the
health/stop contract are covered."""

from __future__ import annotations

from backend.app.services.live_sensor_service import live_sensor_service


def test_sensor_health_requires_auth(client):
    assert client.get("/api/v1/sensor/health").status_code == 401


def test_sensor_start_requires_auth(client):
    assert client.post("/api/v1/sensor/start").status_code == 401


def test_sensor_health_reflects_stopped_state_by_default(client, auth_headers):
    response = client.get("/api/v1/sensor/health", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["collector_status"] == "stopped"
    assert body["telemetry_enabled"] is False  # real .env default, never true in tests
    assert body["events_processed"] == 0
    assert body["active_flows"] == 0


def test_sensor_start_refuses_when_telemetry_disabled(client, auth_headers):
    response = client.post("/api/v1/sensor/start", headers=auth_headers)
    assert response.status_code == 400
    assert "TELEMETRY_ENABLED" in response.json()["detail"]
    # Refusal must happen before the collector is touched (section 22).
    assert live_sensor_service.health().collector_status == "stopped"


def test_sensor_stop_is_idempotent_when_never_started(client, auth_headers):
    response = client.post("/api/v1/sensor/stop", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "stopped"
