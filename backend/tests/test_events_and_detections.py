"""Section 16: event validation, detection persistence, risk persistence."""

from __future__ import annotations


def test_malformed_test_event_missing_required_field_rejected(client, auth_headers):
    response = client.post("/api/v1/test-events", json={"source_ip": "10.0.0.1"}, headers=auth_headers)  # missing destination_ip
    assert response.status_code == 422


def test_valid_test_event_creates_detection_and_risk_assessment(client, auth_headers, db_session):
    response = client.post(
        "/api/v1/test-events",
        json={"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2"},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert "anomaly_score" in body
    assert "risk_score" in body
    assert 1.0 <= body["risk_score"] <= 10.0
    assert body["risk_level"] in {"Very Low", "Low", "Moderate", "High", "Critical"}
    assert len(body["factors"]) == 5
    assert len(body["imputed_features"]) == 67  # no features supplied -> all imputed from scaler means

    from backend.app.models.detection import Detection
    from backend.app.models.event import Event
    from backend.app.models.risk_assessment import RiskAssessment

    event = db_session.query(Event).filter(Event.id == body["event_id"]).first()
    assert event is not None
    assert event.source.value == "test_event"

    detection = db_session.query(Detection).filter(Detection.event_id == event.id).first()
    assert detection is not None
    assert detection.anomaly_score == body["anomaly_score"]

    risk = db_session.query(RiskAssessment).filter(RiskAssessment.event_id == event.id).first()
    assert risk is not None
    assert risk.risk_score == body["risk_score"]


def test_partial_features_are_disclosed_as_imputed(client, auth_headers):
    response = client.post(
        "/api/v1/test-events",
        json={"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "features": {"Destination Port": 443.0}},
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert "Destination Port" not in body["imputed_features"]
    assert len(body["imputed_features"]) == 66


def test_get_events_requires_auth(client):
    assert client.get("/api/v1/events").status_code == 401


def test_get_events_list_and_detail(client, auth_headers):
    create = client.post("/api/v1/test-events", json={"source_ip": "10.0.0.5", "destination_ip": "10.0.0.6"}, headers=auth_headers)
    event_id = create.json()["event_id"]

    listed = client.get("/api/v1/events", headers=auth_headers)
    assert listed.status_code == 200
    assert any(e["id"] == event_id for e in listed.json())

    detail = client.get(f"/api/v1/events/{event_id}", headers=auth_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["detection"] is not None
    assert body["risk_assessment"] is not None


def test_get_nonexistent_event_404s(client, auth_headers):
    response = client.get("/api/v1/events/999999", headers=auth_headers)
    assert response.status_code == 404
