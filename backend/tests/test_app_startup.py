"""Section 16: app startup, health endpoint, database connection."""

from __future__ import annotations


def test_app_importable():
    from backend.app.main import app

    assert app is not None


def test_health_endpoint_reports_ok(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "connected"
    assert body["analytical_core"] == "loaded"


def test_startup_seeds_admin_user(client, db_session):
    from backend.app.models.user import User

    admin = db_session.query(User).first()
    assert admin is not None
    assert admin.is_admin is True
