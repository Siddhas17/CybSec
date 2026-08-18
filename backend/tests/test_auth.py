"""Section 16: authentication, malformed input handling."""

from __future__ import annotations

from backend.app.core.config import settings


def test_login_success(client):
    response = client.post("/api/v1/auth/login", json={"username": settings.admin_username, "password": settings.admin_password})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_wrong_password_rejected(client):
    response = client.post("/api/v1/auth/login", json={"username": settings.admin_username, "password": "not-the-password"})
    assert response.status_code == 401


def test_login_unknown_user_rejected(client):
    response = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "whatever"})
    assert response.status_code == 401


def test_login_malformed_payload_rejected(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin"})  # missing password
    assert response.status_code == 422


def test_protected_endpoint_without_token_rejected(client):
    response = client.get("/api/v1/events")
    assert response.status_code == 401


def test_protected_endpoint_with_garbage_token_rejected(client):
    response = client.get("/api/v1/events", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


def test_me_endpoint_with_valid_token(client, auth_headers):
    response = client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["username"] == settings.admin_username
