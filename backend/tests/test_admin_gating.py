"""Admin-gating tests for the Model Evaluation endpoints -- the first place
`User.is_admin` is actually enforced anywhere in this codebase (see
backend/app/api/deps.require_admin's docstring). Every admin-only endpoint
must reject an authenticated-but-non-admin user with 403 and accept the
seed admin (auth_headers fixture, is_admin=True by default)."""

from __future__ import annotations

import pytest

from backend.app.core.security import create_access_token, hash_password
from backend.app.models.user import User

ADMIN_ONLY_GET_ENDPOINTS = [
    "/api/v1/model-eval/autoencoder/metrics",
    "/api/v1/model-eval/knn/metrics",
    "/api/v1/model-eval/comparison",
    "/api/v1/model-eval/status",
    "/api/v1/model-eval/live-vs-offline",
    "/api/v1/model-eval/dataset-stats",
    "/api/v1/model-eval/training-history",
    "/api/v1/reports",
    "/api/v1/reports/export/events.csv",
    "/api/v1/reports/export/alerts.csv",
    "/api/v1/reports/export/anomalies.csv",
    "/api/v1/reports/export/risk-assessments.csv",
    "/api/v1/reports/export/prevention-actions.csv",
    "/api/v1/reports/export/model-metrics.csv",
]


@pytest.fixture()
def non_admin_auth_headers(client, db_session):
    user = User(username="analyst", hashed_password=hash_password("analyst-pw"), is_admin=False)
    db_session.add(user)
    db_session.commit()
    token = create_access_token(subject=user.username)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", ADMIN_ONLY_GET_ENDPOINTS)
def test_admin_only_get_endpoints_reject_non_admin(client, non_admin_auth_headers, path):
    response = client.get(path, headers=non_admin_auth_headers)
    assert response.status_code == 403


@pytest.mark.parametrize("path", ADMIN_ONLY_GET_ENDPOINTS)
def test_admin_only_get_endpoints_accept_admin(client, auth_headers, path):
    response = client.get(path, headers=auth_headers)
    assert response.status_code == 200


def test_training_history_sync_rejects_non_admin(client, non_admin_auth_headers):
    response = client.post("/api/v1/model-eval/training-history/sync", headers=non_admin_auth_headers)
    assert response.status_code == 403


def test_training_history_sync_accepts_admin(client, auth_headers):
    response = client.post("/api/v1/model-eval/training-history/sync", headers=auth_headers)
    assert response.status_code == 200


def test_training_run_detail_rejects_non_admin_before_the_404_lookup(client, non_admin_auth_headers):
    response = client.get("/api/v1/model-eval/training-history/1", headers=non_admin_auth_headers)
    assert response.status_code == 403


def test_training_run_detail_returns_404_for_admin_when_missing(client, auth_headers):
    response = client.get("/api/v1/model-eval/training-history/999999", headers=auth_headers)
    assert response.status_code == 404


def test_admin_only_endpoints_still_reject_unauthenticated(client):
    response = client.get("/api/v1/model-eval/status")
    assert response.status_code == 401


def test_generate_report_rejects_non_admin(client, non_admin_auth_headers):
    response = client.post("/api/v1/reports/generate", headers=non_admin_auth_headers)
    assert response.status_code == 403


def test_report_detail_rejects_non_admin_before_the_404_lookup(client, non_admin_auth_headers):
    response = client.get("/api/v1/reports/1", headers=non_admin_auth_headers)
    assert response.status_code == 403
