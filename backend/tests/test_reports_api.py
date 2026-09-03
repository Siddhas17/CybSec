"""End-to-end tests for security report generation and download. Runs the
real ReportLab/matplotlib PDF pipeline against the real trained autoencoder
artifacts (same reuse-real-artifacts convention as conftest.py) with an
otherwise-empty test database -- confirms the pipeline produces a genuine
PDF from real (if sparse) data, and that a failure is recorded honestly
rather than swallowed or returned as an opaque 500."""

from __future__ import annotations

import pytest

from backend.app.models.security_report import SecurityReport
from backend.app.services import report_pdf


def test_generate_report_produces_a_real_pdf(client, auth_headers, db_session):
    response = client.post("/api/v1/reports/generate", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["generation_status"] == "complete"
    assert body["file_size_bytes"] and body["file_size_bytes"] > 0

    report_id = body["id"]
    list_response = client.get("/api/v1/reports", headers=auth_headers)
    assert any(r["id"] == report_id for r in list_response.json())

    pdf_response = client.get(f"/api/v1/reports/{report_id}/pdf", headers=auth_headers)
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert pdf_response.content.startswith(b"%PDF")
    assert len(pdf_response.content) > 1000


def test_view_pdf_uses_inline_disposition(client, auth_headers):
    generate_response = client.post("/api/v1/reports/generate", headers=auth_headers)
    report_id = generate_response.json()["id"]

    response = client.get(f"/api/v1/reports/{report_id}/pdf?disposition=inline", headers=auth_headers)
    assert response.status_code == 200
    assert "attachment" not in response.headers.get("content-disposition", "")


def test_generate_report_records_failure_honestly(client, auth_headers, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated PDF build failure")

    monkeypatch.setattr(report_pdf, "build_pdf", _boom)

    response = client.post("/api/v1/reports/generate", headers=auth_headers)
    assert response.status_code == 200  # the failure is recorded, not a leaking 500
    body = response.json()
    assert body["generation_status"] == "failed"
    assert "simulated PDF build failure" in body["error_message"]
    assert body["file_path"] is None


def test_download_pdf_for_a_failed_report_returns_a_clean_error(client, auth_headers, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated PDF build failure")

    monkeypatch.setattr(report_pdf, "build_pdf", _boom)
    generate_response = client.post("/api/v1/reports/generate", headers=auth_headers)
    report_id = generate_response.json()["id"]

    response = client.get(f"/api/v1/reports/{report_id}/pdf", headers=auth_headers)
    assert response.status_code == 409
    assert "failed" in response.json()["detail"]


def test_download_pdf_for_missing_report_returns_404(client, auth_headers):
    response = client.get("/api/v1/reports/999999/pdf", headers=auth_headers)
    assert response.status_code == 404
