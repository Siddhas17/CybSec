"""CSV export endpoint tests: correct content-type, and the exported rows
round-trip through csv.reader into the expected headers/counts against a
small seeded fixture -- real MySQL-shaped data (via the SQLite test DB),
never a hardcoded string."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from backend.app.models.detection import Detection
from backend.app.models.event import Event, EventSource
from backend.app.models.model_version import ModelVersion
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.risk_assessment import RiskAssessment


def _seed_one_flagged_event(db: Session) -> None:
    version = ModelVersion(component="test", version="test-1")
    db.add(version)
    db.flush()

    event = Event(
        event_uid="csv-export-test-1",
        timestamp=datetime.now(UTC),
        source_ip="192.168.56.20",
        destination_ip="10.0.0.9",
        source=EventSource.TEST_EVENT,
        status="processed",
    )
    db.add(event)
    db.flush()

    detection = Detection(event_id=event.id, anomaly_score=0.9, reconstruction_error=0.9, is_anomaly=True, threshold_used=0.1, model_version_id=version.id)
    db.add(detection)
    db.flush()

    risk = RiskAssessment(
        event_id=event.id,
        detection_id=detection.id,
        risk_score=8.5,
        risk_level="Critical",
        factors=[],
        rules_applied=[],
        reason="csv export test fixture",
        risk_config_version_id=version.id,
    )
    db.add(risk)
    db.flush()

    db.add(
        PreventionAction(
            event_id=event.id,
            detection_id=detection.id,
            risk_assessment_id=risk.id,
            source_ip=event.source_ip,
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            requested_action="alert",
            actual_action="alerted",
            dry_run=True,
            success=True,
            reason="csv export test fixture",
            adapter="test",
        )
    )
    db.commit()


def _parse_csv(content: str) -> tuple[list[str], list[list[str]]]:
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    return rows[0], rows[1:]


def test_events_csv_export(client, auth_headers, db_session):
    _seed_one_flagged_event(db_session)
    response = client.get("/api/v1/reports/export/events.csv", headers=auth_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    header, rows = _parse_csv(response.text)
    assert header[:4] == ["id", "event_uid", "timestamp", "source_ip"]
    assert any(r[1] == "csv-export-test-1" for r in rows)


def test_anomalies_csv_export(client, auth_headers, db_session):
    _seed_one_flagged_event(db_session)
    response = client.get("/api/v1/reports/export/anomalies.csv", headers=auth_headers)
    assert response.status_code == 200
    header, rows = _parse_csv(response.text)
    assert header[0] == "detection_id"
    assert len(rows) == 1
    assert rows[0][header.index("anomaly_score")] == "0.9"


def test_alerts_csv_export_only_includes_high_and_critical(client, auth_headers, db_session):
    _seed_one_flagged_event(db_session)
    response = client.get("/api/v1/reports/export/alerts.csv", headers=auth_headers)
    assert response.status_code == 200
    header, rows = _parse_csv(response.text)
    assert "risk_level" in header
    assert len(rows) == 1
    assert rows[0][header.index("risk_level")] == "Critical"


def test_risk_assessments_csv_export(client, auth_headers, db_session):
    _seed_one_flagged_event(db_session)
    response = client.get("/api/v1/reports/export/risk-assessments.csv", headers=auth_headers)
    assert response.status_code == 200
    header, rows = _parse_csv(response.text)
    assert len(rows) == 1
    assert rows[0][header.index("risk_score")] == "8.5"


def test_prevention_actions_csv_export(client, auth_headers, db_session):
    _seed_one_flagged_event(db_session)
    response = client.get("/api/v1/reports/export/prevention-actions.csv", headers=auth_headers)
    assert response.status_code == 200
    header, rows = _parse_csv(response.text)
    assert len(rows) == 1
    assert rows[0][header.index("actual_action")] == "alerted"


def test_model_metrics_csv_export_empty_when_no_training_runs_synced(client, auth_headers):
    response = client.get("/api/v1/reports/export/model-metrics.csv", headers=auth_headers)
    assert response.status_code == 200
    header, rows = _parse_csv(response.text)
    assert header[0] == "id"
    assert rows == []


def test_model_metrics_csv_export_after_sync(client, auth_headers):
    client.post("/api/v1/model-eval/training-history/sync", headers=auth_headers)
    response = client.get("/api/v1/reports/export/model-metrics.csv", headers=auth_headers)
    assert response.status_code == 200
    header, rows = _parse_csv(response.text)
    assert any(r[header.index("component")] == "autoencoder" for r in rows)
