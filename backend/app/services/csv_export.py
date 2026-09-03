"""CSV export for the Reports page's Download CSV actions. Each function
mirrors the query shape the corresponding existing router already uses
(events.py / risks.py / prevention.py) and writes real MySQL data via
csv.writer into an in-memory io.StringIO -- never persisted to disk,
generated fresh per request."""

from __future__ import annotations

import csv
import io

from sqlalchemy.orm import Session

from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.training_run import TrainingRun


def _write_csv(header: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue()


def events_csv(db: Session) -> str:
    rows = db.query(Event).order_by(Event.timestamp.desc()).all()
    header = [
        "id", "event_uid", "timestamp", "source_ip", "source_port", "destination_ip", "destination_port",
        "protocol", "canonical_attack_label", "traffic_class", "source", "status", "created_at",
    ]
    data = [
        [e.id, e.event_uid, e.timestamp, e.source_ip, e.source_port, e.destination_ip, e.destination_port,
         e.protocol, e.canonical_attack_label, e.traffic_class, e.source.value, e.status, e.created_at]
        for e in rows
    ]
    return _write_csv(header, data)


def anomalies_csv(db: Session) -> str:
    """Detection.is_anomaly=True joined to Event -- same definition
    analytics_service.get_summary() already uses for anomaly_count."""
    rows = (
        db.query(Detection, Event)
        .join(Event, Detection.event_id == Event.id)
        .filter(Detection.is_anomaly.is_(True))
        .order_by(Detection.id.desc())
        .all()
    )
    header = ["detection_id", "event_id", "event_uid", "timestamp", "source_ip", "destination_ip", "anomaly_score", "reconstruction_error", "threshold_used", "canonical_attack_label"]
    data = [
        [d.id, e.id, e.event_uid, e.timestamp, e.source_ip, e.destination_ip, d.anomaly_score, d.reconstruction_error, d.threshold_used, e.canonical_attack_label]
        for d, e in rows
    ]
    return _write_csv(header, data)


def alerts_csv(db: Session) -> str:
    """RiskAssessment rows at High/Critical joined to Event -- "what got
    flagged", distinct from prevention_actions_csv ("what the response
    layer did about it")."""
    rows = (
        db.query(RiskAssessment, Event)
        .join(Event, RiskAssessment.event_id == Event.id)
        .filter(RiskAssessment.risk_level.in_(["High", "Critical"]))
        .order_by(RiskAssessment.risk_score.desc())
        .all()
    )
    header = ["risk_assessment_id", "event_id", "event_uid", "timestamp", "source_ip", "destination_ip", "risk_score", "risk_level", "reason"]
    data = [[r.id, e.id, e.event_uid, e.timestamp, e.source_ip, e.destination_ip, r.risk_score, r.risk_level, r.reason] for r, e in rows]
    return _write_csv(header, data)


def risk_assessments_csv(db: Session) -> str:
    rows = db.query(RiskAssessment).order_by(RiskAssessment.risk_score.desc()).all()
    header = ["id", "event_id", "detection_id", "risk_score", "risk_level", "reason", "created_at"]
    data = [[r.id, r.event_id, r.detection_id, r.risk_score, r.risk_level, r.reason, r.created_at] for r in rows]
    return _write_csv(header, data)


def prevention_actions_csv(db: Session) -> str:
    rows = db.query(PreventionAction).order_by(PreventionAction.created_at.desc()).all()
    header = ["id", "event_id", "source_ip", "risk_score", "risk_level", "requested_action", "actual_action", "dry_run", "success", "reason", "adapter", "target_scope", "created_at"]
    data = [
        [p.id, p.event_id, p.source_ip, p.risk_score, p.risk_level, p.requested_action, p.actual_action, p.dry_run, p.success, p.reason, p.adapter, p.target_scope, p.created_at]
        for p in rows
    ]
    return _write_csv(header, data)


def model_metrics_csv(db: Session) -> str:
    """Every synced TrainingRun -- real MySQL data, the same source of
    truth report_service.py uses for the PDF's evaluation-metrics section
    (see model_eval_service.sync_training_run's docstring for why)."""
    rows = db.query(TrainingRun).order_by(TrainingRun.created_at.desc()).all()
    header = ["id", "component", "run_id", "trained_at", "feature_count", "threshold", "metrics", "confusion_matrix", "created_at"]
    data = [[t.id, t.component, t.run_id, t.trained_at, t.feature_count, t.threshold, t.metrics, t.confusion_matrix, t.created_at] for t in rows]
    return _write_csv(header, data)
