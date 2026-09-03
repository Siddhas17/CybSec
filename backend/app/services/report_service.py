"""Orchestrates security-report generation: gathers real data from
existing services (never re-derives query logic already used elsewhere),
renders the PDF via report_pdf.build_pdf(), writes it to disk, and records
a SecurityReport row -- even on failure, mirroring PreventionAction's
"always record, never swallow" convention.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.attack_graph import AttackEdge, AttackNode
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.security_report import SecurityReport
from backend.app.models.user import User
from backend.app.services import analytics_service, model_eval_service, report_pdf
from backend.app.services.model_registry import (
    ATTACK_GRAPH_VERSION,
    AUTOENCODER_VERSION,
    KNN_VERSION,
    PREPROCESSING_VERSION,
    get_predictor,
    get_risk_config,
)

SYSTEM_INFO_TEXT = (
    "Single-machine deployment: a loopback packet sensor (Phase 6) reconstructs network flows and scores them "
    "through the same analytical core used for offline evaluation. The response/prevention layer (Phase 7) runs "
    "in dry-run mode only in this environment -- no traffic has ever actually been blocked. No live multi-host "
    "laboratory (separate attacker/victim machines) exists in this deployment; all live figures in this report "
    "come from this single machine's own captured traffic."
)


def _build_context(db: Session) -> dict:
    model_eval_service.sync_all(db)  # ensure this PDF and the model-metrics CSV export agree with current artifacts

    predictor = get_predictor()
    risk_config = get_risk_config()
    knn_metrics = model_eval_service.get_current_knn_metrics()

    node_count = db.query(func.count(AttackNode.id)).scalar() or 0
    edge_count = db.query(func.count(AttackEdge.id)).scalar() or 0
    prevention_by_action = dict(db.query(PreventionAction.actual_action, func.count(PreventionAction.id)).group_by(PreventionAction.actual_action).all())

    return {
        "system_info": SYSTEM_INFO_TEXT,
        "active_model": {
            "preprocessing_version": PREPROCESSING_VERSION,
            "autoencoder_version": AUTOENCODER_VERSION,
            "autoencoder_threshold": predictor.threshold,
            "attack_graph_version": ATTACK_GRAPH_VERSION,
            "risk_engine_version": risk_config.version,
            "knn_version": KNN_VERSION if knn_metrics.get("available") else "not trained",
        },
        "dataset_stats": model_eval_service.get_dataset_stats(),
        "autoencoder_metrics": model_eval_service.get_current_autoencoder_metrics(),
        "knn_metrics": knn_metrics,
        "summary": analytics_service.get_summary(db),
        "attacks_by_type": analytics_service.get_attacks_by_type(db),
        "risk_distribution": analytics_service.get_risk_distribution(db),
        "risk_score_buckets": analytics_service.get_risk_score_distribution(db),
        "anomaly_score_buckets": analytics_service.get_anomaly_score_distribution(db),
        "timeline": analytics_service.get_timeline(db),
        "top_destinations": analytics_service.get_top_destinations(db, limit=10),
        "graph_node_count": node_count,
        "graph_edge_count": edge_count,
        "prevention_by_action": prevention_by_action,
        "live_vs_offline": model_eval_service.get_live_vs_offline_stats(db),
    }


def generate_report(db: Session, user: User) -> SecurityReport:
    generated_at = datetime.now(UTC)
    title = f"Security Report - {generated_at.strftime('%Y-%m-%d %H:%M UTC')}"

    try:
        context = _build_context(db)
        pdf_bytes = report_pdf.build_pdf(context, generated_by=user.username, generated_at=generated_at)

        settings.reports_output_dir_absolute.mkdir(parents=True, exist_ok=True)
        file_path = settings.reports_output_dir_absolute / f"report_{uuid.uuid4().hex}.pdf"
        file_path.write_bytes(pdf_bytes)

        report = SecurityReport(
            title=title,
            generated_by_user_id=user.id,
            generation_status="complete",
            file_path=str(file_path),
            file_size_bytes=len(pdf_bytes),
            summary_stats=context["summary"],
            model_version_snapshot=context["active_model"],
        )
    except Exception as exc:  # noqa: BLE001 -- always record the real failure, never swallow it silently
        report = SecurityReport(title=title, generated_by_user_id=user.id, generation_status="failed", error_message=str(exc))

    db.add(report)
    db.commit()
    db.refresh(report)
    return report
