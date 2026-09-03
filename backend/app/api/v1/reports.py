"""Security report generation, download, and CSV export -- admin-only (see
backend/app/api/deps.require_admin's docstring for why this is enforced
here). Deliberately thin, same convention as prevention.py: routers just
call report_service/csv_export, no PDF/query logic lives in this file."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, require_admin
from backend.app.models.security_report import SecurityReport
from backend.app.models.user import User
from backend.app.schemas.reports import SecurityReportOut
from backend.app.services import audit, csv_export, report_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate", response_model=SecurityReportOut)
def generate(db: Session = Depends(get_db), admin: User = Depends(require_admin)) -> SecurityReport:
    report = report_service.generate_report(db, admin)
    audit.log(
        db,
        "INFO" if report.generation_status == "complete" else "ERROR",
        "reports",
        f"Security report generation {report.generation_status}: {report.title}",
        user_id=admin.id,
        metadata={"report_id": report.id, "error": report.error_message},
    )
    return report


@router.get("", response_model=list[SecurityReportOut])
def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> list[SecurityReport]:
    return db.query(SecurityReport).order_by(SecurityReport.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{report_id}", response_model=SecurityReportOut)
def get_report(report_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> SecurityReport:
    report = db.get(SecurityReport, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Report {report_id} not found")
    return report


@router.get("/{report_id}/pdf")
def download_pdf(
    report_id: int,
    disposition: str = Query("attachment", pattern="^(attachment|inline)$"),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> FileResponse:
    report = db.get(SecurityReport, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Report {report_id} not found")
    if report.generation_status != "complete" or not report.file_path:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Report {report_id} has no PDF -- generation status is {report.generation_status!r}: {report.error_message}",
        )

    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Report file missing on disk: {path}")

    filename = f"security_report_{report_id}.pdf"
    return FileResponse(path, media_type="application/pdf", filename=filename if disposition == "attachment" else None)


def _csv_response(content: str, filename: str) -> PlainTextResponse:
    return PlainTextResponse(content, media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/export/events.csv")
def export_events(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> PlainTextResponse:
    return _csv_response(csv_export.events_csv(db), "events.csv")


@router.get("/export/alerts.csv")
def export_alerts(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> PlainTextResponse:
    return _csv_response(csv_export.alerts_csv(db), "alerts.csv")


@router.get("/export/anomalies.csv")
def export_anomalies(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> PlainTextResponse:
    return _csv_response(csv_export.anomalies_csv(db), "anomalies.csv")


@router.get("/export/risk-assessments.csv")
def export_risk_assessments(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> PlainTextResponse:
    return _csv_response(csv_export.risk_assessments_csv(db), "risk_assessments.csv")


@router.get("/export/prevention-actions.csv")
def export_prevention_actions(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> PlainTextResponse:
    return _csv_response(csv_export.prevention_actions_csv(db), "prevention_actions.csv")


@router.get("/export/model-metrics.csv")
def export_model_metrics(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> PlainTextResponse:
    return _csv_response(csv_export.model_metrics_csv(db), "model_metrics.csv")
