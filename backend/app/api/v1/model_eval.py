"""Model Evaluation endpoints -- real, computed accuracy/precision/recall/
F1/ROC-AUC/confusion-matrix for the autoencoder and KNN, training history,
dataset stats, and live-vs-offline detection stats. Admin-only (see
backend/app/api/deps.require_admin's docstring for why this is the first
place is_admin is actually enforced anywhere in this codebase).

Metrics/comparison/status/dataset-stats/live-vs-offline are free-form,
dynamically-shaped dicts (their availability and fields depend on whether a
model has been trained yet) -- returned without a response_model, same
established convention as analytics.py's anomaly_score_distribution /
risk_score_distribution. Training-history endpoints are real DB rows with a
fixed shape, so they use TrainingRunOut.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_db, require_admin
from backend.app.models.training_run import TrainingRun
from backend.app.models.user import User
from backend.app.schemas.model_eval import TrainingRunOut
from backend.app.services import audit, model_eval_service, model_validation

router = APIRouter(prefix="/model-eval", tags=["model-eval"])


@router.get("/autoencoder/metrics")
def autoencoder_metrics(_admin: User = Depends(require_admin)) -> dict:
    return model_eval_service.get_current_autoencoder_metrics()


@router.get("/knn/metrics")
def knn_metrics(_admin: User = Depends(require_admin)) -> dict:
    return model_eval_service.get_current_knn_metrics()


@router.get("/comparison")
def comparison(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> dict:
    return model_eval_service.get_model_comparison(db)


@router.get("/status")
def status_check(_admin: User = Depends(require_admin)) -> dict:
    return {"autoencoder": model_validation.validate_autoencoder(), "knn": model_validation.validate_knn()}


@router.get("/live-vs-offline")
def live_vs_offline(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> dict:
    return model_eval_service.get_live_vs_offline_stats(db)


@router.get("/dataset-stats")
def dataset_stats(_admin: User = Depends(require_admin)) -> dict:
    return model_eval_service.get_dataset_stats()


@router.get("/training-history", response_model=list[TrainingRunOut])
def training_history(
    component: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> list[TrainingRun]:
    return model_eval_service.get_training_history(db, component=component, limit=limit)


@router.get("/training-history/{run_id}", response_model=TrainingRunOut)
def training_run_detail(run_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> TrainingRun:
    run = model_eval_service.get_training_run_detail(db, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Training run {run_id} not found")
    return run


@router.post("/training-history/sync", response_model=list[TrainingRunOut])
def sync_training_history(db: Session = Depends(get_db), admin: User = Depends(require_admin)) -> list[TrainingRun]:
    runs = model_eval_service.sync_all(db)
    audit.log(
        db,
        "INFO",
        "model_eval",
        f"Training history synced: {len(runs)} new run(s) recorded ({', '.join(r.component for r in runs) or 'none'})",
        user_id=admin.id,
    )
    return runs
