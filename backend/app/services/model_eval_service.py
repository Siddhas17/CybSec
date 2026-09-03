"""Model Evaluation service: real, computed metrics for the autoencoder and
KNN models -- both a live disk read of "current" artifacts (same pattern
model_registry.get_predictor() already uses for the live scoring path) and
an append-only history log (TrainingRun) for browsing past training runs.

No metric here is ever computed by this module -- it only reads what
ml/training/{train_autoencoder,train_knn}.py and
ml/evaluation/evaluate_autoencoder.py already wrote to disk. This module's
only "compute" is content-hashing those files to detect a changed training
run and aggregating live event counts from MySQL.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.detection import Detection
from backend.app.models.event import Event, EventSource
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.training_run import TrainingRun
from backend.app.services import model_registry
from ml.preprocessing.config import PROCESSED_DATA_DIR, RAW_DATA_DIR

LIVE_ACCURACY_NOTE = "Live accuracy cannot be calculated without ground-truth labels."

_AUTOENCODER_REQUIRED_FILES = ["config.json", "training_report.json", "threshold.json", "test_evaluation.json"]
_KNN_REQUIRED_FILES = ["config.json", "training_report.json", "test_evaluation.json"]


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _required_files(component: str) -> list[str]:
    return _AUTOENCODER_REQUIRED_FILES if component == "autoencoder" else _KNN_REQUIRED_FILES


def _artifact_dir(component: str) -> Path:
    return settings.model_path_absolute if component == "autoencoder" else settings.knn_model_path_absolute


def _content_hash(artifact_dir: Path, filenames: list[str]) -> str | None:
    """sha256 over the concatenated bytes of the given files, in a fixed
    order -- None if any required file is missing (component not trained
    yet, distinct from "unchanged since last sync")."""
    hasher = hashlib.sha256()
    for name in filenames:
        path = artifact_dir / name
        if not path.exists():
            return None
        hasher.update(path.read_bytes())
    return hasher.hexdigest()


def sync_training_run(db: Session, component: str) -> TrainingRun | None:
    """Hashes the component's current on-disk artifacts and inserts a new
    TrainingRun row only if the hash differs from the latest row for that
    component -- mirrors PreventionAction's "new row, never an edit"
    convention. Returns None (no-op, not an error) if the component hasn't
    been trained yet, or if nothing changed since the last sync."""
    artifact_dir = _artifact_dir(component)
    content_hash = _content_hash(artifact_dir, _required_files(component))
    if content_hash is None:
        return None

    latest = db.query(TrainingRun).filter(TrainingRun.component == component).order_by(TrainingRun.id.desc()).first()
    if latest is not None and latest.content_hash == content_hash:
        return None

    config = _read_json(artifact_dir / "config.json") or {}
    training_report = _read_json(artifact_dir / "training_report.json") or {}
    test_evaluation = _read_json(artifact_dir / "test_evaluation.json") or {}
    threshold_report = _read_json(artifact_dir / "threshold.json")
    feature_names = _read_json(artifact_dir / "feature_names.json") or []

    trained_at_raw = config.get("trained_at") or training_report.get("trained_at")
    trained_at = datetime.fromisoformat(trained_at_raw) if trained_at_raw else None

    if component == "autoencoder":
        threshold = threshold_report.get("selected_threshold") if threshold_report else None
        dataset_info = {
            "train_rows": training_report.get("train_rows"),
            "val_rows": training_report.get("val_rows"),
            "benign_training_set": training_report.get("benign_training_set"),
        }
        metrics = {k: test_evaluation.get(k) for k in ("precision", "recall", "f1", "roc_auc", "pr_auc", "false_positive_rate")}
        class_distribution = None
        model_version = model_registry.get_or_create_model_version(
            db, "autoencoder", model_registry.AUTOENCODER_VERSION, {"threshold": threshold}
        )
    else:
        threshold = None
        dataset_info = {
            "train_rows": training_report.get("train_rows"),
            "test_rows": training_report.get("test_rows"),
            "train_class_distribution": training_report.get("train_class_distribution"),
            "test_class_distribution": training_report.get("test_class_distribution"),
        }
        metrics = {
            k: test_evaluation.get(k)
            for k in (
                "accuracy",
                "precision_weighted",
                "recall_weighted",
                "f1_weighted",
                "precision_macro",
                "recall_macro",
                "f1_macro",
                "roc_auc",
                "pr_auc",
                "training_time_seconds",
                "inference_time_seconds",
            )
        }
        class_distribution = training_report.get("test_class_distribution")
        model_version = model_registry.get_or_create_model_version(db, "knn", model_registry.KNN_VERSION, config)

    confusion_matrix = {k: test_evaluation.get(k) for k in ("tp", "tn", "fp", "fn")}

    run = TrainingRun(
        component=component,
        run_id=config.get("run_id") or uuid.uuid4().hex,
        model_version_id=model_version.id,
        artifact_dir=str(artifact_dir),
        content_hash=content_hash,
        trained_at=trained_at,
        training_duration_seconds=training_report.get("training_seconds"),
        feature_count=len(feature_names) if feature_names else None,
        dataset_info=dataset_info,
        hyperparameters=config,
        preprocessing_version=model_registry.PREPROCESSING_VERSION,
        threshold=threshold,
        metrics=metrics,
        confusion_matrix=confusion_matrix,
        class_distribution=class_distribution,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def sync_all(db: Session) -> list[TrainingRun]:
    runs = (sync_training_run(db, component) for component in ("autoencoder", "knn"))
    return [run for run in runs if run is not None]


def get_training_history(db: Session, component: str | None = None, limit: int = 50) -> list[TrainingRun]:
    query = db.query(TrainingRun)
    if component:
        query = query.filter(TrainingRun.component == component)
    return query.order_by(TrainingRun.created_at.desc()).limit(limit).all()


def get_training_run_detail(db: Session, run_id: int) -> TrainingRun | None:
    return db.get(TrainingRun, run_id)


def get_current_autoencoder_metrics() -> dict:
    artifact_dir = settings.model_path_absolute
    test_evaluation = _read_json(artifact_dir / "test_evaluation.json")
    if test_evaluation is None:
        return {
            "available": False,
            "reason": "Autoencoder has not been evaluated yet -- run `python -m ml.evaluation.evaluate_autoencoder`.",
        }

    threshold_report = _read_json(artifact_dir / "threshold.json") or {}
    training_report = _read_json(artifact_dir / "training_report.json") or {}
    config = _read_json(artifact_dir / "config.json") or {}
    benign_stats = test_evaluation.get("benign_test_error_stats", {})
    attack_stats = test_evaluation.get("attack_test_error_stats", {})

    return {
        "available": True,
        "evaluation_label": "Anomaly Detection Evaluation (Held-Out Test Set)",
        "positive_class_definition": test_evaluation.get("positive_class_definition"),
        "threshold": threshold_report.get("selected_threshold"),
        "threshold_strategy": threshold_report.get("selected_strategy"),
        "confusion_matrix": {k: test_evaluation.get(k) for k in ("tp", "tn", "fp", "fn")},
        "precision": test_evaluation.get("precision"),
        "recall": test_evaluation.get("recall"),
        "f1": test_evaluation.get("f1"),
        "roc_auc": test_evaluation.get("roc_auc"),
        "pr_auc": test_evaluation.get("pr_auc"),
        "false_positive_rate": test_evaluation.get("false_positive_rate"),
        "mean_reconstruction_error_benign": benign_stats.get("mean"),
        "median_reconstruction_error_benign": benign_stats.get("median"),
        "mean_reconstruction_error_attack": attack_stats.get("mean"),
        "median_reconstruction_error_attack": attack_stats.get("median"),
        "normal_samples": benign_stats.get("count"),
        "anomalous_samples": attack_stats.get("count"),
        "architecture": config.get("architecture"),
        "trained_at": config.get("trained_at") or training_report.get("trained_at"),
        "training_seconds": training_report.get("training_seconds"),
        "train_rows": training_report.get("train_rows"),
        "val_rows": training_report.get("val_rows"),
    }


def get_current_knn_metrics() -> dict:
    artifact_dir = settings.knn_model_path_absolute
    test_evaluation = _read_json(artifact_dir / "test_evaluation.json")
    if test_evaluation is None:
        return {
            "available": False,
            "reason": "KNN evaluation is unavailable until the model is implemented -- run `python -m ml.training.train_knn`.",
        }

    training_report = _read_json(artifact_dir / "training_report.json") or {}
    config = _read_json(artifact_dir / "config.json") or {}

    return {
        "available": True,
        "evaluation_label": "Supervised Classification Evaluation (Held-Out Test Set)",
        "positive_class_definition": test_evaluation.get("positive_class_definition"),
        "k": test_evaluation.get("k"),
        "weights": test_evaluation.get("weights"),
        "confusion_matrix": {k: test_evaluation.get(k) for k in ("tp", "tn", "fp", "fn")},
        "accuracy": test_evaluation.get("accuracy"),
        "primary_averaging_method": test_evaluation.get("primary_averaging_method"),
        "note_on_averaging": test_evaluation.get("note_on_averaging"),
        "precision_weighted": test_evaluation.get("precision_weighted"),
        "recall_weighted": test_evaluation.get("recall_weighted"),
        "f1_weighted": test_evaluation.get("f1_weighted"),
        "precision_macro": test_evaluation.get("precision_macro"),
        "recall_macro": test_evaluation.get("recall_macro"),
        "f1_macro": test_evaluation.get("f1_macro"),
        "roc_auc": test_evaluation.get("roc_auc"),
        "pr_auc": test_evaluation.get("pr_auc"),
        "training_time_seconds": test_evaluation.get("training_time_seconds"),
        "inference_time_seconds": test_evaluation.get("inference_time_seconds"),
        "inference_time_per_sample_ms": test_evaluation.get("inference_time_per_sample_ms"),
        "feature_count": config.get("feature_count"),
        "train_class_distribution": training_report.get("train_class_distribution"),
        "test_class_distribution": training_report.get("test_class_distribution"),
        "train_rows": training_report.get("train_rows"),
        "test_rows": training_report.get("test_rows"),
        "trained_at": config.get("trained_at") or training_report.get("trained_at"),
    }


def get_model_comparison(db: Session) -> dict:
    return {
        "autoencoder": get_current_autoencoder_metrics(),
        "knn": get_current_knn_metrics(),
        "comparability_note": (
            "The autoencoder is trained unsupervised (BENIGN-only reconstruction) to detect deviation from "
            "normal behavior; KNN is trained supervised (BENIGN vs ATTACK labels) to classify flows directly. "
            "Both are evaluated on the same held-out test split with the same positive-class convention "
            "(1=ATTACK, 0=BENIGN), so their confusion matrices are directly comparable, but the comparison "
            "illustrates two different detection strategies -- it is not an apples-to-apples model selection."
        ),
    }


def get_dataset_stats() -> dict:
    inspection = _read_json(RAW_DATA_DIR / "_inspection.json")
    cleaning_report = _read_json(PROCESSED_DATA_DIR / "_cleaning_report.json")
    if cleaning_report is None:
        return {"available": False, "reason": "No processed dataset found -- run `python -m ml.preprocessing.clean` first."}
    return {
        "available": True,
        "files_loaded": cleaning_report.get("files_loaded"),
        "rows_before_dedup": cleaning_report.get("rows_before_dedup"),
        "exact_duplicate_rows": cleaning_report.get("exact_duplicate_rows"),
        "rows_after_dedup": cleaning_report.get("rows_after_dedup"),
        "rows_after_inf_nan_handling": cleaning_report.get("rows_after_inf_nan_handling"),
        "label_distribution_before": cleaning_report.get("label_distribution_before"),
        "label_distribution_after": cleaning_report.get("label_distribution_after"),
        "split_sizes": cleaning_report.get("split_sizes"),
        "split_label_distribution": cleaning_report.get("split_label_distribution"),
        "raw_inspection_available": inspection is not None,
    }


def get_live_vs_offline_stats(db: Session) -> dict:
    live_event_count = db.query(func.count(Event.id)).filter(Event.source == EventSource.LIVE).scalar() or 0
    live_anomaly_count = (
        db.query(func.count(Detection.id))
        .join(Event, Detection.event_id == Event.id)
        .filter(Event.source == EventSource.LIVE, Detection.is_anomaly.is_(True))
        .scalar()
        or 0
    )
    live_avg_risk = (
        db.query(func.avg(RiskAssessment.risk_score))
        .join(Event, RiskAssessment.event_id == Event.id)
        .filter(Event.source == EventSource.LIVE)
        .scalar()
    )
    live_alert_count = (
        db.query(func.count(PreventionAction.id))
        .join(Event, PreventionAction.event_id == Event.id)
        .filter(Event.source == EventSource.LIVE, PreventionAction.actual_action == "alerted")
        .scalar()
        or 0
    )
    live_prevented_count = (
        db.query(func.count(PreventionAction.id))
        .join(Event, PreventionAction.event_id == Event.id)
        .filter(Event.source == EventSource.LIVE, PreventionAction.actual_action.in_(["blocked", "would_block"]))
        .scalar()
        or 0
    )

    return {
        "offline": {
            "label": "Offline Evaluation -- Held-Out Test Set (Ground Truth Available)",
            "autoencoder": get_current_autoencoder_metrics(),
            "knn": get_current_knn_metrics(),
        },
        "live": {
            "label": "Live Detection Statistics -- Loopback-Captured Events (No Ground Truth)",
            "total_live_events": live_event_count,
            "detected_anomalies": live_anomaly_count,
            "alerts": live_alert_count,
            "threats_prevented_or_would_block": live_prevented_count,
            "average_risk_score": float(live_avg_risk) if live_avg_risk is not None else None,
            "live_accuracy_note": LIVE_ACCURACY_NOTE,
        },
    }
