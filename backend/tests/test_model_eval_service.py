"""Unit tests for model_eval_service.sync_training_run's hash-and-insert-
if-changed logic, using tmp_path fixture JSON (this only tests the sync
mechanism itself against controlled inputs -- real metric correctness is
the training script's own concern, exercised separately when it's run
against the real dataset)."""

from __future__ import annotations

import json

from backend.app.core.config import settings
from backend.app.models.training_run import TrainingRun
from backend.app.services import model_eval_service


def _write_autoencoder_artifacts(artifact_dir, precision=0.7, run_id="run-1"):
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "config.json").write_text(
        json.dumps({"architecture": {"dims": [67, 32, 16]}, "run_id": run_id, "trained_at": "2026-01-01T00:00:00+00:00"})
    )
    (artifact_dir / "training_report.json").write_text(json.dumps({"train_rows": 100, "val_rows": 20, "training_seconds": 1.0}))
    (artifact_dir / "threshold.json").write_text(json.dumps({"selected_threshold": 0.1, "selected_strategy": "percentile"}))
    (artifact_dir / "test_evaluation.json").write_text(
        json.dumps(
            {
                "tp": 1,
                "tn": 2,
                "fp": 3,
                "fn": 4,
                "precision": precision,
                "recall": 0.5,
                "f1": 0.6,
                "roc_auc": 0.9,
                "pr_auc": 0.8,
                "false_positive_rate": 0.1,
            }
        )
    )
    (artifact_dir / "feature_names.json").write_text(json.dumps(["f1", "f2"]))


def test_sync_training_run_inserts_a_new_row(db_session, monkeypatch, tmp_path):
    artifact_dir = tmp_path / "autoencoder"
    _write_autoencoder_artifacts(artifact_dir)
    monkeypatch.setattr(settings, "model_path", str(artifact_dir))

    run = model_eval_service.sync_training_run(db_session, "autoencoder")

    assert run is not None
    assert run.component == "autoencoder"
    assert run.metrics["precision"] == 0.7
    assert run.confusion_matrix == {"tp": 1, "tn": 2, "fp": 3, "fn": 4}
    assert db_session.query(TrainingRun).count() == 1


def test_sync_training_run_is_a_noop_when_unchanged(db_session, monkeypatch, tmp_path):
    artifact_dir = tmp_path / "autoencoder"
    _write_autoencoder_artifacts(artifact_dir)
    monkeypatch.setattr(settings, "model_path", str(artifact_dir))

    first = model_eval_service.sync_training_run(db_session, "autoencoder")
    second = model_eval_service.sync_training_run(db_session, "autoencoder")

    assert first is not None
    assert second is None
    assert db_session.query(TrainingRun).count() == 1


def test_sync_training_run_inserts_a_second_row_when_content_changes(db_session, monkeypatch, tmp_path):
    artifact_dir = tmp_path / "autoencoder"
    _write_autoencoder_artifacts(artifact_dir, precision=0.7)
    monkeypatch.setattr(settings, "model_path", str(artifact_dir))
    first = model_eval_service.sync_training_run(db_session, "autoencoder")

    _write_autoencoder_artifacts(artifact_dir, precision=0.9, run_id="run-2")  # simulates a retrain, fresh run_id like the real training script generates
    second = model_eval_service.sync_training_run(db_session, "autoencoder")

    assert first is not None
    assert second is not None
    assert first.id != second.id
    assert second.metrics["precision"] == 0.9
    assert db_session.query(TrainingRun).count() == 2


def test_sync_training_run_returns_none_when_untrained(db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "knn_model_path", str(tmp_path / "does-not-exist"))

    run = model_eval_service.sync_training_run(db_session, "knn")

    assert run is None
    assert db_session.query(TrainingRun).count() == 0
