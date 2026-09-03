"""Validates that a trained model is actually usable before the dashboard
shows it as "ACTIVE" -- checks required artifact files exist, then performs
a real inference call so a corrupted/incompatible artifact fails loudly
with its real error rather than the dashboard silently claiming a model is
active when it cannot actually score anything."""

from __future__ import annotations

import numpy as np

from backend.app.core.config import settings
from backend.app.services import model_registry


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _validate(component: str, artifact_dir, required_files: dict[str, str], get_predictor, real_prediction_note: str) -> dict:
    checks = []
    for check_name, filename in required_files.items():
        path = artifact_dir / filename
        exists = path.exists()
        checks.append(_check(check_name, exists, f"{path} {'found' if exists else 'MISSING'}"))

    evaluation_path = artifact_dir / "test_evaluation.json"
    exists = evaluation_path.exists()
    checks.append(_check("evaluation_results_exist", exists, f"{evaluation_path} {'found' if exists else 'MISSING'}"))

    if all(c["passed"] for c in checks):
        try:
            get_predictor.cache_clear()  # force a fresh load from disk, not a stale in-memory copy
            predictor = get_predictor()
            dummy = np.zeros((1, len(predictor.feature_names)))
            predictor.predict(dummy)
            checks.append(_check("can_perform_inference", True, real_prediction_note))
        except Exception as exc:  # noqa: BLE001 -- surfacing the real error to the admin is the point
            checks.append(_check("can_perform_inference", False, f"Inference failed: {exc}"))
    else:
        checks.append(_check("can_perform_inference", False, "Skipped -- required artifact file(s) missing."))

    return {"component": component, "valid": all(c["passed"] for c in checks), "checks": checks}


def validate_autoencoder() -> dict:
    required_files = {
        "model_file_exists": "best_model.pt",
        "preprocessing_pipeline_exists": "scaler.pkl",
        "feature_list_exists": "feature_names.json",
        "threshold_exists": "threshold.json",
        "config_exists": "config.json",
    }
    return _validate(
        "autoencoder",
        settings.model_path_absolute,
        required_files,
        model_registry.get_predictor,
        "Ran a real forward pass on a zero-vector input without error.",
    )


def validate_knn() -> dict:
    required_files = {
        "model_file_exists": "model.pkl",
        "preprocessing_pipeline_exists": "scaler.pkl",
        "feature_list_exists": "feature_names.json",
        "config_exists": "config.json",
    }
    return _validate(
        "knn",
        settings.knn_model_path_absolute,
        required_files,
        model_registry.get_knn_predictor,
        "Ran a real prediction on a zero-vector input without error.",
    )
