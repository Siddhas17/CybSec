"""Unit tests for model_validation.validate_autoencoder/validate_knn --
missing-artifact fixtures verify a model is never shown 'valid' when it
cannot actually be loaded or run inference, and the real committed
artifacts confirm validation genuinely exercises inference rather than
always reporting success (same reuse-real-artifacts convention documented
in conftest.py)."""

from __future__ import annotations

from backend.app.core.config import settings
from backend.app.services import model_validation


def test_validate_autoencoder_fails_when_artifact_dir_is_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "model_path", str(tmp_path / "empty"))

    result = model_validation.validate_autoencoder()

    assert result["component"] == "autoencoder"
    assert result["valid"] is False
    checks = {c["name"]: c for c in result["checks"]}
    assert checks["model_file_exists"]["passed"] is False
    assert "MISSING" in checks["model_file_exists"]["detail"]
    assert checks["can_perform_inference"]["passed"] is False


def test_validate_knn_fails_when_artifact_dir_is_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "knn_model_path", str(tmp_path / "empty"))

    result = model_validation.validate_knn()

    assert result["component"] == "knn"
    assert result["valid"] is False
    checks = {c["name"]: c for c in result["checks"]}
    assert checks["model_file_exists"]["passed"] is False


def test_validate_autoencoder_passes_against_the_real_trained_artifacts():
    result = model_validation.validate_autoencoder()

    assert result["valid"] is True
    checks = {c["name"]: c["passed"] for c in result["checks"]}
    assert checks["can_perform_inference"] is True
