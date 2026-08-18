"""Unit tests for ml.training.train_autoencoder's helper functions
(BENIGN filtering, leakage checks, scaler-not-refit verification) and a
fast smoke test of the training loop itself, all on tiny synthetic
fixtures -- never the real dataset."""

import pickle

import numpy as np
import pandas as pd
import pytest
import torch
from sklearn.preprocessing import StandardScaler

from ml.models.autoencoder import AutoencoderConfig
from ml.training.train_autoencoder import (
    TrainingConfig,
    build_benign_training_set,
    run_leakage_checks,
    train_autoencoder,
    verify_scaler_not_refit,
)


def test_build_benign_training_set_filters_correctly():
    X = np.arange(15).reshape(5, 3).astype("float32")
    meta = pd.DataFrame({"canonical_label": ["BENIGN", "BENIGN", "DDoS", "BENIGN", "PortScan"]})

    X_benign, report = build_benign_training_set(X, meta)

    assert X_benign.shape == (3, 3)
    assert report["total_training_rows"] == 5
    assert report["benign_training_rows"] == 3
    assert report["attack_rows_excluded"] == 2
    assert report["final_training_matrix_shape"] == [3, 3]
    np.testing.assert_array_equal(X_benign, X[[0, 1, 3]])


def test_run_leakage_checks_passes_on_clean_feature_names():
    meta = pd.DataFrame({"canonical_label": ["BENIGN", "DDoS", "BENIGN"]})
    X_benign = np.zeros((2, 3))
    report = run_leakage_checks(["f1", "f2", "Destination Port"], meta, X_benign)

    assert report["5_no_attack_labels_as_input_features"]["passed"] is True
    assert report["6_no_metadata_columns_in_feature_matrix"]["passed"] is True
    assert report["6_no_metadata_columns_in_feature_matrix"]["leaked_columns_found"] == []


def test_run_leakage_checks_detects_leaked_metadata_column():
    meta = pd.DataFrame({"canonical_label": ["BENIGN"]})
    X_benign = np.zeros((1, 3))
    report = run_leakage_checks(["f1", "canonical_label", "source_file"], meta, X_benign)

    assert report["5_no_attack_labels_as_input_features"]["passed"] is False
    assert report["6_no_metadata_columns_in_feature_matrix"]["passed"] is False
    assert set(report["6_no_metadata_columns_in_feature_matrix"]["leaked_columns_found"]) == {
        "canonical_label",
        "source_file",
    }


def test_verify_scaler_not_refit_passes_for_identical_copy(tmp_path):
    rng = np.random.default_rng(0)
    scaler = StandardScaler().fit(rng.normal(size=(20, 3)))
    copy_path = tmp_path / "scaler.pkl"
    with open(copy_path, "wb") as f:
        pickle.dump(scaler, f)

    result = verify_scaler_not_refit(scaler, copy_path)
    assert result["passed"] is True


def test_verify_scaler_not_refit_detects_a_different_scaler(tmp_path):
    rng = np.random.default_rng(0)
    original = StandardScaler().fit(rng.normal(size=(20, 3)))
    refit_differently = StandardScaler().fit(rng.normal(loc=100, size=(20, 3)))
    copy_path = tmp_path / "scaler.pkl"
    with open(copy_path, "wb") as f:
        pickle.dump(refit_differently, f)

    result = verify_scaler_not_refit(original, copy_path)
    assert result["passed"] is False


def test_train_autoencoder_smoke_and_early_stopping_selects_best_val_loss():
    rng = np.random.default_rng(42)
    X_train = rng.normal(size=(200, 4)).astype("float32")
    X_val = rng.normal(size=(50, 4)).astype("float32")

    config = TrainingConfig(
        architecture=AutoencoderConfig(dims=[4, 3]),
        max_epochs=5,
        early_stopping_patience=5,
        batch_size=32,
        learning_rate=1e-2,
    )
    device = torch.device("cpu")

    model, history, epochs_run = train_autoencoder(X_train, X_val, config, device)

    assert 1 <= epochs_run <= config.max_epochs
    assert len(history) == epochs_run
    assert all("train_loss" in h and "val_loss" in h for h in history)

    # The returned model's weights must be the checkpoint with the lowest
    # recorded val_loss, not simply the last epoch's weights.
    val_tensor = torch.tensor(X_val, dtype=torch.float32)
    with torch.no_grad():
        recomputed_val_loss = float(torch.nn.functional.mse_loss(model(val_tensor), val_tensor))
    best_recorded = min(h["val_loss"] for h in history)
    assert recomputed_val_loss == pytest.approx(best_recorded, abs=1e-4)
