"""Unit tests for ml.models.inference.AutoencoderPredictor: model
save/load consistency, inference consistency after reload, threshold
application, and feature-order validation. All against a tiny synthetic
3-feature fixture saved to tmp_path -- never the real 67-feature model."""

import json
import pickle

import numpy as np
import pandas as pd
import pytest
import torch
from sklearn.preprocessing import StandardScaler

from ml.models.autoencoder import Autoencoder, AutoencoderConfig, reconstruction_error
from ml.models.inference import AutoencoderPredictor

FEATURE_NAMES = ["f1", "f2", "f3"]


def _write_artifact_dir(tmp_path, threshold=0.5):
    config = AutoencoderConfig(dims=[3, 2])
    model = Autoencoder(config)
    torch.save(model.state_dict(), tmp_path / "best_model.pt")

    rng = np.random.default_rng(42)
    scaler = StandardScaler().fit(rng.normal(size=(50, 3)))
    with open(tmp_path / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    (tmp_path / "config.json").write_text(json.dumps({"architecture": config.to_dict()}), encoding="utf-8")
    (tmp_path / "feature_names.json").write_text(json.dumps(FEATURE_NAMES), encoding="utf-8")
    (tmp_path / "threshold.json").write_text(json.dumps({"selected_threshold": threshold}), encoding="utf-8")

    return model, scaler, config


def test_load_reconstructs_matching_config(tmp_path):
    _, _, config = _write_artifact_dir(tmp_path)
    predictor = AutoencoderPredictor.load(tmp_path)

    assert predictor.feature_names == FEATURE_NAMES
    assert predictor.threshold == 0.5
    assert predictor.model.config.dims == config.dims


def test_save_load_gives_identical_reconstruction_error(tmp_path):
    model, scaler, _ = _write_artifact_dir(tmp_path)
    predictor = AutoencoderPredictor.load(tmp_path)

    raw = np.array([[1.0, 2.0, 3.0]])
    expected_error = float(
        reconstruction_error(model, torch.tensor(scaler.transform(raw), dtype=torch.float32))[0]
    )

    result = predictor.predict(raw[0])
    assert result["reconstruction_error"] == pytest.approx(expected_error, abs=1e-5)
    assert result["anomaly_score"] == pytest.approx(expected_error, abs=1e-5)


def test_predict_single_row_returns_scalars(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = AutoencoderPredictor.load(tmp_path)

    result = predictor.predict(np.array([1.0, 2.0, 3.0]))
    assert isinstance(result["reconstruction_error"], float)
    assert isinstance(result["anomaly_score"], float)
    assert isinstance(result["is_anomaly"], bool)


def test_predict_batch_returns_arrays(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = AutoencoderPredictor.load(tmp_path)

    result = predictor.predict(np.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]))
    assert result["reconstruction_error"].shape == (2,)
    assert result["is_anomaly"].shape == (2,)


def test_threshold_application_flips_is_anomaly(tmp_path):
    _write_artifact_dir(tmp_path, threshold=1e9)  # unreachable -> never anomalous
    high_threshold_predictor = AutoencoderPredictor.load(tmp_path)
    result_low = high_threshold_predictor.predict(np.array([1.0, 2.0, 3.0]))
    assert result_low["is_anomaly"] is False

    _write_artifact_dir(tmp_path, threshold=-1e9)  # always exceeded -> always anomalous
    low_threshold_predictor = AutoencoderPredictor.load(tmp_path)
    result_high = low_threshold_predictor.predict(np.array([1.0, 2.0, 3.0]))
    assert result_high["is_anomaly"] is True


def test_dataframe_input_reorders_columns_to_match_feature_names(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = AutoencoderPredictor.load(tmp_path)

    ordered = pd.DataFrame([[1.0, 2.0, 3.0]], columns=["f1", "f2", "f3"])
    shuffled = pd.DataFrame([[3.0, 1.0, 2.0]], columns=["f3", "f1", "f2"])  # same row, different column order

    result_ordered = predictor.predict(ordered)
    result_shuffled = predictor.predict(shuffled)
    assert result_ordered["reconstruction_error"] == pytest.approx(result_shuffled["reconstruction_error"], abs=1e-6)


def test_dataframe_missing_required_column_raises(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = AutoencoderPredictor.load(tmp_path)

    incomplete = pd.DataFrame([[1.0, 2.0]], columns=["f1", "f2"])
    with pytest.raises(ValueError, match="f3"):
        predictor.predict(incomplete)


def test_wrong_column_count_array_raises(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = AutoencoderPredictor.load(tmp_path)

    with pytest.raises(ValueError):
        predictor.predict(np.array([1.0, 2.0]))
