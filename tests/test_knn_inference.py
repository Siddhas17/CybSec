"""Unit tests for ml.models.knn_inference.KNNPredictor: model save/load
consistency, inference consistency after reload, and feature-order
validation. All against a tiny synthetic 3-feature fixture saved to
tmp_path -- never the real 67-feature model.

Critically, the fixture writes model.pkl with joblib.dump() -- exactly
what ml/training/train_knn.py's real save step does -- not plain pickle.
An earlier version of KNNPredictor.load() used pickle.load() for
model.pkl, which raised "invalid load key" against a real joblib-dumped
KNeighborsClassifier (joblib's on-disk format for large numpy-backed
estimators isn't plain-pickle-compatible); this only surfaced when the
real ~1.76M-row model was validated after training, not in earlier tests
that never exercised joblib's actual serialization. This module's fixture
must keep using joblib.dump(), not pickle.dump(), to guard against a
regression to plain pickle."""

import json
import pickle

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler

from ml.models.knn_inference import KNNPredictor

FEATURE_NAMES = ["f1", "f2", "f3"]


def _write_artifact_dir(tmp_path):
    rng = np.random.default_rng(42)
    X_benign = rng.normal(loc=0.0, scale=0.1, size=(20, 3))
    X_attack = rng.normal(loc=5.0, scale=0.1, size=(20, 3))
    X = np.vstack([X_benign, X_attack])
    y = np.array([0] * 20 + [1] * 20)

    model = KNeighborsClassifier(n_neighbors=3, weights="distance")
    model.fit(X, y)
    joblib.dump(model, tmp_path / "model.pkl")  # same format ml/training/train_knn.py actually writes

    scaler = StandardScaler().fit(rng.normal(size=(50, 3)))
    with open(tmp_path / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    (tmp_path / "feature_names.json").write_text(json.dumps(FEATURE_NAMES), encoding="utf-8")

    return model, scaler


def test_load_reads_a_joblib_dumped_model(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = KNNPredictor.load(tmp_path)

    assert predictor.feature_names == FEATURE_NAMES
    assert isinstance(predictor.model, KNeighborsClassifier)


def test_predict_single_row_returns_scalars(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = KNNPredictor.load(tmp_path)

    result = predictor.predict(np.array([0.0, 0.0, 0.0]))
    assert isinstance(result["predicted_class"], int)
    assert isinstance(result["predicted_label"], str)
    assert isinstance(result["attack_probability"], float)


def test_predict_batch_returns_arrays(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = KNNPredictor.load(tmp_path)

    result = predictor.predict(np.array([[0.0, 0.0, 0.0], [5.0, 5.0, 5.0]]))
    assert result["predicted_class"].shape == (2,)
    assert result["attack_probability"].shape == (2,)


def test_dataframe_input_reorders_columns_to_match_feature_names(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = KNNPredictor.load(tmp_path)

    ordered = pd.DataFrame([[0.0, 0.0, 0.0]], columns=["f1", "f2", "f3"])
    shuffled = pd.DataFrame([[0.0, 0.0, 0.0]], columns=["f3", "f1", "f2"])

    result_ordered = predictor.predict(ordered)
    result_shuffled = predictor.predict(shuffled)
    assert result_ordered["attack_probability"] == pytest.approx(result_shuffled["attack_probability"], abs=1e-9)


def test_dataframe_missing_required_column_raises(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = KNNPredictor.load(tmp_path)

    incomplete = pd.DataFrame([[1.0, 2.0]], columns=["f1", "f2"])
    with pytest.raises(ValueError, match="f3"):
        predictor.predict(incomplete)


def test_wrong_column_count_array_raises(tmp_path):
    _write_artifact_dir(tmp_path)
    predictor = KNNPredictor.load(tmp_path)

    with pytest.raises(ValueError):
        predictor.predict(np.array([1.0, 2.0]))
