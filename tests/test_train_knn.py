"""Unit tests for ml.training.train_knn's helper functions (class
distribution, leakage checks) and a fast smoke test of KNN fit/predict on a
tiny, clearly-separable synthetic fixture -- never the real dataset."""

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from ml.models.knn import KNNConfig, build_knn
from ml.training.train_autoencoder import BENIGN_LABEL
from ml.training.train_knn import class_distribution, run_leakage_checks


def test_class_distribution_counts_and_percentages():
    meta = pd.DataFrame({"canonical_label": ["BENIGN", "BENIGN", "BENIGN", "DDoS"]})
    dist = class_distribution(meta)

    assert dist["benign_count"] == 3
    assert dist["attack_count"] == 1
    assert dist["total_count"] == 4
    assert dist["benign_pct"] == 75.0
    assert dist["attack_pct"] == 25.0


def test_run_leakage_checks_passes_on_clean_feature_names():
    meta_train = pd.DataFrame({"canonical_label": ["BENIGN", "DDoS", "BENIGN"]})
    meta_test = pd.DataFrame({"canonical_label": ["BENIGN", "PortScan"]})
    report = run_leakage_checks(["f1", "f2", "Destination Port"], meta_train, meta_test)

    assert report["1_no_metadata_columns_in_feature_matrix"]["passed"] is True
    assert report["1_no_metadata_columns_in_feature_matrix"]["leaked_columns_found"] == []
    assert report["4_test_split_used_only_for_final_evaluation"]["train_rows"] == 3
    assert report["4_test_split_used_only_for_final_evaluation"]["test_rows"] == 2


def test_run_leakage_checks_detects_leaked_metadata_column():
    meta_train = pd.DataFrame({"canonical_label": ["BENIGN"]})
    meta_test = pd.DataFrame({"canonical_label": ["BENIGN"]})
    report = run_leakage_checks(["f1", "canonical_label", "source_file"], meta_train, meta_test)

    assert report["1_no_metadata_columns_in_feature_matrix"]["passed"] is False
    assert set(report["1_no_metadata_columns_in_feature_matrix"]["leaked_columns_found"]) == {
        "canonical_label",
        "source_file",
    }


def test_knn_fit_predict_matches_sklearn_reference_on_separable_data():
    """Two well-separated clusters -- BENIGN near 0, ATTACK near 10 -- so
    K=3 nearest-neighbor classification should be perfect, and the
    train_knn module's own metric computation (accuracy/precision/recall/f1
    via sklearn) must match sklearn's reference functions called directly."""
    import numpy as np

    rng = np.random.default_rng(0)
    X_benign = rng.normal(loc=0.0, scale=0.1, size=(30, 4))
    X_attack = rng.normal(loc=10.0, scale=0.1, size=(30, 4))
    X_train = np.vstack([X_benign, X_attack])
    y_train = np.array([0] * 30 + [1] * 30)

    X_test = np.vstack([rng.normal(loc=0.0, scale=0.1, size=(10, 4)), rng.normal(loc=10.0, scale=0.1, size=(10, 4))])
    y_test = np.array([0] * 10 + [1] * 10)

    config = KNNConfig(n_neighbors=3)
    model = build_knn(config)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    assert (tp, tn, fp, fn) == (10, 10, 0, 0)
    assert accuracy_score(y_test, y_pred) == 1.0
    assert precision_score(y_test, y_pred, average="weighted") == 1.0
    assert recall_score(y_test, y_pred, average="weighted") == 1.0
    assert f1_score(y_test, y_pred, average="weighted") == 1.0
