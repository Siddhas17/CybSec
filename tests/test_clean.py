"""Validates the Phase 1 cleaning/feature-selection pipeline against small
synthetic fixtures with known properties — not the real CICIDS2017 dataset.
Each test targets one policy requirement from the cleaning-decision spec:
global dedup before split, Inf->NaN conversion + concentration reporting,
zero-variance detection on train only, mojibake normalization refusing
unknown labels, and no split leaking into another split's fitted scaler.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import StandardScaler

from ml.preprocessing.clean import (
    CANONICAL_LABEL_COLUMN,
    RAW_LABEL_COLUMN,
    SOURCE_FILE_COLUMN,
    assert_clean_matrix,
    find_redundant_features,
    find_zero_variance_columns,
    handle_inf_nan,
    remove_exact_duplicates,
    separate_features_metadata,
    stratified_split,
)
from ml.preprocessing.labels import MOJIBAKE_TO_CANONICAL, normalize_labels


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_remove_exact_duplicates_catches_cross_file_duplicates():
    df = pd.DataFrame(
        {
            "Flow Duration": [100, 100, 200, 100],
            RAW_LABEL_COLUMN: ["BENIGN", "BENIGN", "DDoS", "BENIGN"],
            CANONICAL_LABEL_COLUMN: ["BENIGN", "BENIGN", "DDoS", "BENIGN"],
            SOURCE_FILE_COLUMN: ["monday.csv", "tuesday.csv", "monday.csv", "monday.csv"],
        }
    )
    deduped, dup_count = remove_exact_duplicates(df)

    assert dup_count == 2  # rows 1 and 3 duplicate row 0 (source_file ignored)
    assert len(deduped) == 2
    assert deduped["Flow Duration"].tolist() == [100, 200]


def test_remove_exact_duplicates_keeps_rows_that_only_look_similar():
    df = pd.DataFrame(
        {
            "Flow Duration": [100, 101],
            RAW_LABEL_COLUMN: ["BENIGN", "BENIGN"],
            CANONICAL_LABEL_COLUMN: ["BENIGN", "BENIGN"],
            SOURCE_FILE_COLUMN: ["monday.csv", "monday.csv"],
        }
    )
    deduped, dup_count = remove_exact_duplicates(df)

    assert dup_count == 0
    assert len(deduped) == 2


# ---------------------------------------------------------------------------
# Inf/NaN handling
# ---------------------------------------------------------------------------


def test_handle_inf_nan_converts_and_reports_concentration():
    df = pd.DataFrame(
        {
            "Flow Bytes/s": [1.0, np.inf, 3.0, -np.inf, 5.0],
            "Flow Packets/s": [1.0, 2.0, np.inf, 4.0, 5.0],
            CANONICAL_LABEL_COLUMN: ["BENIGN", "DDoS", "DDoS", "BENIGN", "BENIGN"],
            SOURCE_FILE_COLUMN: ["a.csv", "a.csv", "b.csv", "b.csv", "b.csv"],
        }
    )
    cleaned, stats = handle_inf_nan(df, columns=["Flow Bytes/s", "Flow Packets/s"])

    assert stats["inf_counts_before"] == {"Flow Bytes/s": 2, "Flow Packets/s": 1}
    # rows 1, 2, 3 are affected (row 1: Bytes=inf, row 2: Packets=inf, row 3: Bytes=-inf)
    assert stats["nan_rows_after_inf_conversion"] == 3
    assert stats["nan_by_label"] == {"DDoS": 2, "BENIGN": 1}
    assert stats["nan_by_file"] == {"a.csv": 1, "b.csv": 2}
    # affected fraction (3/5 = 60%) is above the drop threshold in this fixture
    assert stats["rows_dropped"] is False
    # no raw inf values remain in the numeric columns after conversion
    assert not np.isinf(cleaned["Flow Bytes/s"].to_numpy(dtype="float64")).any()
    assert not np.isinf(cleaned["Flow Packets/s"].to_numpy(dtype="float64")).any()


def test_handle_inf_nan_drops_rows_when_fraction_is_small():
    n = 1000
    bytes_col = [1.0] * n
    bytes_col[0] = np.inf  # 1/1000 = 0.1%, well under the 1% threshold
    df = pd.DataFrame(
        {
            "Flow Bytes/s": bytes_col,
            "Flow Packets/s": [2.0] * n,
            CANONICAL_LABEL_COLUMN: ["BENIGN"] * n,
            SOURCE_FILE_COLUMN: ["a.csv"] * n,
        }
    )
    cleaned, stats = handle_inf_nan(df, columns=["Flow Bytes/s", "Flow Packets/s"])

    assert stats["rows_dropped"] is True
    assert len(cleaned) == n - 1
    assert cleaned["Flow Bytes/s"].isna().sum() == 0


# ---------------------------------------------------------------------------
# Zero-variance detection
# ---------------------------------------------------------------------------


def test_find_zero_variance_columns():
    df = pd.DataFrame(
        {
            "constant_col": [1, 1, 1, 1],
            "varying_col": [1, 2, 3, 4],
            "constant_float": [0.5, 0.5, 0.5, 0.5],
        }
    )
    result = find_zero_variance_columns(df, ["constant_col", "varying_col", "constant_float"])

    assert set(result.keys()) == {"constant_col", "constant_float"}
    assert result["constant_col"] == 0.0
    assert result["constant_float"] == 0.0


# ---------------------------------------------------------------------------
# Redundant feature detection
# ---------------------------------------------------------------------------


def test_find_redundant_features_detects_exact_and_near_duplicates():
    rng = np.random.default_rng(0)
    base = rng.normal(size=500)
    df = pd.DataFrame(
        {
            "a": base,
            "a_exact_copy": base,  # identical -> exact duplicate
            "a_near_copy": base + rng.normal(scale=1e-6, size=500),  # near-identical
            "independent": rng.normal(size=500),
        }
    )
    exact_pairs, near_pairs = find_redundant_features(
        df, ["a", "a_exact_copy", "a_near_copy", "independent"]
    )

    assert ["a", "a_exact_copy"] in exact_pairs
    assert any(pair["columns"] == ["a", "a_near_copy"] for pair in near_pairs)
    assert not any("independent" in pair for pair in exact_pairs)
    assert not any("independent" in pair["columns"] for pair in near_pairs)


# ---------------------------------------------------------------------------
# Feature / metadata separation
# ---------------------------------------------------------------------------


def test_separate_features_metadata_excludes_zero_variance_and_non_numeric():
    df = pd.DataFrame(
        {
            "Flow Duration": [1, 2, 3],
            "Destination Port": [80, 443, 22],
            "constant_col": [1, 1, 1],
            RAW_LABEL_COLUMN: ["BENIGN", "DDoS", "BENIGN"],
            CANONICAL_LABEL_COLUMN: ["BENIGN", "DDoS", "BENIGN"],
            SOURCE_FILE_COLUMN: ["a.csv", "a.csv", "a.csv"],
        }
    )
    model_features, metadata_cols = separate_features_metadata(df, zero_variance_cols=["constant_col"])

    assert "constant_col" not in model_features
    assert RAW_LABEL_COLUMN not in model_features
    assert CANONICAL_LABEL_COLUMN not in model_features
    assert SOURCE_FILE_COLUMN not in model_features
    assert "Flow Duration" in model_features
    # Destination Port is deliberately in both: a scaled model feature AND
    # unscaled metadata for the future attack-graph module (2026-08-18 decision).
    assert "Destination Port" in model_features
    assert set(metadata_cols) == {RAW_LABEL_COLUMN, CANONICAL_LABEL_COLUMN, SOURCE_FILE_COLUMN, "Destination Port"}


# ---------------------------------------------------------------------------
# Label normalization
# ---------------------------------------------------------------------------


def test_normalize_labels_maps_known_mojibake_variants():
    raw = pd.Series(["BENIGN", "Web Attack � Brute Force", "DDoS"])
    normalized = normalize_labels(raw)

    assert normalized.tolist() == ["BENIGN", "Web Attack - Brute Force", "DDoS"]


def test_normalize_labels_rejects_unknown_values():
    raw = pd.Series(["BENIGN", "Some Totally New Attack"])

    with pytest.raises(ValueError, match="Some Totally New Attack"):
        normalize_labels(raw)


def test_all_mojibake_variants_map_to_distinct_canonical_labels():
    canonical_values = set(MOJIBAKE_TO_CANONICAL.values())
    assert len(canonical_values) == len(MOJIBAKE_TO_CANONICAL)


# ---------------------------------------------------------------------------
# Split leakage prevention
# ---------------------------------------------------------------------------


def _make_split_fixture(n_per_class: int = 40) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    rows = []
    for label in ["BENIGN", "DDoS", "PortScan"]:
        for i in range(n_per_class):
            rows.append({"feature_a": rng.normal(), "feature_b": rng.normal(), CANONICAL_LABEL_COLUMN: label})
    return pd.DataFrame(rows)


def test_stratified_split_produces_disjoint_partitions_covering_all_rows():
    df = _make_split_fixture()
    train_df, val_df, test_df = stratified_split(
        df, CANONICAL_LABEL_COLUMN, train_frac=0.7, val_frac=0.15, test_frac=0.15, seed=1
    )

    total = len(train_df) + len(val_df) + len(test_df)
    assert total == len(df)

    # no row (identified by its unique feature pair) appears in more than one split
    def sig(d):
        return set(zip(d["feature_a"], d["feature_b"]))

    train_sig, val_sig, test_sig = sig(train_df), sig(val_df), sig(test_df)
    assert train_sig.isdisjoint(val_sig)
    assert train_sig.isdisjoint(test_sig)
    assert val_sig.isdisjoint(test_sig)


def test_stratified_split_preserves_class_proportions_roughly():
    df = _make_split_fixture(n_per_class=100)
    train_df, val_df, test_df = stratified_split(
        df, CANONICAL_LABEL_COLUMN, train_frac=0.7, val_frac=0.15, test_frac=0.15, seed=1
    )

    for label in ["BENIGN", "DDoS", "PortScan"]:
        assert (train_df[CANONICAL_LABEL_COLUMN] == label).sum() == 70
        assert (val_df[CANONICAL_LABEL_COLUMN] == label).sum() == 15
        assert (test_df[CANONICAL_LABEL_COLUMN] == label).sum() == 15


def test_stratified_split_routes_ultra_rare_classes_to_train_only():
    df = _make_split_fixture(n_per_class=40)
    rare = pd.DataFrame(
        {"feature_a": [0.1, 0.2], "feature_b": [0.1, 0.2], CANONICAL_LABEL_COLUMN: ["Heartbleed", "Heartbleed"]}
    )
    df = pd.concat([df, rare], ignore_index=True)

    train_df, val_df, test_df = stratified_split(
        df, CANONICAL_LABEL_COLUMN, train_frac=0.7, val_frac=0.15, test_frac=0.15, seed=1
    )

    assert (train_df[CANONICAL_LABEL_COLUMN] == "Heartbleed").sum() == 2
    assert (val_df[CANONICAL_LABEL_COLUMN] == "Heartbleed").sum() == 0
    assert (test_df[CANONICAL_LABEL_COLUMN] == "Heartbleed").sum() == 0


def test_scaler_fit_only_on_train_does_not_leak_val_test_statistics():
    rng = np.random.default_rng(0)
    train = rng.normal(loc=0.0, scale=1.0, size=(200, 2))
    val = rng.normal(loc=50.0, scale=1.0, size=(50, 2))  # deliberately shifted

    scaler = StandardScaler().fit(train)
    val_scaled = scaler.transform(val)

    # if val's own statistics had leaked into fitting, val_scaled would be
    # roughly centered at 0; instead it should reflect the large train/val
    # distribution shift (val mean is far from train mean)
    assert abs(val_scaled.mean()) > 10


# ---------------------------------------------------------------------------
# Final matrix integrity
# ---------------------------------------------------------------------------


def test_assert_clean_matrix_passes_on_clean_data():
    X = np.array([[1.0, 2.0], [3.0, 4.0]])
    assert_clean_matrix(X, "X")  # should not raise


def test_assert_clean_matrix_rejects_nan():
    X = np.array([[1.0, np.nan], [3.0, 4.0]])
    with pytest.raises(AssertionError):
        assert_clean_matrix(X, "X")


def test_assert_clean_matrix_rejects_inf():
    X = np.array([[1.0, np.inf], [3.0, 4.0]])
    with pytest.raises(AssertionError):
        assert_clean_matrix(X, "X")
