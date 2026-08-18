"""Unit tests for risk_engine.normalize: each formula's bounds and
documented edge-case behavior."""

import pytest

from risk_engine.normalize import (
    anomaly_severity,
    attack_activity_norm,
    attack_context_norm,
    edge_attack_ratio_norm,
    temporal_persistence_norm,
)


def test_anomaly_severity_zero_score_is_zero():
    assert anomaly_severity(0.0, threshold=0.1) == 0.0


def test_anomaly_severity_at_threshold_is_documented_constant():
    # score == threshold -> 1 - e^-1
    assert anomaly_severity(0.1, threshold=0.1) == pytest.approx(1 - 2.718281828 ** -1, abs=1e-4)


def test_anomaly_severity_saturates_toward_one_for_extreme_scores():
    # A wildly heavy-tailed score (e.g. 87,376, the real BENIGN validation max)
    # must still land in [0,1] (never negative, never above 1) -- at this
    # magnitude score/threshold ~823,000, so exp() legitimately underflows
    # to exactly 0.0 in float64 and severity rounds to exactly 1.0; that's
    # correct saturation, not overflow.
    severity = anomaly_severity(87376.0, threshold=0.106125)
    assert 0.0 <= severity <= 1.0
    assert severity > 0.999


def test_anomaly_severity_monotonic_increasing():
    low = anomaly_severity(0.05, threshold=0.1)
    mid = anomaly_severity(0.1, threshold=0.1)
    high = anomaly_severity(1.0, threshold=0.1)
    assert low < mid < high


def test_anomaly_severity_rejects_negative_score():
    with pytest.raises(ValueError):
        anomaly_severity(-1.0, threshold=0.1)


def test_anomaly_severity_rejects_nonpositive_threshold():
    with pytest.raises(ValueError):
        anomaly_severity(1.0, threshold=0.0)


def test_edge_attack_ratio_norm_passthrough_and_missing():
    assert edge_attack_ratio_norm(0.5) == 0.5
    assert edge_attack_ratio_norm(None) == 0.0
    assert edge_attack_ratio_norm(1.2) == 1.0  # clipped
    assert edge_attack_ratio_norm(-0.1) == 0.0  # clipped


def test_attack_activity_norm_zero_and_missing():
    assert attack_activity_norm(0, activity_scale=100) == 0.0
    assert attack_activity_norm(None, activity_scale=100) == 0.0


def test_attack_activity_norm_saturates_at_scale():
    at_scale = attack_activity_norm(100, activity_scale=100)
    assert at_scale == pytest.approx(1.0, abs=1e-6)


def test_attack_activity_norm_beyond_scale_still_capped_at_one():
    assert attack_activity_norm(10_000_000, activity_scale=100) == 1.0


def test_temporal_persistence_norm_missing_timestamps():
    assert temporal_persistence_norm(None, "2017-07-04T00:00:00", temporal_scale_hours=96) == 0.0
    assert temporal_persistence_norm("2017-07-04T00:00:00", None, temporal_scale_hours=96) == 0.0


def test_temporal_persistence_norm_full_scale_saturates():
    result = temporal_persistence_norm("2017-07-03T00:00:00", "2017-07-07T00:00:00", temporal_scale_hours=96)
    assert result == pytest.approx(1.0, abs=1e-6)


def test_temporal_persistence_norm_half_scale():
    result = temporal_persistence_norm("2017-07-03T00:00:00", "2017-07-05T00:00:00", temporal_scale_hours=96)
    assert result == pytest.approx(0.5, abs=1e-6)


def test_attack_context_norm_missing_and_zero():
    assert attack_context_norm(None, attack_label_cap=3) == 0.0
    assert attack_context_norm(0, attack_label_cap=3) == 0.0


def test_attack_context_norm_saturates_at_cap():
    assert attack_context_norm(3, attack_label_cap=3) == 1.0
    assert attack_context_norm(10, attack_label_cap=3) == 1.0
    assert attack_context_norm(1, attack_label_cap=3) == pytest.approx(1 / 3)
