"""Unit tests for ml.evaluation.threshold_analysis using synthetic,
clearly-separable BENIGN/ATTACK reconstruction-error distributions so the
expected threshold and metrics are known in advance."""

import numpy as np

from ml.evaluation.threshold_analysis import (
    compare_threshold_strategies,
    evaluate_threshold,
    pr_auc,
    roc_auc,
    threshold_from_mean_std,
    threshold_from_percentile,
    threshold_from_pr,
    threshold_from_roc,
)

BENIGN_ERRORS = np.linspace(0.0, 1.0, 100)
ATTACK_ERRORS = np.linspace(5.0, 10.0, 50)
Y_TRUE = np.concatenate([np.zeros(100), np.ones(50)]).astype(int)
SCORES = np.concatenate([BENIGN_ERRORS, ATTACK_ERRORS])


def test_threshold_from_percentile():
    t = threshold_from_percentile(BENIGN_ERRORS, percentile=95.0)
    assert 0.9 < t < 1.0


def test_threshold_from_mean_std_stays_below_attack_range():
    t = threshold_from_mean_std(BENIGN_ERRORS, k=3.0)
    assert t < ATTACK_ERRORS.min()
    assert t > BENIGN_ERRORS.max() * 0.5  # sanity: not a degenerate near-zero threshold


def test_threshold_from_roc_perfectly_separates_classes():
    t = threshold_from_roc(Y_TRUE, SCORES)
    assert BENIGN_ERRORS.max() <= t <= ATTACK_ERRORS.min()


def test_threshold_from_pr_perfectly_separates_classes():
    t = threshold_from_pr(Y_TRUE, SCORES)
    assert BENIGN_ERRORS.max() <= t <= ATTACK_ERRORS.min()


def test_evaluate_threshold_perfect_separation():
    metrics = evaluate_threshold(Y_TRUE, SCORES, threshold=3.0)
    assert metrics["tp"] == 50
    assert metrics["tn"] == 100
    assert metrics["fp"] == 0
    assert metrics["fn"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["false_positive_rate"] == 0.0


def test_evaluate_threshold_all_flagged_as_anomaly():
    metrics = evaluate_threshold(Y_TRUE, SCORES, threshold=-1.0)  # everything >= threshold
    assert metrics["tp"] == 50
    assert metrics["fp"] == 100
    assert metrics["tn"] == 0
    assert metrics["fn"] == 0
    assert metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 1.0


def test_compare_threshold_strategies_returns_all_four():
    result = compare_threshold_strategies(BENIGN_ERRORS, Y_TRUE, SCORES)
    assert set(result.keys()) == {"percentile", "mean_std", "roc", "pr"}
    for strategy_result in result.values():
        assert "threshold" in strategy_result
        assert "precision" in strategy_result
        assert "recall" in strategy_result
        assert "f1" in strategy_result


def test_roc_auc_and_pr_auc_near_perfect_for_separable_classes():
    assert roc_auc(Y_TRUE, SCORES) == 1.0
    assert pr_auc(Y_TRUE, SCORES) == 1.0
