"""Pure-logic tests for the response policy (section 13's pure scenarios
1-3: no adapter, no DB, no network -- just risk_score -> decision)."""

from __future__ import annotations

import pytest

from backend.app.services.prevention.policy import ResponseDecision, ResponsePolicy


@pytest.fixture()
def policy() -> ResponsePolicy:
    return ResponsePolicy(alert_threshold=7.0, block_threshold=9.0)


def test_risk_below_alert_threshold_is_log_only(policy: ResponsePolicy) -> None:
    assert policy.decide(3.0) == ResponseDecision.LOG
    assert policy.decide(6.99) == ResponseDecision.LOG


def test_risk_at_or_above_alert_threshold_is_alert(policy: ResponsePolicy) -> None:
    assert policy.decide(7.0) == ResponseDecision.ALERT
    assert policy.decide(8.99) == ResponseDecision.ALERT


def test_risk_at_or_above_block_threshold_is_block_candidate(policy: ResponsePolicy) -> None:
    assert policy.decide(9.0) == ResponseDecision.BLOCK_CANDIDATE
    assert policy.decide(10.0) == ResponseDecision.BLOCK_CANDIDATE


def test_thresholds_are_configurable_not_hard_coded() -> None:
    strict = ResponsePolicy(alert_threshold=2.0, block_threshold=4.0)
    assert strict.decide(5.0) == ResponseDecision.BLOCK_CANDIDATE  # would be plain LOG under the default policy


def test_block_threshold_below_alert_threshold_is_rejected() -> None:
    with pytest.raises(ValueError):
        ResponsePolicy(alert_threshold=8.0, block_threshold=5.0)


def test_thresholds_outside_the_1_to_10_scale_are_rejected() -> None:
    with pytest.raises(ValueError):
        ResponsePolicy(alert_threshold=0.5, block_threshold=9.0)
    with pytest.raises(ValueError):
        ResponsePolicy(alert_threshold=7.0, block_threshold=11.0)
