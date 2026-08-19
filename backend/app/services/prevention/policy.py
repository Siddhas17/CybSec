"""Response policy (section 4 of the phase instructions): a pure,
deterministic mapping from risk score to a response decision. No network
access, no database access, no dependency on a response adapter -- this
module cannot itself take an action, only decide what should happen.

Thresholds are on the existing 1-10 risk_engine scale
(risk_engine.config.RISK_LEVELS) and are NOT claimed to be objectively
correct -- see docs/prevention.md "Response thresholds" for the documented
rationale. `ALERT` begins at the same "High" boundary already used
elsewhere in this project (risk_engine.config.HIGH_RISK_THRESHOLD,
sensor's own live_sensor_service.HIGH_RISK_FLAG_THRESHOLD, both 7.0) for
consistency rather than introducing a fourth unrelated magic number.
`BLOCK_CANDIDATE` begins one bucket further in, inside "Critical" rather
than at its outer 8.0 edge, because blocking is a stronger action than
alerting and deliberately asks for a stronger signal than merely crossing
into the highest labeled risk bucket.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ResponseDecision(str, enum.Enum):
    LOG = "log"
    ALERT = "alert"
    BLOCK_CANDIDATE = "block_candidate"


@dataclass(frozen=True)
class ResponsePolicy:
    alert_threshold: float = 7.0
    block_threshold: float = 9.0

    def __post_init__(self) -> None:
        if not (1.0 <= self.alert_threshold <= 10.0):
            raise ValueError(f"alert_threshold must be within the risk engine's 1-10 scale, got {self.alert_threshold}")
        if not (1.0 <= self.block_threshold <= 10.0):
            raise ValueError(f"block_threshold must be within the risk engine's 1-10 scale, got {self.block_threshold}")
        if self.block_threshold < self.alert_threshold:
            raise ValueError("block_threshold must be >= alert_threshold -- blocking is a strictly stronger response than alerting")

    def decide(self, risk_score: float) -> ResponseDecision:
        if risk_score >= self.block_threshold:
            return ResponseDecision.BLOCK_CANDIDATE
        if risk_score >= self.alert_threshold:
            return ResponseDecision.ALERT
        return ResponseDecision.LOG
