"""Bounded, single-shot victim-agent flow capture-and-submit worker.

Wires together three already-proven, already-tested victim_agent building
blocks -- victim_agent.capture.capture_packets(), victim_agent.flow.
reconstruct_flows()/Flow.to_cicids_features(), and victim_agent.sender.
AgentSender.score_flow() -- into one reusable orchestration unit that can
run ONE bounded capture-and-submit cycle. This module contains zero packet
capture, flow reconstruction, feature-calculation, protocol-mapping, or
HTTP/auth logic of its own; it only sequences calls to the existing
modules and reports what happened.

Deliberately NOT wired into agent.py's main loop -- blocking packet
capture does not belong in that single-threaded heartbeat/telemetry/
retry-queue loop -- and deliberately NOT a scheduler: FlowScoringWorker.
run_once() performs exactly one bounded capture, converts whatever flows
result, and returns a structured result synchronously. No `while True`,
no threading/asyncio, no sleep. A later checkpoint decides how/whether to
call run_once() repeatedly; this module does not make that decision.

KNN, the attack graph, and prevention are never touched here -- the
backend's POST /agents/flow-score endpoint already owns graph-context
lookup and scoring (see backend.app.services.victim_agent_flow_bridge's
own docstring for why KNN stays out of every live-traffic path). This
worker only builds the same payload shape
scripts/validate_victim_agent_flow_submission.py already exercises
against a real backend, and submits it via the existing AgentSender.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from victim_agent.capture import capture_packets
from victim_agent.flow import Flow, reconstruct_flows
from victim_agent.sender import AgentSender, SenderError

logger = logging.getLogger(__name__)

# Hard ceiling on capture_duration_seconds -- matches the hard bound the
# existing manual validation scripts (scripts/validate_live_flow_risk.py,
# scripts/validate_victim_agent_flow_submission.py) already use for the
# same reason: a victim-agent capture cycle must never run unboundedly
# long. Enforced in FlowScoringWorker.__init__, not just documented -- a
# caller cannot construct a worker that violates it.
MAX_CAPTURE_DURATION_SECONDS = 10

# Conservative default cap on how many flows one run_once() call will
# submit over the network -- keeps a single bounded capture cycle from
# generating an unbounded number of outbound scoring requests.
DEFAULT_MAX_FLOWS_PER_RUN = 10

CaptureFn = Callable[..., list[Any]]
ReconstructFn = Callable[[Iterable[Any]], list[Flow]]


@dataclass(frozen=True)
class FlowSubmissionOutcome:
    """The result of attempting to score exactly one reconstructed flow.
    submitted=False always carries a non-None error -- every considered
    flow either produced a payload+response (submitted=True) or failed
    with a recorded reason, never a silent drop."""

    flow: Flow
    submitted: bool
    payload: dict | None = None
    response: dict | None = None
    error: str | None = None


@dataclass(frozen=True)
class FlowWorkerRunResult:
    """Structured summary of one FlowScoringWorker.run_once() call."""

    packets_captured: int
    flows_reconstructed: int
    flows_considered: int
    flows_submitted: int
    flows_failed: int
    outcomes: list[FlowSubmissionOutcome] = field(default_factory=list)


def _build_score_payload(flow: Flow) -> dict:
    """Builds exactly the payload POST /api/v1/agents/flow-score expects --
    the same shape scripts/validate_victim_agent_flow_submission.py's own
    _flow_payload() and victim_agent/tests/test_sender.py's
    _flow_score_payload() already use. Reuses Flow.to_cicids_features()
    unmodified; computes no CICIDS formula itself."""
    return {
        "source_ip": flow.source_ip,
        "destination_ip": flow.destination_ip,
        "source_port": flow.source_port,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol,
        "timestamp": flow.start_timestamp.isoformat(),
        "features": flow.to_cicids_features(),
    }


class FlowScoringWorker:
    """Performs one bounded capture-and-submit cycle via run_once().

    All dependencies are injected through the constructor -- no unrelated
    global application state (a config-module singleton, a module-level
    AgentSender, etc.) is constructed here. capture_fn/reconstruct_fn
    default to the real victim_agent.capture.capture_packets()/
    victim_agent.flow.reconstruct_flows(), overridable so tests never open
    Npcap or send real HTTP.
    """

    def __init__(
        self,
        sender: AgentSender,
        agent_id: str,
        token: str,
        capture_duration_seconds: int = MAX_CAPTURE_DURATION_SECONDS,
        max_flows_per_run: int = DEFAULT_MAX_FLOWS_PER_RUN,
        interface: Any | None = None,
        capture_fn: CaptureFn = capture_packets,
        reconstruct_fn: ReconstructFn = reconstruct_flows,
    ) -> None:
        if capture_duration_seconds <= 0:
            raise ValueError("capture_duration_seconds must be positive")
        if capture_duration_seconds > MAX_CAPTURE_DURATION_SECONDS:
            raise ValueError(f"capture_duration_seconds must not exceed the hard bound of {MAX_CAPTURE_DURATION_SECONDS}s")
        if max_flows_per_run <= 0:
            raise ValueError("max_flows_per_run must be positive")

        self._sender = sender
        self._agent_id = agent_id
        self._token = token
        self._capture_duration_seconds = capture_duration_seconds
        self._max_flows_per_run = max_flows_per_run
        self._interface = interface
        self._capture_fn = capture_fn
        self._reconstruct_fn = reconstruct_fn

    def run_once(self) -> FlowWorkerRunResult:
        """Captures for exactly self._capture_duration_seconds (bounded by
        the hard MAX_CAPTURE_DURATION_SECONDS ceiling enforced at
        construction), reconstructs flows via the existing flow module,
        submits at most self._max_flows_per_run of them through
        AgentSender.score_flow(), and returns a structured result.
        Executes synchronously and returns -- no loop, no scheduling,
        nothing left running in the background."""
        packets = self._capture_fn(duration_seconds=self._capture_duration_seconds, iface=self._interface)
        flows = self._reconstruct_fn(packets)
        considered = flows[: self._max_flows_per_run]

        outcomes = [self._submit_one(flow) for flow in considered]

        submitted = sum(1 for outcome in outcomes if outcome.submitted)
        return FlowWorkerRunResult(
            packets_captured=len(packets),
            flows_reconstructed=len(flows),
            flows_considered=len(considered),
            flows_submitted=submitted,
            flows_failed=len(outcomes) - submitted,
            outcomes=outcomes,
        )

    def _submit_one(self, flow: Flow) -> FlowSubmissionOutcome:
        """One flow's failure (feature extraction or submission) is
        recorded and never raised -- matching victim_agent's existing
        "one bad record must never abort the batch" convention (see
        capture.extract_packet_metadata(), flow.FlowTracker.add())."""
        try:
            payload = _build_score_payload(flow)
        except Exception as exc:  # noqa: BLE001 -- one bad flow must never abort the run
            logger.warning(
                "Skipping flow %s:%s -> %s:%s: feature extraction failed: %s",
                flow.source_ip, flow.source_port, flow.destination_ip, flow.destination_port, exc,
            )
            return FlowSubmissionOutcome(flow=flow, submitted=False, error=f"feature extraction failed: {exc}")

        try:
            response = self._sender.score_flow(payload, self._agent_id, self._token)
        except SenderError as exc:
            logger.warning(
                "Flow scoring submission failed for %s:%s -> %s:%s: %s",
                flow.source_ip, flow.source_port, flow.destination_ip, flow.destination_port, exc,
            )
            return FlowSubmissionOutcome(flow=flow, submitted=False, payload=payload, error=str(exc))

        return FlowSubmissionOutcome(flow=flow, submitted=True, payload=payload, response=response)
