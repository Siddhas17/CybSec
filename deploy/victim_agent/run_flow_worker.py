"""One-shot manual CLI entry point for FlowScoringWorker.

Captures once (bounded, <=10s), reconstructs flows, submits up to 10 of
them to the Admin's POST /api/v1/agents/flow-score, prints a summary, and
exits. Contains no packet-capture, flow-reconstruction, feature-
extraction, or HTTP logic of its own -- it only sequences the existing
victim_agent.config / identity / agent / sender / flow_worker functions,
the same way victim_agent/agent.py itself does for the normal continuous
loop.

Run from this directory -- the one containing this file and the
victim_agent/ package (i.e. deploy/victim_agent/ once copied to the
Victim laptop):

    python run_flow_worker.py

This is NOT a continuous agent and NOT a scheduler: it calls
FlowScoringWorker.run_once() exactly one time and exits. For the normal
continuous registration/heartbeat/telemetry loop, use
`python -m victim_agent.agent` instead (see README.md).

Never prints the agent's bearer token, the enrollment key, or any other
credential -- only the (non-secret) agent_id and the worker's own
structured, payload-free result.
"""

from __future__ import annotations

import sys

from victim_agent.agent import ensure_registered
from victim_agent.config import load_config
from victim_agent.flow_worker import FlowScoringWorker, FlowWorkerRunResult
from victim_agent.identity import load_or_create_identity
from victim_agent.sender import AgentSender


def _format_summary(result: FlowWorkerRunResult) -> str:
    lines = [
        "=" * 78,
        "FLOW SCORING WORKER -- SINGLE BOUNDED RUN SUMMARY",
        "=" * 78,
        f"packets captured:    {result.packets_captured}",
        f"flows reconstructed: {result.flows_reconstructed}",
        f"flows considered:    {result.flows_considered}",
        f"flows submitted:     {result.flows_submitted}",
        f"flows failed:        {result.flows_failed}",
    ]

    if not result.outcomes:
        lines.append("")
        lines.append("(no flows to report -- zero packets captured or zero flows reconstructed)")
    else:
        lines.append("")
        lines.append("per-flow results:")
        for outcome in result.outcomes:
            flow = outcome.flow
            source_port = flow.source_port if flow.source_port is not None else "-"
            destination_port = flow.destination_port if flow.destination_port is not None else "-"
            header = f"  {flow.protocol} {flow.source_ip}:{source_port} -> {flow.destination_ip}:{destination_port}"
            if outcome.submitted:
                response = outcome.response or {}
                lines.append(
                    f"{header}  OK  risk_score={response.get('risk_score', '?')} "
                    f"risk_level={response.get('risk_level', '?')} anomaly={response.get('is_anomaly', '?')}"
                )
            else:
                lines.append(f"{header}  FAILED  reason={outcome.error}")

    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> int:
    print("Loading configuration (victim_agent/.env)...")
    try:
        config = load_config()
    except RuntimeError as exc:
        print(f"STOP -- configuration unavailable: {exc}")
        return 1

    identity = load_or_create_identity(config)
    print(f"agent_id: {identity.agent_id}")  # never the token

    sender = AgentSender(config)
    try:
        try:
            ensure_registered(config, identity, sender)
        except SystemExit:
            print(
                "STOP -- agent credentials are unavailable (registration did not succeed). "
                "Check ADMIN_BASE_URL/AGENT_ENROLLMENT_KEY in victim_agent/.env."
            )
            return 1

        if identity.token is None:
            print("STOP -- no agent token available after registration.")
            return 1

        worker = FlowScoringWorker(sender=sender, agent_id=identity.agent_id, token=identity.token)

        print("Running one bounded capture-and-submit cycle (<=10s capture, <=10 flows submitted)...")
        result = worker.run_once()
        print(_format_summary(result))
        return 0
    finally:
        sender.close()


if __name__ == "__main__":
    sys.exit(main())
