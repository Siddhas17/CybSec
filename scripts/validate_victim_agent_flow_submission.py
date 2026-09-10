"""Bounded end-to-end validation: Npcap capture -> victim_agent.flow ->
AgentSender.score_flow() -> POST /api/v1/agents/flow-score -> real backend
Autoencoder + Attack Graph + Risk Engine -> returned 1-10 risk result.

VALIDATION PROTOTYPE ONLY -- not wired into victim_agent/agent.py's normal
loop. Run standalone from the project root:

    python scripts/validate_victim_agent_flow_submission.py

Reuses the project-root .env's AGENT_ENROLLMENT_KEY directly (via
load_config()'s existing env_file parameter -- config.py itself is
unmodified) instead of requiring a second victim_agent/.env copy of the
same secret: this script always runs on the same machine as the backend
it validates against, so there is no separate-machine trust boundary to
preserve here the way there is for a real victim_agent deployment.
ADMIN_BASE_URL is not a secret and is set directly below (always
http://127.0.0.1:8000 for this co-located validation tool) rather than
sourced from either .env, since the project-root .env has no reason to
define it (that concept only makes sense from a remote agent's point of
view) and duplicating it in a second file would defeat the point of this
change. This is a deliberate divergence from the real, documented,
separate-machine victim_agent deployment model (victim_agent/.env.example:
"the victim laptop this runs on has no access to [the Admin's project-root
.env] at all") -- that model remains correct and necessary for an actual
victim laptop; it just doesn't apply to a same-machine validation script.
It reuses the same victim_agent.config.load_config() / victim_agent.
identity.load_or_create_identity() / victim_agent.agent.ensure_registered()
the real agent.py already uses (imported, not duplicated), so the identity
this script uses -- and persists to the same .agent_identity.json -- is
produced by the exact same mechanism, not a second one.

It:
  - discovers the Wi-Fi interface via capture.find_wifi_interface() (never
    hardcoded),
  - captures for a hard-bounded <=10 seconds (capture.capture_packets(),
    which already calls extract_packet_metadata() per packet -- payload-
    free by construction; nothing raw is ever stored or transmitted),
  - reconstructs flows via flow.reconstruct_flows() (victim_agent.flow's
    own FlowTracker),
  - for at most MAX_FLOWS_TO_SUBMIT (10) valid flows, builds the exact
    payload POST /api/v1/agents/flow-score expects (source_ip,
    destination_ip, ports, protocol, timestamp, the 67-name
    Flow.to_cicids_features() dict) and submits it via the existing
    AgentSender.score_flow() -- the same bounded-retry HTTP client and
    machine-auth headers every other agent request already uses.

Never invokes KNN or the prevention layer -- this script never imports
either. Never persists anything locally beyond the identity file
load_or_create_identity() already manages; all other output is console
only. The only backend-side state change from a successful run is the
same agents.last_seen touch every authenticated agent request already
causes (get_current_agent's existing side effect, not something this
script adds).
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from victim_agent import capture, flow  # noqa: E402
from victim_agent.agent import ensure_registered  # noqa: E402
from victim_agent.config import load_config  # noqa: E402
from victim_agent.identity import load_or_create_identity  # noqa: E402
from victim_agent.sender import AgentSender, SenderError  # noqa: E402

CAPTURE_DURATION_SECONDS = 10  # hard bound -- not configurable from the CLI
MAX_FLOWS_TO_SUBMIT = 10  # hard bound on outbound scoring requests

# Not a secret -- this script only ever talks to the backend co-located on
# this same machine. setdefault() so a real operator's own exported
# ADMIN_BASE_URL (if any) still wins, matching config.py's own documented
# "(or the real process environment)" fallback.
_LOCAL_ADMIN_BASE_URL = "http://127.0.0.1:8000"


def _flow_payload(f: flow.Flow) -> dict:
    return {
        "source_ip": f.source_ip,
        "destination_ip": f.destination_ip,
        "source_port": f.source_port,
        "destination_port": f.destination_port,
        "protocol": f.protocol,
        "timestamp": f.start_timestamp.isoformat(),
        "features": f.to_cicids_features(),
    }


def _is_valid_feature_vector(features: dict) -> bool:
    if len(features) != 67 or list(features.keys()) != list(flow.CICIDS_FEATURE_NAMES):
        return False
    return not any(not isinstance(v, (int, float)) or isinstance(v, bool) or math.isnan(v) or math.isinf(v) for v in features.values())


def main() -> None:
    print("=" * 78)
    print(f"VICTIM-AGENT FLOW SUBMISSION VALIDATION (<= {CAPTURE_DURATION_SECONDS}s capture, <= {MAX_FLOWS_TO_SUBMIT} flows submitted)")
    print("=" * 78)

    print("\n[1] load configuration + identity (project-root .env for AGENT_ENROLLMENT_KEY -- no duplicate secret)")
    os.environ.setdefault("ADMIN_BASE_URL", _LOCAL_ADMIN_BASE_URL)
    try:
        config = load_config(env_file=PROJECT_ROOT / ".env")
    except RuntimeError as exc:
        print(f"STOP -- configuration unavailable: {exc}")
        return
    identity = load_or_create_identity(config)
    print(f"    agent_id: {identity.agent_id}")

    sender = AgentSender(config)
    try:
        print("\n[2] ensure the agent is registered (existing agent.py logic, reused -- not duplicated)")
        try:
            ensure_registered(config, identity, sender)
        except SystemExit:
            print("STOP -- agent credentials are unavailable (no local token and registration did not succeed).")
            return
        if identity.token is None:
            print("STOP -- agent credentials are unavailable after ensure_registered().")
            return
        print("    credentials available (agent token present locally; never printed)")

        print("\n[3] interface discovery (victim_agent.capture.find_wifi_interface())")
        try:
            iface = capture.find_wifi_interface()
        except capture.CaptureError as exc:
            print(f"STOP -- interface discovery failed: {exc}")
            return
        print(f"    interface: {getattr(iface, 'name', '?')} (ip={getattr(iface, 'ip', '?')})")

        print(f"\n[4] bounded capture (<= {CAPTURE_DURATION_SECONDS}s)")
        try:
            packets = capture.capture_packets(duration_seconds=CAPTURE_DURATION_SECONDS, iface=iface)
        except capture.CaptureError as exc:
            print(f"STOP -- capture failed: {exc}")
            return
        print(f"    packets captured (payload-free metadata only): {len(packets)}")

        print("\n[5] flow reconstruction (victim_agent.flow.reconstruct_flows())")
        flows = flow.reconstruct_flows(packets)
        print(f"    flows reconstructed: {len(flows)}")

        to_submit = flows[:MAX_FLOWS_TO_SUBMIT]
        if len(flows) > MAX_FLOWS_TO_SUBMIT:
            print(f"    submitting only the first {MAX_FLOWS_TO_SUBMIT} (bounded, per validation-script safety limit)")

        print("\n[6] score each flow via AgentSender.score_flow() -> POST /agents/flow-score")
        submitted = 0
        successful = 0
        skipped = 0
        example_result: dict | None = None

        for f in to_submit:
            try:
                features = f.to_cicids_features()
            except Exception:
                skipped += 1
                continue
            if not _is_valid_feature_vector(features):
                skipped += 1
                continue

            sport = f.source_port if f.source_port is not None else "-"
            dport = f.destination_port if f.destination_port is not None else "-"
            header = f"    {f.protocol} {f.source_ip}:{sport} -> {f.destination_ip}:{dport} dur={f.duration_seconds:.3f}s pkts={f.total_packets}"

            submitted += 1
            try:
                result = sender.score_flow(_flow_payload(f), identity.agent_id, identity.token)
            except SenderError as exc:
                print(f"{header}  ==> SCORING FAILED: {exc}")
                continue

            successful += 1
            print(f"{header}  ==> risk_score={result.get('risk_score')} risk_level={result.get('risk_level')} anomaly={result.get('is_anomaly')}")
            if example_result is None:
                example_result = {"flow": header.strip(), **result}

        print("\n" + "=" * 78)
        print("SUMMARY")
        print(f"  packets captured:          {len(packets)}")
        print(f"  flows reconstructed:       {len(flows)}")
        print(f"  flows submitted:           {submitted}")
        print(f"  successful scoring calls:  {successful}")
        print(f"  skipped (invalid vector):  {skipped}")
        print(f"  example result: {example_result if example_result else '(none)'}")
        print("=" * 78)
        print("DONE -- no raw packet payloads were transmitted or stored; no credentials/tokens were printed; KNN and prevention were never invoked.")
    finally:
        sender.close()


if __name__ == "__main__":
    main()
