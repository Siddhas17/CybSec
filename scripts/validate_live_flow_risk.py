"""Bounded real-traffic validation: Npcap capture -> victim_agent.flow ->
victim_agent_flow_bridge -> AnalyticalPipeline -> DetectionResult, using
REAL locally captured packets for AT MOST 10 seconds.

Run from the project root (needs the full backend/ML stack -- numpy/torch/
sqlalchemy -- installed, unlike victim_agent's own lightweight
requirements.txt, since this script also exercises the backend-side risk
pipeline):

    python scripts/validate_live_flow_risk.py

This is a manual, one-shot validation script -- not part of the automated
pytest suite (no fixtures/mocks; it genuinely opens Npcap and, best-effort,
a real DB connection). It:

  - captures for <=10 seconds on the auto-discovered Wi-Fi interface
    (victim_agent.capture.find_wifi_interface() -- never hardcoded),
  - reconstructs flows via victim_agent.flow's own accumulator. That
    class is named FlowTracker in this package (used here through the
    existing reconstruct_flows() convenience wrapper) -- there is a
    same-purpose but differently-typed FlowAccumulator in
    sensor/normalization/flow_reconstruction.py for the OTHER,
    loopback-based live sensor, which produces a RawFlow with no
    to_cicids_features() method, so it does not apply to this
    victim_agent-based path,
  - since capture is already stopped by the time reconstruct_flows() is
    called, every resulting Flow is complete by construction -- there is
    no separate "close"/finalize call to make,
  - scores every valid flow through the existing, unmodified
    victim_agent_flow_bridge.score_victim_agent_flow() ->
    AnalyticalPipeline.score() (real autoencoder + real risk_engine,
    weights/thresholds untouched),
  - best-effort reuses the existing graph_service.get_edge_context()
    against the real DB for graph context (read-only: a single SELECT via
    the existing query, never a write) and falls back to no graph context
    -- never a fabricated one -- if the DB is unreachable.

Never invokes KNN, never persists an Event/Detection/RiskAssessment row,
never broadcasts over WebSocket, never calls the prevention layer, and
never stores or prints raw packet payloads or captured traffic to disk --
this script's own output is a compact summary only.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services import victim_agent_flow_bridge as bridge  # noqa: E402
from backend.app.services.analytical_pipeline import AnalyticalPipeline  # noqa: E402
from backend.app.services.model_registry import get_predictor, get_risk_config  # noqa: E402
from victim_agent import capture, flow  # noqa: E402

CAPTURE_DURATION_SECONDS = 10  # hard bound -- not configurable from the CLI, per the task's safety requirement


def _try_get_graph_context(src_ip: str, dst_ip: str):
    """Best-effort use of the EXISTING graph_service.get_edge_context()
    against the real DB. Never raises, never fabricates graph data if the
    DB is unreachable -- returns (GraphContext | None, used: bool,
    reason: str)."""
    try:
        from backend.app.db.session import SessionLocal
        from backend.app.services import graph_service
    except Exception as exc:
        return None, False, f"graph_service/db import failed: {type(exc).__name__}: {exc}"

    db = None
    try:
        db = SessionLocal()
        context = graph_service.get_edge_context(db, src_ip, dst_ip)
        return context, True, "ok"
    except Exception as exc:
        return None, False, f"DB unreachable or query failed: {type(exc).__name__}: {exc}"
    finally:
        if db is not None:
            db.close()


def main() -> None:
    print("=" * 78)
    print(f"BOUNDED REAL LIVE FLOW -> RISK VALIDATION (<= {CAPTURE_DURATION_SECONDS}s capture, local only)")
    print("=" * 78)

    print("\n[1] interface discovery (victim_agent.capture.find_wifi_interface())")
    try:
        iface = capture.find_wifi_interface()
    except capture.CaptureError as exc:
        print(f"STOP -- interface discovery failed via the existing API: {exc}")
        return
    iface_name = getattr(iface, "name", "?")
    iface_ip = getattr(iface, "ip", "?")
    print(f"    interface: {iface_name} (ip={iface_ip})")

    print(f"\n[2] bounded capture (<= {CAPTURE_DURATION_SECONDS}s)")
    try:
        packets = capture.capture_packets(duration_seconds=CAPTURE_DURATION_SECONDS, iface=iface)
    except capture.CaptureError as exc:
        print(f"STOP -- capture failed via the existing API: {exc}")
        return
    print(f"    packets captured (payload-free metadata only): {len(packets)}")

    print("\n[3-5] flow reconstruction (victim_agent.flow.reconstruct_flows() -- FlowTracker)")
    flows = flow.reconstruct_flows(packets)
    print(f"    flows reconstructed: {len(flows)}")

    print("\n[6-7] validate 67-feature vectors, then score via the existing bridge + AnalyticalPipeline")
    pipeline = AnalyticalPipeline(get_predictor(), get_risk_config())

    valid_results: list[tuple] = []
    skipped = 0
    graph_context_used_count = 0
    graph_context_unavailable_reason: str | None = None

    for f in flows:
        try:
            features = f.to_cicids_features()
        except Exception:
            skipped += 1
            continue
        if len(features) != 67 or list(features.keys()) != list(flow.CICIDS_FEATURE_NAMES):
            skipped += 1
            continue
        if any((not isinstance(v, (int, float))) or isinstance(v, bool) or math.isnan(v) or math.isinf(v) for v in features.values()):
            skipped += 1
            continue

        graph_context, used, reason = _try_get_graph_context(f.source_ip, f.destination_ip)
        if used:
            graph_context_used_count += 1
        else:
            graph_context_unavailable_reason = reason

        try:
            result = bridge.score_victim_agent_flow(f, pipeline, graph_context)
        except Exception:
            skipped += 1
            continue

        valid_results.append((f, result))

    print("\n" + "=" * 78)
    print("SUMMARY")
    print(f"  interface:                 {iface_name} ({iface_ip})")
    print(f"  packets captured:          {len(packets)}")
    print(f"  flows reconstructed:       {len(flows)}")
    print(f"  valid ML flows:            {len(valid_results)}")
    print(f"  skipped/invalid flows:     {skipped}")
    print(f"  graph context obtained:    {graph_context_used_count}/{len(valid_results)} valid flow(s)")
    if graph_context_used_count < len(valid_results):
        print(f"    (unavailable for the rest -- reason: {graph_context_unavailable_reason})")

    anomaly_count = sum(1 for _, r in valid_results if r.is_anomaly)
    normal_count = len(valid_results) - anomaly_count
    print(f"  Autoencoder anomaly count: {anomaly_count}")
    print(f"  Autoencoder normal count:  {normal_count}")

    level_counts: dict[str, int] = {}
    for _, r in valid_results:
        level_counts[r.risk_level] = level_counts.get(r.risk_level, 0) + 1
    print(f"  risk-level counts:         {level_counts or '(none)'}")

    if valid_results:
        f, r = valid_results[0]
        sport = f.source_port if f.source_port is not None else "-"
        dport = f.destination_port if f.destination_port is not None else "-"
        print(
            "  representative flow:      "
            f"{f.protocol} {f.source_ip}:{sport} -> {f.destination_ip}:{dport} "
            f"dur={f.duration_seconds:.3f}s pkts={f.total_packets} "
            f"anomaly={r.is_anomaly} risk_score={r.risk_score:.2f} risk_level={r.risk_level}"
        )
    else:
        print("  representative flow:      (none)")

    print("=" * 78)
    print("DONE -- no packet payloads or captured traffic were saved to disk; no DB row was written; KNN and prevention were never invoked.")


if __name__ == "__main__":
    main()
