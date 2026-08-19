"""Live telemetry -> raw flow representation -> feature adapter -> 67 raw
model features -> (existing, unmodified) scaler -> autoencoder (section 5).

Every one of the 67 names in ml/datasets/processed/feature_names.json is
computed here from real captured-packet statistics -- nothing is filled
with a random or fabricated constant. Two things ARE approximated rather
than byte-exactly reverse-engineered from the original (proprietary-in-
behavior, not just proprietary-in-code) CICFlowMeter Java tool that built
CICIDS2017, and both are declared in FEATURE_COMPATIBILITY /
FEATURE_NOTES below rather than silently assumed correct -- see section 6
of docs/live_telemetry.md for the full compatibility audit this module
implements.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

from sensor.config import PROJECT_ROOT
from sensor.normalization.flow_reconstruction import RawFlow

_FEATURE_NAMES_PATH = PROJECT_ROOT / "ml" / "datasets" / "processed" / "feature_names.json"
FEATURE_NAMES: list[str] = json.loads(_FEATURE_NAMES_PATH.read_text())

# Compatibility classification (section 6): "A" = directly observable from
# a real captured bidirectional flow with no algorithmic ambiguity; "B" =
# derivable, but this adapter's formula is a documented approximation of a
# CICFlowMeter-specific convention rather than a verified byte-exact match.
# No feature is "C" (unavailable) -- see docs/live_telemetry.md section 6
# for why the two "STOP" trigger conditions (section 6/22) were not hit.
FEATURE_COMPATIBILITY: dict[str, str] = {name: "A" for name in FEATURE_NAMES}
FEATURE_NOTES: dict[str, str] = {}

for _b_name, _note in {
    "CWE Flag Count": "Implemented as a literal count of the TCP CWR bit. The real dataset is ~always 0 for this "
    "column (verified empirically, see docs/live_telemetry.md section 4) -- consistent with this "
    "implementation, but the original tool's own 'CWE' semantics were never independently confirmed.",
    "Subflow Fwd Bytes": "Approximated as (direction total bytes / subflow count), where subflow count uses this "
    "adapter's activity/idle burst algorithm (see 'Active *' notes) rather than a verified byte-exact "
    "port of CICFlowMeter's own subflow-splitting logic.",
    "Subflow Bwd Bytes": "Same approximation as Subflow Fwd Bytes, backward direction.",
    "min_seg_size_forward": "TCP: minimum observed TCP header length (dataofs*4) in the forward direction -- "
    "matches the real dataset's 20-44 byte range exactly (verified empirically). Non-TCP (e.g. UDP): "
    "this adapter reports the fixed 8-byte UDP header length, which does NOT match the real dataset's "
    "unexplained ~20-52 byte range for UDP rows (that range's derivation was not identifiable from "
    "public CICFlowMeter documentation) -- documented divergence, not a silent guess.",
    "Active Mean": "Uses this adapter's own activity/idle burst-splitting algorithm (packets are 'active' while "
    "gaps stay under activity_idle_threshold_seconds, 'idle' otherwise) -- the general CICFlowMeter "
    "approach, not a verified byte-exact port of its implementation.",
    "Active Std": "See Active Mean.",
    "Active Max": "See Active Mean.",
    "Active Min": "See Active Mean.",
    "Idle Mean": "See Active Mean (idle = gaps between bursts).",
    "Idle Std": "See Active Mean.",
    "Idle Max": "See Active Mean.",
    "Idle Min": "See Active Mean.",
}.items():
    FEATURE_COMPATIBILITY[_b_name] = "B"
    FEATURE_NOTES[_b_name] = _note

# Protocol-conditional, not a compatibility gap: these fields are only
# meaningful for TCP and use the same -1 "not applicable" sentinel the
# real CICIDS2017 dataset itself uses for non-TCP rows (verified
# empirically against ml/datasets/raw_labelled_flows -- see
# docs/live_telemetry.md section 4). This is a property of the feature
# set the offline model was already trained on, not a new live-only gap.
TCP_ONLY_SENTINEL_FEATURES: tuple[str, ...] = ("Init_Win_bytes_forward", "Init_Win_bytes_backward")

_EPSILON_SECONDS = 1e-6  # documented rate-calculation floor -- see _duration_seconds()


@dataclass
class FeatureAdapterResult:
    features: dict[str, float]
    missing: list[str] = field(default_factory=list)  # always [] in practice -- kept for the section-5 contract
    notes: dict[str, str] = field(default_factory=dict)  # feature -> caveat, only for values that used a fallback


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _population_std(values: list[float]) -> float:
    # Population std (ddof=0), not sample std: verified against the real
    # dataset that single-packet-direction flows produce 0.0, never NaN,
    # for every *Std column (docs/dataset_inspection.md: inf/NaN in this
    # dataset are confined to Flow Bytes/s and Flow Packets/s only).
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(_mean([(v - m) ** 2 for v in values]))


def _iat_stats_us(timestamps: list[float]) -> tuple[float, float, float, float, float]:
    """Returns (total, mean, std, max, min) inter-arrival time in
    microseconds, matching Flow Duration's units (verified empirically --
    see docs/live_telemetry.md section 3)."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    ordered = sorted(timestamps)
    diffs_us = [(b - a) * 1_000_000 for a, b in zip(ordered, ordered[1:])]
    return sum(diffs_us), _mean(diffs_us), _population_std(diffs_us), max(diffs_us), min(diffs_us)


def _activity_bursts(timestamps: list[float], idle_threshold_seconds: float) -> tuple[list[float], list[float]]:
    """Splits a flow's full (both-direction) timestamp sequence into
    bursts separated by gaps >= idle_threshold_seconds -- the general
    CICFlowMeter Active/Idle approach (FEATURE_NOTES above). Returns
    (active_durations_us, idle_gaps_us)."""
    if len(timestamps) < 2:
        return [0.0], []
    ordered = sorted(timestamps)
    active_durations: list[float] = []
    idle_gaps: list[float] = []
    burst_start = ordered[0]
    prev = ordered[0]
    for ts in ordered[1:]:
        gap = ts - prev
        if gap >= idle_threshold_seconds:
            active_durations.append((prev - burst_start) * 1_000_000)
            idle_gaps.append(gap * 1_000_000)
            burst_start = ts
        prev = ts
    active_durations.append((prev - burst_start) * 1_000_000)
    return active_durations, idle_gaps


def _duration_seconds(first_ts: float, last_ts: float) -> float:
    """Flooring, not fabrication: a real single/near-instant-packet flow
    has a genuine near-zero duration; Flow Bytes/s and Flow Packets/s
    would otherwise be +inf, which the persisted scaler was never fit
    against (this exact division-by-zero issue is Phase 1's own
    documented finding for these two columns -- docs/cleaning_decision_
    report.md). Phase 1 could drop such offline rows; live inference
    cannot skip scoring a real flow, so a 1-microsecond floor is used
    instead, and only for these two rate features."""
    return max(last_ts - first_ts, _EPSILON_SECONDS)


def adapt_features(flow: RawFlow, activity_idle_threshold_seconds: float = 5.0) -> FeatureAdapterResult:
    fwd = flow.fwd_packets
    bwd = flow.bwd_packets
    all_packets = fwd + bwd
    if not all_packets:
        raise ValueError("cannot adapt a flow with zero packets")

    first_ts = min(p.timestamp for p in all_packets)
    last_ts = max(p.timestamp for p in all_packets)
    duration_us = max((last_ts - first_ts) * 1_000_000, 0.0)
    duration_s = _duration_seconds(first_ts, last_ts)

    fwd_lengths = [float(p.total_length) for p in fwd]
    bwd_lengths = [float(p.total_length) for p in bwd]
    all_lengths = fwd_lengths + bwd_lengths

    fwd_ts = [p.timestamp for p in fwd]
    bwd_ts = [p.timestamp for p in bwd]
    all_ts = [p.timestamp for p in all_packets]

    flow_iat_total, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats_us(all_ts)
    fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats_us(fwd_ts)
    bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats_us(bwd_ts)

    is_tcp = flow.protocol == 6

    def _flag_count(pred) -> int:
        return sum(1 for p in all_packets if p.tcp_flags is not None and pred(p.tcp_flags))

    fwd_psh = sum(1 for p in fwd if p.tcp_flags is not None and p.tcp_flags.psh)
    fwd_urg = sum(1 for p in fwd if p.tcp_flags is not None and p.tcp_flags.urg)

    fwd_header_len = sum(p.transport_header_length for p in fwd)
    bwd_header_len = sum(p.transport_header_length for p in bwd)

    act_data_pkt_fwd = sum(1 for p in fwd if p.payload_length > 0)

    def _init_window(packets: list) -> float:
        for p in packets:
            if is_tcp and p.tcp_window is not None:
                return float(p.tcp_window)
            break
        return -1.0  # matches the real dataset's own "not applicable" sentinel (see TCP_ONLY_SENTINEL_FEATURES)

    if is_tcp:
        fwd_transport_headers = [p.transport_header_length for p in fwd]
        min_seg_size_forward = float(min(fwd_transport_headers)) if fwd_transport_headers else 0.0
    else:
        min_seg_size_forward = 8.0  # documented divergence for non-TCP -- see FEATURE_NOTES

    active_durations_us, idle_gaps_us = _activity_bursts(all_ts, activity_idle_threshold_seconds)
    subflow_count = max(len(active_durations_us), 1)
    subflow_fwd_bytes = sum(fwd_lengths) / subflow_count
    subflow_bwd_bytes = sum(bwd_lengths) / subflow_count

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)

    values: dict[str, float] = {
        "Destination Port": float(flow.forward_port if flow.forward_port is not None else -1),
        "Flow Duration": duration_us,
        "Total Fwd Packets": float(len(fwd)),
        "Total Backward Packets": float(len(bwd)),
        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,
        "Fwd Packet Length Max": max(fwd_lengths) if fwd_lengths else 0.0,
        "Fwd Packet Length Min": min(fwd_lengths) if fwd_lengths else 0.0,
        "Fwd Packet Length Mean": _mean(fwd_lengths),
        "Fwd Packet Length Std": _population_std(fwd_lengths),
        "Bwd Packet Length Max": max(bwd_lengths) if bwd_lengths else 0.0,
        "Bwd Packet Length Min": min(bwd_lengths) if bwd_lengths else 0.0,
        "Bwd Packet Length Mean": _mean(bwd_lengths),
        "Bwd Packet Length Std": _population_std(bwd_lengths),
        "Flow Bytes/s": (total_fwd_bytes + total_bwd_bytes) / duration_s,
        "Flow Packets/s": len(all_packets) / duration_s,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": fwd_iat_total,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": float(fwd_psh),
        "Fwd URG Flags": float(fwd_urg),
        "Fwd Header Length": float(fwd_header_len),
        "Bwd Header Length": float(bwd_header_len),
        "Fwd Packets/s": len(fwd) / duration_s,
        "Bwd Packets/s": len(bwd) / duration_s,
        "Min Packet Length": min(all_lengths) if all_lengths else 0.0,
        "Max Packet Length": max(all_lengths) if all_lengths else 0.0,
        "Packet Length Mean": _mean(all_lengths),
        "Packet Length Std": _population_std(all_lengths),
        "Packet Length Variance": _population_std(all_lengths) ** 2,
        "FIN Flag Count": float(_flag_count(lambda f: f.fin)),
        "SYN Flag Count": float(_flag_count(lambda f: f.syn)),
        "RST Flag Count": float(_flag_count(lambda f: f.rst)),
        "PSH Flag Count": float(_flag_count(lambda f: f.psh)),
        "ACK Flag Count": float(_flag_count(lambda f: f.ack)),
        "URG Flag Count": float(_flag_count(lambda f: f.urg)),
        "CWE Flag Count": float(_flag_count(lambda f: f.cwr)),
        "ECE Flag Count": float(_flag_count(lambda f: f.ece)),
        "Down/Up Ratio": (len(bwd) / len(fwd)) if fwd else 0.0,
        "Average Packet Size": (total_fwd_bytes + total_bwd_bytes) / len(all_packets),
        "Avg Fwd Segment Size": _mean(fwd_lengths),
        "Avg Bwd Segment Size": _mean(bwd_lengths),
        "Subflow Fwd Bytes": subflow_fwd_bytes,
        "Subflow Bwd Bytes": subflow_bwd_bytes,
        "Init_Win_bytes_forward": _init_window(fwd),
        "Init_Win_bytes_backward": _init_window(bwd),
        "act_data_pkt_fwd": float(act_data_pkt_fwd),
        "min_seg_size_forward": min_seg_size_forward,
        "Active Mean": _mean(active_durations_us),
        "Active Std": _population_std(active_durations_us),
        "Active Max": max(active_durations_us) if active_durations_us else 0.0,
        "Active Min": min(active_durations_us) if active_durations_us else 0.0,
        "Idle Mean": _mean(idle_gaps_us),
        "Idle Std": _population_std(idle_gaps_us),
        "Idle Max": max(idle_gaps_us) if idle_gaps_us else 0.0,
        "Idle Min": min(idle_gaps_us) if idle_gaps_us else 0.0,
    }

    missing = [name for name in FEATURE_NAMES if name not in values]
    notes = {name: FEATURE_NOTES[name] for name in FEATURE_NAMES if name in FEATURE_NOTES}
    ordered_features = {name: values[name] for name in FEATURE_NAMES if name in values}
    return FeatureAdapterResult(features=ordered_features, missing=missing, notes=notes)
