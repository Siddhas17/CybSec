"""Standalone Phase 1 bidirectional flow reconstruction.

Deliberately not wired into agent.py/telemetry.py/sender.py, and does not
import victim_agent.capture -- this module only groups packet-metadata
records (the dict shape produced by
victim_agent.capture.extract_packet_metadata(), e.g. via
dataclasses.asdict()) into bidirectional flows and computes basic
counters. It never captures packets itself, never talks to the backend,
and never invokes the ML pipeline, attack graph, or prevention layer --
those are separate, later stages.

A "flow" here is the standard bidirectional 5-tuple grouping: a request
and its reply (same IP/port pair, same protocol, addresses reversed)
belong to one flow, not two. See make_flow_key() for exactly how.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# A canonical, order-independent endpoint pair: (protocol, low_endpoint, high_endpoint).
# Each endpoint is (ip, port) with port normalized to -1 when absent (ICMP).
FlowKey = tuple[str, tuple[str, int], tuple[str, int]]

# The exact 67 names and order the trained autoencoder/KNN require --
# hardcoded here (not read from ml/models/artifacts/... at runtime) so
# victim_agent stays a standalone package with no filesystem coupling to
# ml/, matching capture.py/config.py's existing "no coupling to
# ml/backend" design. Verified identical, name-for-name and order-for-
# order, to ml/models/artifacts/autoencoder/feature_names.json -- if that
# file ever changes, this tuple must be updated to match.
CICIDS_FEATURE_NAMES: tuple[str, ...] = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)

# Default "active burst" gap threshold for the Active */Idle * feature
# family, matching sensor/normalization/feature_adapter.py's default --
# see _compute_cicids_features()'s docstring for what this controls.
_ACTIVITY_IDLE_THRESHOLD_SECONDS = 5.0

# Floor for rate-feature (Flow/Fwd/Bwd Bytes|Packets per second)
# denominators -- a genuine near-instant flow has a real near-zero
# duration; without a floor, dividing by it produces +inf, which is
# exactly the division-by-zero issue documented for these two columns in
# docs/cleaning_decision_report.md (Phase 1 dataset cleaning) and solved
# the same way in sensor/normalization/feature_adapter.py.
_RATE_EPSILON_SECONDS = 1e-6

_REQUIRED_FIELDS = ("source_ip", "destination_ip", "protocol", "timestamp")


def _get(packet: Any, field_name: str, default: Any = None) -> Any:
    if isinstance(packet, dict):
        return packet.get(field_name, default)
    return getattr(packet, field_name, default)


def _endpoint(ip: str, port: int | None) -> tuple[str, int]:
    return (ip, port if port is not None else -1)


def make_flow_key(source_ip: str, source_port: int | None, destination_ip: str, destination_port: int | None, protocol: str) -> FlowKey:
    """Returns the same key regardless of which side is "source" -- a
    packet A:p1->B:p2 and its reply B:p2->A:p1 both produce this exact
    tuple, so they land in the same flow."""
    a = _endpoint(source_ip, source_port)
    b = _endpoint(destination_ip, destination_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return (protocol, lo, hi)


@dataclass(frozen=True)
class _PacketRecord:
    """Per-packet detail kept only for CICIDS2017 feature calculation --
    the aggregate counters on Flow (total_packets, total_bytes, ...)
    remain the source of truth for simple counts; this is additional,
    not a replacement. Any field capture.py couldn't determine for this
    packet (e.g. tcp_window on a UDP packet) is None here too -- never
    fabricated."""

    timestamp: datetime
    length: int
    tcp_flags: str | None
    tcp_window: int | None
    transport_header_length: int | None
    tcp_payload_length: int | None


@dataclass
class Flow:
    """One bidirectional flow. source_ip/source_port/destination_ip/
    destination_port record the direction of the *first* packet observed
    for this flow -- that packet's direction is "forward"; anything
    arriving with addresses reversed is "backward". Which physical side
    that corresponds to (client vs server) is not tracked here; that is
    the concern of a later analysis stage, not reconstruction."""

    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    start_timestamp: datetime
    end_timestamp: datetime
    total_packets: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    total_bytes: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    _forward_records: list[_PacketRecord] = field(default_factory=list, repr=False)
    _backward_records: list[_PacketRecord] = field(default_factory=list, repr=False)

    @property
    def duration_seconds(self) -> float:
        return (self.end_timestamp - self.start_timestamp).total_seconds()

    def to_cicids_features(self, activity_idle_threshold_seconds: float = _ACTIVITY_IDLE_THRESHOLD_SECONDS) -> dict[str, float]:
        """Returns all 67 trained-model feature names -> float, in the
        exact order of CICIDS_FEATURE_NAMES, computed from this flow's
        actual packets. See the module-level docstring section below
        _compute_cicids_features() for the conventions used (population
        std, microsecond time units, epsilon-floored rate denominators,
        -1 non-TCP sentinels) and which are documented approximations
        rather than a verified byte-exact CICFlowMeter port -- ported
        from sensor/normalization/feature_adapter.py's already-audited
        implementation (see docs/live_telemetry.md section 6), adapted
        to this module's Flow/_PacketRecord shape."""
        return _compute_cicids_features(self, activity_idle_threshold_seconds)


class FlowTracker:
    """Consumes packet-metadata records one at a time and groups them into
    Flow objects keyed by make_flow_key(). A malformed/incomplete record
    (missing required fields, wrong types) is logged at DEBUG and skipped
    -- it never raises and never corrupts other flows, matching the rest
    of victim_agent's "never crash the loop over one bad record" convention."""

    def __init__(self) -> None:
        self._flows: dict[FlowKey, Flow] = {}
        self._forward_endpoint: dict[FlowKey, tuple[str, int]] = {}

    def add(self, packet: Any) -> Flow | None:
        try:
            values = {name: _get(packet, name) for name in _REQUIRED_FIELDS}
            if any(values[name] is None or values[name] == "" for name in _REQUIRED_FIELDS):
                logger.debug("Skipping packet metadata missing required field(s): %r", packet)
                return None

            source_ip: str = values["source_ip"]
            destination_ip: str = values["destination_ip"]
            protocol: str = values["protocol"]
            timestamp: datetime = values["timestamp"]
            source_port = _get(packet, "source_port")
            destination_port = _get(packet, "destination_port")
            length = int(_get(packet, "length", 0) or 0)

            tcp_flags = _get(packet, "tcp_flags")
            tcp_window = _get(packet, "tcp_window")
            transport_header_length = _get(packet, "transport_header_length")
            tcp_payload_length = _get(packet, "tcp_payload_length")
            record = _PacketRecord(
                timestamp=timestamp,
                length=length,
                tcp_flags=tcp_flags if isinstance(tcp_flags, str) else None,
                tcp_window=int(tcp_window) if isinstance(tcp_window, (int, float)) else None,
                transport_header_length=int(transport_header_length) if isinstance(transport_header_length, (int, float)) else None,
                tcp_payload_length=int(tcp_payload_length) if isinstance(tcp_payload_length, (int, float)) else None,
            )

            key = make_flow_key(source_ip, source_port, destination_ip, destination_port, protocol)
            forward_endpoint = _endpoint(source_ip, source_port)

            flow = self._flows.get(key)
            if flow is None:
                flow = Flow(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    source_port=source_port,
                    destination_port=destination_port,
                    protocol=protocol,
                    start_timestamp=timestamp,
                    end_timestamp=timestamp,
                )
                self._flows[key] = flow
                self._forward_endpoint[key] = forward_endpoint

            is_forward = forward_endpoint == self._forward_endpoint[key]

            flow.total_packets += 1
            flow.total_bytes += length
            if is_forward:
                flow.forward_packets += 1
                flow.forward_bytes += length
                flow._forward_records.append(record)
            else:
                flow.backward_packets += 1
                flow.backward_bytes += length
                flow._backward_records.append(record)

            if timestamp < flow.start_timestamp:
                flow.start_timestamp = timestamp
            if timestamp > flow.end_timestamp:
                flow.end_timestamp = timestamp

            return flow
        except Exception as exc:  # noqa: BLE001 -- one bad record must never abort reconstruction
            logger.debug("Skipping unparseable packet metadata: %s (%r)", exc, packet)
            return None

    def flows(self) -> list[Flow]:
        return list(self._flows.values())


def reconstruct_flows(packets: Iterable[Any]) -> list[Flow]:
    """Convenience one-shot wrapper: feeds every item in packets through a
    fresh FlowTracker and returns the resulting flows."""
    tracker = FlowTracker()
    for packet in packets:
        tracker.add(packet)
    return tracker.flows()


# --- CICIDS2017 feature calculation -----------------------------------------
#
# Ports sensor/normalization/feature_adapter.py's already-audited formulas
# (docs/live_telemetry.md section 6) onto this module's Flow/_PacketRecord
# shape. That module classifies each of the 67 features "A" (directly
# observable, no ambiguity -- 60 features) or "B" (derivable, but a
# documented approximation of a CICFlowMeter-specific convention rather
# than a verified byte-exact port): CWE Flag Count, Subflow Fwd/Bwd Bytes,
# min_seg_size_forward (non-TCP case), and the Active */Idle * family.
# Nothing is "C" (unavailable) -- every one of the 67 names below is
# computed from this flow's actual packets, never a fabricated constant.
#
# Conventions carried over unchanged (verified against the real dataset --
# see docs/live_telemetry.md sections 3-4):
#   - Flow Duration and every IAT/Active/Idle feature are in MICROSECONDS.
#   - *Std columns use population std (ddof=0): a single-observation
#     direction produces 0.0, never NaN.
#   - Flow/Fwd/Bwd Bytes|Packets per second divide by a duration floored
#     at _RATE_EPSILON_SECONDS, never a literal 0 -- avoids +inf instead
#     of reproducing the real dataset's documented inf/NaN quality issue
#     for exactly these two columns (docs/cleaning_decision_report.md).
#   - Init_Win_bytes_forward/backward use -1.0 for non-TCP flows, matching
#     the real dataset's own "not applicable" sentinel (35.4% of real
#     training rows are exactly -1 for this reason).
#
# One documented divergence from feature_adapter.py: that module only
# ever sees TCP or UDP flows and falls back to a fixed 8.0 (UDP header
# length) for min_seg_size_forward on any non-TCP flow. This module's
# flows can also be ICMP (or another IP protocol), where
# transport_header_length is never populated (capture.py only fills it in
# for TCP/UDP -- see PacketMetadata). Reusing "8.0" for ICMP would
# misattribute a UDP-specific constant to a protocol it doesn't describe,
# which is exactly the kind of invented value this task said not to
# produce -- so here min_seg_size_forward falls back to 0.0 only when no
# transport_header_length was observed at all (i.e. genuinely ICMP/other),
# and still reproduces feature_adapter.py's UDP behavior (fixed 8) when
# UDP packets are actually present, since that value is real, observed
# data for UDP. See test_flow.py for the ICMP case this affects.


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _population_std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(_mean([(v - m) ** 2 for v in values]))


def _epoch_seconds(ts: datetime) -> float:
    return ts.timestamp()


def _iat_stats_us(timestamps: list[datetime]) -> tuple[float, float, float, float, float]:
    """Returns (total, mean, std, max, min) inter-arrival time in
    microseconds. Fewer than 2 timestamps means no interval exists to
    measure -- all-zero, not NaN, per the module-level convention note."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    ordered = sorted(_epoch_seconds(t) for t in timestamps)
    diffs_us = [(b - a) * 1_000_000 for a, b in zip(ordered, ordered[1:])]
    return sum(diffs_us), _mean(diffs_us), _population_std(diffs_us), max(diffs_us), min(diffs_us)


def _activity_bursts(timestamps: list[datetime], idle_threshold_seconds: float) -> tuple[list[float], list[float]]:
    """Splits a flow's full (both-direction) timestamp sequence into
    bursts separated by gaps >= idle_threshold_seconds -- packets are
    "active" while consecutive gaps stay under the threshold, "idle"
    otherwise (the general CICFlowMeter approach; see the "B" note
    above). Returns (active_durations_us, idle_gaps_us)."""
    if len(timestamps) < 2:
        return [0.0], []
    ordered = sorted(_epoch_seconds(t) for t in timestamps)
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


def _flag_count(records: list[_PacketRecord], letter: str) -> int:
    """Counts packets whose tcp_flags string contains `letter` -- Scapy
    always prints TCP flags in fixed canonical order (F S R P A U E C N),
    so simple membership is a reliable per-flag test. Non-TCP packets
    have tcp_flags=None and are never counted."""
    return sum(1 for r in records if r.tcp_flags is not None and letter in r.tcp_flags)


def _init_window(records: list[_PacketRecord], is_tcp: bool) -> float:
    """CICFlowMeter's Init_Win_bytes_* is the TCP window of the *first*
    packet in that direction specifically -- not the first packet that
    happens to have a window recorded. -1.0 (the real dataset's own
    sentinel) when there is no first packet, the flow isn't TCP, or that
    first packet's window wasn't captured."""
    if not records:
        return -1.0
    first = records[0]
    if is_tcp and first.tcp_window is not None:
        return float(first.tcp_window)
    return -1.0


def _min_seg_size_forward(fwd_records: list[_PacketRecord]) -> float:
    """Minimum observed transport-header length in the forward direction.
    0.0 only when no transport_header_length was observed at all (a pure
    ICMP/other-IP-protocol flow) -- see the module-level divergence note
    above for why this isn't 8.0 the way feature_adapter.py's TCP/UDP-only
    fallback is."""
    headers = [r.transport_header_length for r in fwd_records if r.transport_header_length is not None]
    return float(min(headers)) if headers else 0.0


def _compute_cicids_features(flow: Flow, activity_idle_threshold_seconds: float) -> dict[str, float]:
    fwd = sorted(flow._forward_records, key=lambda r: r.timestamp)
    bwd = sorted(flow._backward_records, key=lambda r: r.timestamp)
    all_records = sorted(fwd + bwd, key=lambda r: r.timestamp)

    fwd_lengths = [float(r.length) for r in fwd]
    bwd_lengths = [float(r.length) for r in bwd]
    all_lengths = fwd_lengths + bwd_lengths

    fwd_ts = [r.timestamp for r in fwd]
    bwd_ts = [r.timestamp for r in bwd]
    all_ts = [r.timestamp for r in all_records]

    if all_ts:
        first_ts = min(_epoch_seconds(t) for t in all_ts)
        last_ts = max(_epoch_seconds(t) for t in all_ts)
    else:
        first_ts = last_ts = 0.0
    duration_us = max((last_ts - first_ts) * 1_000_000, 0.0)
    duration_s = max(last_ts - first_ts, _RATE_EPSILON_SECONDS)

    flow_iat_total, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats_us(all_ts)
    fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats_us(fwd_ts)
    bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats_us(bwd_ts)

    is_tcp = flow.protocol == "TCP"

    fwd_psh = sum(1 for r in fwd if r.tcp_flags is not None and "P" in r.tcp_flags)
    fwd_urg = sum(1 for r in fwd if r.tcp_flags is not None and "U" in r.tcp_flags)

    fwd_header_len = sum(r.transport_header_length or 0 for r in fwd)
    bwd_header_len = sum(r.transport_header_length or 0 for r in bwd)

    act_data_pkt_fwd = sum(1 for r in fwd if (r.tcp_payload_length or 0) > 0)

    active_durations_us, idle_gaps_us = _activity_bursts(all_ts, activity_idle_threshold_seconds)
    subflow_count = max(len(active_durations_us), 1)
    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)
    subflow_fwd_bytes = total_fwd_bytes / subflow_count
    subflow_bwd_bytes = total_bwd_bytes / subflow_count

    total_packets = len(all_records)

    values: dict[str, float] = {
        "Destination Port": float(flow.destination_port) if flow.destination_port is not None else -1.0,
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
        "Flow Packets/s": total_packets / duration_s,
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
        "FIN Flag Count": float(_flag_count(all_records, "F")),
        "SYN Flag Count": float(_flag_count(all_records, "S")),
        "RST Flag Count": float(_flag_count(all_records, "R")),
        "PSH Flag Count": float(_flag_count(all_records, "P")),
        "ACK Flag Count": float(_flag_count(all_records, "A")),
        "URG Flag Count": float(_flag_count(all_records, "U")),
        "CWE Flag Count": float(_flag_count(all_records, "C")),
        "ECE Flag Count": float(_flag_count(all_records, "E")),
        "Down/Up Ratio": (len(bwd) / len(fwd)) if fwd else 0.0,
        "Average Packet Size": ((total_fwd_bytes + total_bwd_bytes) / total_packets) if total_packets else 0.0,
        "Avg Fwd Segment Size": _mean(fwd_lengths),
        "Avg Bwd Segment Size": _mean(bwd_lengths),
        "Subflow Fwd Bytes": subflow_fwd_bytes,
        "Subflow Bwd Bytes": subflow_bwd_bytes,
        "Init_Win_bytes_forward": _init_window(fwd, is_tcp),
        "Init_Win_bytes_backward": _init_window(bwd, is_tcp),
        "act_data_pkt_fwd": float(act_data_pkt_fwd),
        "min_seg_size_forward": _min_seg_size_forward(fwd),
        "Active Mean": _mean(active_durations_us),
        "Active Std": _population_std(active_durations_us),
        "Active Max": max(active_durations_us) if active_durations_us else 0.0,
        "Active Min": min(active_durations_us) if active_durations_us else 0.0,
        "Idle Mean": _mean(idle_gaps_us),
        "Idle Std": _population_std(idle_gaps_us),
        "Idle Max": max(idle_gaps_us) if idle_gaps_us else 0.0,
        "Idle Min": min(idle_gaps_us) if idle_gaps_us else 0.0,
    }

    return {name: values[name] for name in CICIDS_FEATURE_NAMES}
