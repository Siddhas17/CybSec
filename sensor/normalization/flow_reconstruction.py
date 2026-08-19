"""Groups RawPacketEvents into bidirectional flows, the same unit
CICFlowMeter (and therefore ml/datasets/processed/feature_names.json)
operates on. A flow is identified by its unordered 5-tuple; direction
("forward"/"backward") is fixed by whichever endpoint sent the first
packet, exactly as CICFlowMeter defines it. A flow ends on RST, on a FIN
seen in both directions, on `flow_idle_timeout_seconds` of silence, or on
`flow_max_duration_seconds`/`flow_max_packets` being reached (so a single
long-lived connection cannot grow the in-memory state without bound --
section 9's "no unbounded growth" applies here as much as to the live
graph).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sensor.collectors.base import RawPacketEvent
from sensor.config import sensor_config


@dataclass(frozen=True)
class FlowKey:
    ip_a: str
    port_a: int | None
    ip_b: str
    port_b: int | None
    protocol: int


@dataclass
class RawFlow:
    """One completed bidirectional flow, ready for sensor.normalization.
    feature_adapter.adapt_features(). Packets are kept as two
    already-direction-sorted, timestamp-sorted lists rather than one
    merged list -- every CICFlowMeter-style feature needs one or the
    other."""

    key: FlowKey
    forward_ip: str
    forward_port: int | None
    backward_ip: str
    backward_port: int | None
    protocol: int
    fwd_packets: list[RawPacketEvent]
    bwd_packets: list[RawPacketEvent]
    end_reason: str  # "fin" | "rst" | "idle_timeout" | "max_duration" | "max_packets" | "flush"

    @property
    def first_ts(self) -> float:
        all_ts = [p.timestamp for p in self.fwd_packets + self.bwd_packets]
        return min(all_ts)

    @property
    def last_ts(self) -> float:
        all_ts = [p.timestamp for p in self.fwd_packets + self.bwd_packets]
        return max(all_ts)


@dataclass
class _FlowState:
    forward_ip: str
    forward_port: int | None
    backward_ip: str
    backward_port: int | None
    protocol: int
    fwd_packets: list[RawPacketEvent] = field(default_factory=list)
    bwd_packets: list[RawPacketEvent] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0
    fin_seen_fwd: bool = False
    fin_seen_bwd: bool = False

    def packet_count(self) -> int:
        return len(self.fwd_packets) + len(self.bwd_packets)


def _make_key(event: RawPacketEvent) -> FlowKey:
    a = (event.src_ip, event.src_port if event.src_port is not None else -1)
    b = (event.dst_ip, event.dst_port if event.dst_port is not None else -1)
    if a <= b:
        return FlowKey(event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol)
    return FlowKey(event.dst_ip, event.dst_port, event.src_ip, event.src_port, event.protocol)


def _to_raw_flow(state: _FlowState, end_reason: str) -> RawFlow:
    return RawFlow(
        key=FlowKey(state.forward_ip, state.forward_port, state.backward_ip, state.backward_port, state.protocol),
        forward_ip=state.forward_ip,
        forward_port=state.forward_port,
        backward_ip=state.backward_ip,
        backward_port=state.backward_port,
        protocol=state.protocol,
        fwd_packets=sorted(state.fwd_packets, key=lambda p: p.timestamp),
        bwd_packets=sorted(state.bwd_packets, key=lambda p: p.timestamp),
        end_reason=end_reason,
    )


class FlowAccumulator:
    """Pure Python, no I/O -- fully unit-testable with hand-built
    RawPacketEvent fixtures (section 16 forbids real network traffic in
    unit tests)."""

    def __init__(
        self,
        idle_timeout_seconds: float | None = None,
        max_duration_seconds: float | None = None,
        max_packets: int | None = None,
    ) -> None:
        self._idle_timeout = idle_timeout_seconds if idle_timeout_seconds is not None else sensor_config.flow_idle_timeout_seconds
        self._max_duration = max_duration_seconds if max_duration_seconds is not None else sensor_config.flow_max_duration_seconds
        self._max_packets = max_packets if max_packets is not None else sensor_config.flow_max_packets
        self._active: dict[FlowKey, _FlowState] = {}

    def ingest(self, event: RawPacketEvent) -> list[RawFlow]:
        """Feed one packet in. Returns zero or more completed flows: the
        just-completed old flow if this packet starts a new epoch on the
        same key (idle timeout expired), plus the current flow if this
        packet itself ends it (RST / both-sides FIN / max duration/packets)."""
        completed: list[RawFlow] = []
        key = _make_key(event)
        state = self._active.get(key)

        if state is not None and (event.timestamp - state.last_ts) > self._idle_timeout:
            completed.append(_to_raw_flow(state, "idle_timeout"))
            state = None

        if state is None:
            state = _FlowState(
                forward_ip=event.src_ip,
                forward_port=event.src_port,
                backward_ip=event.dst_ip,
                backward_port=event.dst_port,
                protocol=event.protocol,
                first_ts=event.timestamp,
                last_ts=event.timestamp,
            )
            self._active[key] = state

        is_forward = event.src_ip == state.forward_ip and event.src_port == state.forward_port
        (state.fwd_packets if is_forward else state.bwd_packets).append(event)
        state.last_ts = max(state.last_ts, event.timestamp)
        state.first_ts = min(state.first_ts, event.timestamp)

        if event.protocol == 6 and event.tcp_flags is not None:
            if event.tcp_flags.rst:
                completed.append(_to_raw_flow(state, "rst"))
                del self._active[key]
                return completed
            if event.tcp_flags.fin:
                if is_forward:
                    state.fin_seen_fwd = True
                else:
                    state.fin_seen_bwd = True
                if state.fin_seen_fwd and state.fin_seen_bwd:
                    completed.append(_to_raw_flow(state, "fin"))
                    del self._active[key]
                    return completed

        if (state.last_ts - state.first_ts) >= self._max_duration:
            completed.append(_to_raw_flow(state, "max_duration"))
            del self._active[key]
            return completed

        if state.packet_count() >= self._max_packets:
            completed.append(_to_raw_flow(state, "max_packets"))
            del self._active[key]
            return completed

        return completed

    def flush_idle(self, now_ts: float) -> list[RawFlow]:
        """Periodic sweep (section 9-style bounded background cleanup) for
        flows that have gone silent with no new packet to trigger the
        idle-timeout check inside ingest()."""
        expired_keys = [k for k, s in self._active.items() if (now_ts - s.last_ts) > self._idle_timeout]
        flows = []
        for k in expired_keys:
            flows.append(_to_raw_flow(self._active.pop(k), "idle_timeout"))
        return flows

    def flush_all(self) -> list[RawFlow]:
        """Force-completes every in-progress flow -- used on collector
        shutdown so no partially-observed flow is silently discarded."""
        flows = [_to_raw_flow(s, "flush") for s in self._active.values()]
        self._active.clear()
        return flows

    @property
    def active_flow_count(self) -> int:
        return len(self._active)
