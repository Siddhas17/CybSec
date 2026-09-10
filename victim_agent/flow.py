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
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# A canonical, order-independent endpoint pair: (protocol, low_endpoint, high_endpoint).
# Each endpoint is (ip, port) with port normalized to -1 when absent (ICMP).
FlowKey = tuple[str, tuple[str, int], tuple[str, int]]

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

    @property
    def duration_seconds(self) -> float:
        return (self.end_timestamp - self.start_timestamp).total_seconds()


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
            else:
                flow.backward_packets += 1
                flow.backward_bytes += length

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
