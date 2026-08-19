"""BaseTelemetryCollector: the interface every telemetry source implements
(section 3). Concrete collectors never compute the 67 model features
themselves -- they only ever produce RawPacketEvent objects; flow
reconstruction and feature adaptation live in sensor/normalization/, kept
separate so a future second collector (e.g. a different capture mechanism)
reuses that logic unchanged.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class CollectorStatus(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"


@dataclass(frozen=True)
class TcpFlags:
    fin: bool = False
    syn: bool = False
    rst: bool = False
    psh: bool = False
    ack: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False


@dataclass(frozen=True)
class RawPacketEvent:
    """One captured packet, already parsed into the fields flow
    reconstruction needs -- never a raw byte blob (section 13: malformed
    packets are rejected before this point, see
    collectors/_capture_worker.py::_parse_packet)."""

    timestamp: float  # Unix epoch seconds, sub-millisecond precision
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: int  # IANA protocol number (6=TCP, 17=UDP, 1=ICMP, ...)
    total_length: int  # IP total length (bytes on the wire for this packet)
    ip_header_length: int  # IPv4 header bytes (20 without options)
    transport_header_length: int  # TCP (20-60, per dataofs) or UDP (fixed 8) header bytes; 0 for other protocols
    payload_length: int  # total_length - ip_header_length - transport_header_length, clipped at 0
    tcp_flags: TcpFlags | None  # None for non-TCP protocols
    tcp_window: int | None  # None for non-TCP protocols


@dataclass
class CollectorHealth:
    """Section 14: what the System Health page needs to show."""

    status: CollectorStatus
    interface: str
    started_at: str | None = None
    last_event_at: str | None = None
    packets_received: int = 0
    packets_dropped: int = 0  # queue overflow (section 9's backpressure), not malformed
    parse_errors: int = 0
    restart_count: int = 0
    last_error: str | None = None
    extra: dict = field(default_factory=dict)


class BaseTelemetryCollector(ABC):
    """start()/stop()/health()/events() -- section 3. A collector must
    survive and report, never raise out of start()/stop() for conditions a
    lab operator can recover from (section 13)."""

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def health(self) -> CollectorHealth: ...

    @abstractmethod
    def events(self):
        """Yields RawPacketEvent objects as they arrive. Must not block
        forever with no way to stop -- implementations poll with a timeout
        so a stop() request is honored promptly."""
        ...
