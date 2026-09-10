"""Standalone Phase 1 packet-capture validation module.

Deliberately not wired into agent.py/telemetry.py/sender.py -- this module
only proves that Npcap + Scapy can capture real packets on this Windows
machine and extract safe, payload-free metadata from them. Nothing here
sends data anywhere or touches the retry queue, the backend, or the
database; see docs/victim_agent.md for why psutil connection telemetry and
packet capture are kept as separate data paths.

Run directly (`python -m victim_agent.capture`) for a short manual capture
that prints what was seen; import capture_packets()/extract_packet_metadata()
for programmatic/tested use.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable

logger = logging.getLogger(__name__)

try:
    from scapy.all import IFACES, IP, TCP, UDP, sniff

    _SCAPY_IMPORT_ERROR: Exception | None = None
except ImportError as exc:  # pragma: no cover -- exercised only when scapy isn't installed
    IFACES = IP = TCP = UDP = sniff = None  # type: ignore[assignment]
    _SCAPY_IMPORT_ERROR = exc

# Link-local (APIPA) and loopback addresses indicate the interface has no
# real network connection -- Windows commonly assigns these to virtual
# adapters (e.g. "Microsoft Wi-Fi Direct Virtual Adapter") whose
# description also contains "Wi-Fi", so they must be excluded rather than
# just requiring *some* IPv4 string to be present.
_INACTIVE_IP_PREFIXES = ("169.254.", "127.")


class CaptureError(Exception):
    """Raised when packet capture cannot proceed -- missing Scapy, missing
    Npcap, or no usable Wi-Fi interface. Always carries a human-readable,
    actionable message; never a raw Scapy/OS traceback."""


@dataclass(frozen=True)
class PacketMetadata:
    """Payload-free summary of one captured packet. Never holds raw bytes,
    header options, or application data -- only what's needed to see that
    capture works."""

    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    length: int


_IP_PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-ENCAP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


def _require_scapy() -> None:
    if _SCAPY_IMPORT_ERROR is not None:
        raise CaptureError(
            "Scapy is not installed -- run `pip install -r victim_agent/requirements.txt` "
            "inside the victim_agent environment."
        ) from _SCAPY_IMPORT_ERROR


def _list_interfaces() -> list[Any]:
    _require_scapy()
    try:
        interfaces = list(IFACES.values())
    except Exception as exc:  # pragma: no cover -- defensive; IFACES shape varies by scapy/OS version
        raise CaptureError(f"Could not enumerate network interfaces: {exc}") from exc

    if not interfaces:
        raise CaptureError(
            "No network interfaces were found by Scapy -- Npcap may not be installed "
            "(see https://npcap.com) or this process may need to run as Administrator."
        )
    return interfaces


def _has_active_ipv4(iface: Any) -> bool:
    ip = getattr(iface, "ip", None)
    if not ip:
        return False
    return not ip.startswith(_INACTIVE_IP_PREFIXES)


def find_wifi_interface(interfaces: Iterable[Any] | None = None) -> Any:
    """Returns the Scapy interface object for the active Wi-Fi adapter --
    description containing "Wi-Fi" (case-insensitive) with a real,
    non-link-local IPv4 address. Raises CaptureError with the list of
    available interfaces if none qualifies, rather than silently falling
    back to an arbitrary interface."""
    candidates = list(interfaces) if interfaces is not None else _list_interfaces()

    for iface in candidates:
        description = getattr(iface, "description", "") or getattr(iface, "name", "") or ""
        if "wi-fi" in description.lower() and _has_active_ipv4(iface):
            return iface

    available = [f"{getattr(i, 'name', '?')} ({getattr(i, 'description', '?')}, ip={getattr(i, 'ip', None)!r})" for i in candidates]
    raise CaptureError("No active Wi-Fi interface with a valid IPv4 address was found. Available interfaces: " + "; ".join(available))


def extract_packet_metadata(packet: Any) -> PacketMetadata | None:
    """Extracts safe metadata from one captured packet. Returns None for
    non-IPv4 packets (e.g. ARP) -- out of scope for this phase. Never
    raises for a single malformed/unexpected packet; logs at DEBUG and
    skips it instead, matching telemetry.py's convention."""
    try:
        if IP is None or not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        source_port: int | None = None
        destination_port: int | None = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)
        else:
            protocol = _IP_PROTOCOL_NAMES.get(int(ip_layer.proto), f"IP-PROTO-{ip_layer.proto}")

        raw_time = getattr(packet, "time", None)
        timestamp = datetime.fromtimestamp(float(raw_time), tz=UTC) if raw_time is not None else datetime.now(UTC)

        return PacketMetadata(
            timestamp=timestamp,
            source_ip=ip_layer.src,
            destination_ip=ip_layer.dst,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            length=len(packet),
        )
    except Exception as exc:  # noqa: BLE001 -- one bad packet must never abort a capture
        logger.debug("Skipping unparseable packet: %s", exc)
        return None


def capture_packets(duration_seconds: int = 10, iface: Any | None = None) -> list[PacketMetadata]:
    """Captures on the given interface (or the auto-detected Wi-Fi
    interface) for exactly duration_seconds, then returns. Never runs
    indefinitely -- Scapy's own `timeout` bounds the sniff regardless of
    packet count. Payload contents are never stored: `store=False` keeps
    Scapy from retaining captured packets past the per-packet callback,
    and only extract_packet_metadata()'s output is collected."""
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")

    _require_scapy()
    target_iface = iface if iface is not None else find_wifi_interface()

    collected: list[PacketMetadata] = []

    def _on_packet(packet: Any) -> None:
        metadata = extract_packet_metadata(packet)
        if metadata is not None:
            collected.append(metadata)

    logger.info("Starting capture on %s for %ds", getattr(target_iface, "name", target_iface), duration_seconds)
    try:
        sniff(iface=target_iface, prn=_on_packet, store=False, timeout=duration_seconds)
    except PermissionError as exc:
        raise CaptureError("Permission denied opening the capture interface -- try running as Administrator.") from exc
    except OSError as exc:
        raise CaptureError(f"Failed to capture on interface {target_iface!r} -- is Npcap installed and the interface up? ({exc})") from exc

    logger.info("Capture finished: %d packet(s) captured", len(collected))
    return collected


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    results = capture_packets()
    for meta in results:
        print(f"{meta.timestamp.isoformat()} {meta.protocol:<10} {meta.source_ip}:{meta.source_port} -> {meta.destination_ip}:{meta.destination_port} ({meta.length}B)")
    print(f"Total: {len(results)} packet(s)")


if __name__ == "__main__":
    main()
