#!/usr/bin/env python3
"""Runs inside an isolated, unprivileged (user+net) network namespace
created by the parent process (sensor.collectors.netns_loopback --
NetnsLoopbackCollector.start()). Never invoked directly against a shared
host interface -- the isolation boundary (section 4/8 of the phase
instructions: an authorized, isolated lab source, not arbitrary sniffing
of a shared adapter) is created by the caller before this script runs.

Emits one JSON line per captured packet on stdout (line-buffered) so the
parent can read it over a plain pipe -- no shared memory, no raw payload
bytes ever leave this process (section 21: nothing here writes packet
captures to disk).
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import warnings

# scapy's TLS layer imports a deprecated cryptography API at import time,
# which would otherwise print to stderr and get mistaken for a real
# capture error by netns_loopback.py::_read_stderr (which treats every
# stderr line as a health-affecting last_error) -- this is a benign
# library warning (CryptographyDeprecationWarning subclasses UserWarning,
# not DeprecationWarning, so the default filter does not already hide it),
# not a fault in this worker.
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from scapy.all import IP, TCP, UDP, sniff  # heavy import kept local to this subprocess only

_stop = False


def _handle_signal(_signum, _frame) -> None:
    global _stop
    _stop = True


def _bring_up_loopback() -> None:
    subprocess.run(["ip", "link", "set", "dev", "lo", "up"], check=True, capture_output=True, timeout=5)


def _emit(record: dict) -> None:
    sys.stdout.write(json.dumps(record) + "\n")
    sys.stdout.flush()


def _parse_packet(pkt) -> dict | None:
    if IP not in pkt:
        return None  # non-IPv4 (e.g. IPv6 on lo) -- out of scope, matches CICIDS2017's IPv4-only data
    ip = pkt[IP]
    total_length = int(ip.len) if ip.len is not None else len(pkt)
    ip_header_len = int(ip.ihl) * 4 if ip.ihl else 20

    src_port = dst_port = None
    tcp_flags = None
    tcp_window = None
    transport_header_len = 0

    if TCP in pkt:
        tcp = pkt[TCP]
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        transport_header_len = int(tcp.dataofs) * 4 if tcp.dataofs else 20
        flag_str = str(tcp.flags)
        tcp_flags = {
            "fin": "F" in flag_str,
            "syn": "S" in flag_str,
            "rst": "R" in flag_str,
            "psh": "P" in flag_str,
            "ack": "A" in flag_str,
            "urg": "U" in flag_str,
            "ece": "E" in flag_str,
            "cwr": "C" in flag_str,
        }
        tcp_window = int(tcp.window)
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port, dst_port = int(udp.sport), int(udp.dport)
        transport_header_len = 8
    # else (e.g. ICMP): ports/flags/window stay None -- protocol alone carries the information.

    payload_length = max(0, total_length - ip_header_len - transport_header_len)

    return {
        "type": "packet",
        "timestamp": float(pkt.time),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": int(ip.proto),
        "total_length": total_length,
        "ip_header_length": ip_header_len,
        "transport_header_length": transport_header_len,
        "payload_length": payload_length,
        "tcp_flags": tcp_flags,
        "tcp_window": tcp_window,
    }


def _on_packet(pkt) -> None:
    try:
        record = _parse_packet(pkt)
    except Exception as exc:  # a single malformed packet must never kill the capture loop (section 13)
        _emit({"type": "parse_error", "error": str(exc)})
        return
    if record is not None:
        _emit(record)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="lo")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _bring_up_loopback()
    _emit({"type": "ready", "interface": args.interface, "pid": os.getpid()})

    # timeout=1 so the loop re-checks _stop roughly once a second instead of
    # blocking in sniff() forever with no way to honor a stop request.
    while not _stop:
        sniff(iface=args.interface, store=False, prn=_on_packet, stop_filter=lambda _pkt: _stop, timeout=1)

    _emit({"type": "stopped"})


if __name__ == "__main__":
    main()
