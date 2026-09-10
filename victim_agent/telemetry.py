"""Real OS-level telemetry collection via psutil only -- hostname, local
IPv4 addresses, and active TCP/UDP connections. Never fabricates data: if
psutil can't see something (e.g. AccessDenied without elevation), this
module logs a WARNING and returns a partial/empty result rather than
inventing values. Collects only connection metadata (addresses, ports,
protocol, status) -- never passwords, keystrokes, browser contents, or
other file/user data."""

from __future__ import annotations

import logging
import socket

import psutil

logger = logging.getLogger(__name__)

_SOCK_TYPE_TO_PROTOCOL = {
    socket.SOCK_STREAM: "TCP",
    socket.SOCK_DGRAM: "UDP",
}


def get_hostname() -> str:
    return socket.gethostname()


def get_local_ipv4s() -> list[str]:
    addrs: list[str] = []
    try:
        for interface_addrs in psutil.net_if_addrs().values():
            for addr in interface_addrs:
                if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                    addrs.append(addr.address)
    except (psutil.Error, OSError) as exc:
        logger.warning("Could not enumerate local IPv4 addresses: %s", exc)
    return addrs


def get_primary_local_ip() -> str:
    addrs = get_local_ipv4s()
    return addrs[0] if addrs else "127.0.0.1"


def get_connections() -> list[dict]:
    """Returns a list of {local_ip, local_port, remote_ip, remote_port,
    protocol, status} dicts for currently active inet connections. Skips
    (and logs at DEBUG) any connection whose socket type isn't TCP/UDP or
    that has no local address; never raises for a single bad entry."""
    connections: list[dict] = []
    try:
        raw_connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as exc:
        logger.warning("Permission denied reading connection table (try running elevated): %s", exc)
        return []
    except (psutil.Error, OSError) as exc:
        logger.warning("Failed to read connection table: %s", exc)
        return []

    for conn in raw_connections:
        try:
            protocol = _SOCK_TYPE_TO_PROTOCOL.get(conn.type)
            if protocol is None or not conn.laddr:
                continue
            connections.append(
                {
                    "local_ip": conn.laddr.ip,
                    "local_port": conn.laddr.port,
                    "remote_ip": conn.raddr.ip if conn.raddr else None,
                    "remote_port": conn.raddr.port if conn.raddr else None,
                    "protocol": protocol,
                    "status": conn.status,
                }
            )
        except (AttributeError, ValueError) as exc:
            logger.debug("Skipping unparseable connection entry: %s", exc)
            continue

    return connections
