"""Validated identifier handling (section 5/6 of the phase instructions).
Every IP address a response action would operate on passes through
`validate_lab_target()` first -- an API caller's raw string is never
handed to a response adapter directly.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from backend.app.core.config import settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class InvalidTargetError(ValueError):
    """A proposed response target failed validation. `.reason` is safe to
    surface to an API caller and to store verbatim in an audit record --
    it never includes anything beyond the rejected IP and why."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ValidatedTarget:
    ip: str
    scope: str  # which lab CIDR matched, or the loopback-exception label


def _lab_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parses `settings.lab_network_cidrs` fresh on every call (not cached
    at import time) so a config change takes effect without a restart of
    this specific check -- consistent with the rest of `settings` already
    being read live throughout the backend. A malformed entry is skipped,
    not fatal to the whole allowlist, since one bad entry in an operator's
    config shouldn't silently make every response action fail closed with
    an unrelated-looking error."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in settings.lab_network_cidrs.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
    return networks


def validate_lab_target(raw_ip: str) -> ValidatedTarget:
    """Rejects: unparseable input, multicast/unspecified/broadcast/
    IANA-reserved addresses, loopback (unless explicitly enabled), and
    anything outside the configured lab CIDR allowlist. Raises
    `InvalidTargetError` rather than returning a sentinel, so a caller
    cannot forget to check a boolean and silently proceed."""
    candidate = (raw_ip or "").strip()
    try:
        ip_obj: IPAddress = ipaddress.ip_address(candidate)
    except ValueError:
        raise InvalidTargetError(f"{candidate!r} is not a valid IP address")

    if ip_obj.is_multicast:
        raise InvalidTargetError(f"{candidate} is a multicast address -- never a valid response target")
    if ip_obj.is_unspecified:
        raise InvalidTargetError(f"{candidate} is the unspecified address -- never a valid response target")
    if candidate == "255.255.255.255":
        raise InvalidTargetError(f"{candidate} is the broadcast address -- never a valid response target")
    if ip_obj.is_reserved:
        raise InvalidTargetError(f"{candidate} is an IANA-reserved address -- never a valid response target")

    if ip_obj.is_loopback:
        if not settings.lab_allow_loopback_target:
            raise InvalidTargetError(
                f"{candidate} is a loopback address, rejected by default -- set LAB_ALLOW_LOOPBACK_TARGET=true "
                "to permit this explicitly (e.g. for a loopback-only sensor lab, see docs/live_telemetry.md section 1)"
            )
        return ValidatedTarget(ip=str(ip_obj), scope="loopback (LAB_ALLOW_LOOPBACK_TARGET=true)")

    for network in _lab_networks():
        if ip_obj in network:
            return ValidatedTarget(ip=str(ip_obj), scope=str(network))

    raise InvalidTargetError(f"{candidate} is outside the configured lab network scope ({settings.lab_network_cidrs})")
