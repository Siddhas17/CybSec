"""Pydantic schemas for raw victim_agent connection telemetry (Phase 1).
Validation here is deliberately strict (spec section 16) since this is the
one place external, untrusted machines write directly into MySQL -- IPs,
ports, protocol, and connection status are all checked before anything
reaches the DB layer."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# psutil's own CONN_* vocabulary (psutil.CONN_* constants) -- "NONE" is what
# psutil reports for UDP sockets, which have no connection-state concept.
_KNOWN_CONNECTION_STATUSES = {
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "NONE",
}


def _validate_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"not a valid IP address: {value!r}") from exc
    return value


class ConnectionIn(BaseModel):
    local_ip: str
    local_port: int | None = Field(default=None, ge=0, le=65535)
    remote_ip: str | None = None
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal["TCP", "UDP"]
    status: str | None = None

    @field_validator("local_ip")
    @classmethod
    def _check_local_ip(cls, v: str) -> str:
        return _validate_ip(v)  # type: ignore[return-value]

    @field_validator("remote_ip")
    @classmethod
    def _check_remote_ip(cls, v: str | None) -> str | None:
        return _validate_ip(v)

    @field_validator("status")
    @classmethod
    def _check_status(cls, v: str | None) -> str | None:
        if v is None:
            return None
        upper = v.upper()
        if upper not in _KNOWN_CONNECTION_STATUSES:
            raise ValueError(f"unrecognized connection status: {v!r}")
        return upper


class TelemetryBatchIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    timestamp: datetime
    local_ip: str
    connections: list[ConnectionIn] = []

    @field_validator("local_ip")
    @classmethod
    def _check_local_ip(cls, v: str) -> str:
        return _validate_ip(v)  # type: ignore[return-value]


class TelemetryBatchOut(BaseModel):
    accepted: bool
    connections_received: int
    agent_id: str
    timestamp: datetime


class TelemetryEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: int
    collected_at: datetime
    received_at: datetime
    hostname: str
    local_ip: str
    local_port: int | None
    remote_ip: str | None
    remote_port: int | None
    protocol: str
    connection_status: str | None
