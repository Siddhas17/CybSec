"""Pydantic schemas for victim_agent identity/registration/heartbeat
(Phase 1). AgentRegisterOut is the only place the plaintext agent token
ever appears -- never re-returned by any other endpoint."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentRegisterIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    operating_system: str | None = Field(default=None, max_length=128)
    ip_address: str | None = Field(default=None, max_length=64)
    agent_version: str | None = Field(default=None, max_length=32)


class AgentRegisterOut(BaseModel):
    agent_id: str
    agent_token: str
    rotated: bool


class AgentStatusUpdateIn(BaseModel):
    status: Literal["active", "disabled"]


class AgentHeartbeatIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    timestamp: datetime | None = None
    ip_address: str | None = Field(default=None, max_length=64)
    agent_version: str | None = Field(default=None, max_length=32)


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: str
    hostname: str
    ip_address: str | None
    agent_version: str | None
    status: str
    last_seen: datetime | None
    created_at: datetime
    online: bool
