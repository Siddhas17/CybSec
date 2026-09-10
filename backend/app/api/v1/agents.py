"""victim_agent identity/registration/heartbeat (Phase 1). Registration is
gated by a one-time X-Enrollment-Key header (backend.app.core.config
.agent_enrollment_key), never the admin JWT and never a hardcoded secret.
Heartbeat/list use the machine-auth (get_current_agent) / human-JWT
(require_admin) dependencies respectively -- two distinct principal types,
never conflated."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_agent, get_db, require_admin
from backend.app.core.config import settings
from backend.app.models.agent import Agent
from backend.app.models.user import User
from backend.app.schemas.agent import AgentHeartbeatIn, AgentOut, AgentRegisterIn, AgentRegisterOut
from backend.app.services import agent_service, audit

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/register", response_model=AgentRegisterOut)
def register_agent(
    payload: AgentRegisterIn,
    x_enrollment_key: str | None = Header(default=None, alias="X-Enrollment-Key"),
    db: Session = Depends(get_db),
) -> AgentRegisterOut:
    # Checked before anything else, including any DB lookup -- a caller
    # without the key can never learn whether a given agent_id already
    # exists (structurally resolves the enumeration concern rather than by
    # hand-tuning error messages/timing).
    if not settings.agent_enrollment_key:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Agent enrollment is not configured")
    if not x_enrollment_key or not secrets.compare_digest(x_enrollment_key, settings.agent_enrollment_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment key")

    agent, token, rotated = agent_service.register_agent(db, payload)
    audit.log(
        db,
        "INFO",
        "agent",
        f"Agent {'re-enrolled (token rotated)' if rotated else 'registered'}: {agent.agent_id}",
        metadata={"agent_id": agent.agent_id, "hostname": agent.hostname},
    )
    return AgentRegisterOut(agent_id=agent.agent_id, agent_token=token, rotated=rotated)


@router.post("/heartbeat")
def agent_heartbeat(
    payload: AgentHeartbeatIn,
    db: Session = Depends(get_db),
    current_agent: Agent = Depends(get_current_agent),
) -> dict:
    if payload.agent_id != current_agent.agent_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="agent_id does not match authenticated agent")
    agent_service.touch_last_seen(db, current_agent, ip_address=payload.ip_address, agent_version=payload.agent_version)
    return {"accepted": True, "agent_id": current_agent.agent_id, "last_seen": current_agent.last_seen}


@router.get("", response_model=list[AgentOut])
def list_agents(db: Session = Depends(get_db), _current_user: User = Depends(require_admin)) -> list[AgentOut]:
    agents = db.query(Agent).order_by(Agent.agent_id).all()
    return [
        AgentOut(
            id=a.id,
            agent_id=a.agent_id,
            hostname=a.hostname,
            ip_address=a.ip_address,
            agent_version=a.agent_version,
            status=a.status,
            last_seen=a.last_seen,
            created_at=a.created_at,
            online=agent_service.is_online(a, settings.agent_offline_threshold_seconds),
        )
        for a in agents
    ]
