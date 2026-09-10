"""Shared FastAPI dependencies: DB session (re-exported), the
authenticated-user check, the admin-only check, and the victim_agent
machine-auth check (get_current_agent -- a separate principal type from
User, never a JWT)."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.app.core.security import decode_access_token
from backend.app.db.session import get_db
from backend.app.models.agent import Agent
from backend.app.models.user import User
from backend.app.services import agent_service
from backend.app.services.auth_service import get_user_by_username

__all__ = ["get_db", "get_current_user", "require_admin", "get_current_agent"]

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    username = decode_access_token(credentials.credentials)
    if username is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    user = get_user_by_username(db, username)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found", headers={"WWW-Authenticate": "Bearer"})
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Gate for Reports and Model Evaluation endpoints -- the only place
    `User.is_admin` is actually enforced anywhere in this codebase today.
    Not retrofitted onto pre-existing endpoints; those are unchanged."""
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return user


def get_current_agent(
    x_agent_id: str | None = Header(default=None, alias="X-Agent-Id"),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Agent:
    """Machine-auth for victim_agent (Phase 1) -- never the human JWT path.
    X-Agent-Id identifies which row to check (bcrypt hashes can't be looked
    up by value); Authorization: Bearer carries the per-agent secret token.
    A single uniform 401 for every failure mode (missing headers, unknown
    agent_id, wrong token) -- never distinguishes "no such agent" from "bad
    token" in the response."""
    if x_agent_id is None or credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid agent credentials", headers={"WWW-Authenticate": "Bearer"})
    agent = agent_service.authenticate_agent(db, x_agent_id, credentials.credentials)
    if agent is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid agent credentials", headers={"WWW-Authenticate": "Bearer"})
    agent_service.touch_last_seen(db, agent)
    return agent
