from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.core.security import create_access_token
from backend.app.models.user import User
from backend.app.schemas.auth import CurrentUserOut, LoginRequest, TokenResponse
from backend.app.services import audit
from backend.app.services.auth_service import authenticate

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate(db, payload.username, payload.password)
    if user is None:
        audit.log(db, "WARNING", "auth", f"Failed login attempt for username={payload.username!r}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    audit.log(db, "INFO", "auth", f"User {user.username!r} logged in", user_id=user.id)
    token = create_access_token(subject=user.username)
    return TokenResponse(access_token=token)


@router.get("/me", response_model=CurrentUserOut)
def me(current_user: User = Depends(get_current_user)) -> CurrentUserOut:
    return CurrentUserOut(username=current_user.username, is_admin=current_user.is_admin)
