"""Administrator authentication -- section 11: secure password hashing
(bcrypt), no plaintext storage, kept modular and deliberately simple
(single-admin academic app, not enterprise IAM)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.app.core.security import hash_password, verify_password
from backend.app.models.user import User


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).first()


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = get_user_by_username(db, username)
    if user is None or not verify_password(password, user.hashed_password):
        return None
    return user


def ensure_seed_admin(db: Session, username: str, password: str) -> User:
    """Creates the admin account if no user exists yet at all -- idempotent,
    safe to call on every startup."""
    existing = db.query(User).first()
    if existing is not None:
        return existing
    user = User(username=username, hashed_password=hash_password(password), is_admin=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
