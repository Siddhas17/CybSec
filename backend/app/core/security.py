"""Password hashing (bcrypt, called directly) and JWT issuance/verification
(python-jose). No plaintext passwords are ever stored or logged.

Uses the `bcrypt` library directly rather than passlib's CryptContext
wrapper: passlib 1.7.4 (last released 2020) runs an internal self-test
against modern bcrypt (>=4.1, which enforces the 72-byte input limit
strictly) that raises ValueError before any real password is even
hashed -- a documented upstream incompatibility, not specific to this
project. bcrypt's own API is stable and sufficient for a single-admin
academic app (section 11: no need for passlib's multi-scheme abstraction
here).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import bcrypt
from jose import JWTError, jwt

from backend.app.core.config import settings

_MAX_BCRYPT_BYTES = 72


def hash_password(plain_password: str) -> str:
    password_bytes = plain_password.encode("utf-8")[:_MAX_BCRYPT_BYTES]
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode("utf-8")[:_MAX_BCRYPT_BYTES]
    return bcrypt.checkpw(password_bytes, hashed_password.encode("utf-8"))


def create_access_token(subject: str, expires_minutes: int | None = None) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=expires_minutes or settings.jwt_expire_minutes)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> str | None:
    """Returns the token subject (username) if valid, else None."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None
    return payload.get("sub")
