"""SQLAlchemy declarative base. All ORM models (backend/app/models/) inherit
from this so Alembic autogenerate and Base.metadata.create_all() see every
table from one place."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
