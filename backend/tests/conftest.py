"""Backend test fixtures: an isolated in-memory SQLite database per test
(never the real MySQL demo data, never the full CICIDS2017 dataset --
section 16). The trained Phase 3/4 artifacts (ml/models/artifacts/,
risk_engine/output/) ARE reused as-is since they're small, fast-loading,
already-committed-adjacent build outputs, not the raw dataset.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.app.models  # noqa: F401 -- registers every table on Base.metadata
from backend.app.api.deps import get_db
from backend.app.core.config import settings
from backend.app.db.base import Base


@pytest.fixture()
def test_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture()
def TestingSessionLocal(test_engine):
    return sessionmaker(bind=test_engine, autoflush=False, autocommit=False)


@pytest.fixture()
def db_session(TestingSessionLocal):
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(monkeypatch, TestingSessionLocal, db_session):
    """A TestClient wired to the isolated SQLite DB -- including the app's
    startup event (which seeds the admin user), by monkeypatching the
    SessionLocal the startup hook uses."""
    import backend.app.main as main_module

    monkeypatch.setattr(main_module, "SessionLocal", TestingSessionLocal)

    def _override_get_db():
        yield db_session

    main_module.app.dependency_overrides[get_db] = _override_get_db
    with TestClient(main_module.app) as c:
        yield c
    main_module.app.dependency_overrides.clear()


@pytest.fixture()
def auth_headers(client):
    response = client.post("/api/v1/auth/login", json={"username": settings.admin_username, "password": settings.admin_password})
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
