"""FastAPI application entrypoint (app factory pattern).

Run with:
    uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
(from the project root, with the attack-graph-ids conda env active)
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.core.logging import configure_logging
from backend.app.db.session import SessionLocal
from backend.app.services.auth_service import ensure_seed_admin
from backend.app.websocket.router import router as websocket_router

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    db = SessionLocal()
    try:
        user = ensure_seed_admin(db, settings.admin_username, settings.admin_password)
        logger.info("Seed admin account ready: %s", user.username)
    finally:
        db.close()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Intelligent Cybersecurity System Using Attack Graphs -- API",
        description=(
            "Application layer around the validated Phase 1-4 analytical core. "
            "Offline dataset demonstration mode only -- no live network monitoring, "
            "no automatic prevention. See docs/application_architecture.md."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)
    app.include_router(websocket_router)

    return app


app = create_app()
