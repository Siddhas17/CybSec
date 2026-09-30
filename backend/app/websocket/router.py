"""WebSocket endpoint. Clients connect to /ws/events, optionally
authenticating with ?token=<JWT> (same token as the REST API). The server
sends {"type": "connected", ...} on accept, periodic {"type": "heartbeat"}
pings, and {"type": "new_threat", "data": ThreatRowOut} whenever a new
event is persisted via ingestion or a test event.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db, require_admin
from backend.app.core.security import decode_access_token
from backend.app.models.user import User
from backend.app.websocket.manager import manager

router = APIRouter(tags=["websocket"])
logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL_SECONDS = 30


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, token: str | None = None) -> None:
    # Authentication is optional here by design: an unauthenticated
    # connection still receives live updates (matching a read-only
    # dashboard view), but the subject is recorded when a token IS
    # supplied, for future audit use. REST endpoints remain the
    # authenticated surface for anything that mutates state.
    username = decode_access_token(token) if token else None

    await manager.connect(websocket)
    await websocket.send_json({"type": "connected", "data": {"authenticated_as": username}})

    heartbeat_task = asyncio.create_task(_heartbeat_loop(websocket))
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket connection error")
    finally:
        heartbeat_task.cancel()
        manager.disconnect(websocket)


@router.websocket("/ws/admin/victim-flow-scores")
async def admin_victim_flow_scores(
    websocket: WebSocket,
    token: str | None = None,
    db: Session = Depends(get_db),
) -> None:
    if not token:
        await websocket.close(code=4401)
        return

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    try:
        user: User = get_current_user(credentials=credentials, db=db)
        require_admin(user)
    except HTTPException as exc:
        await websocket.close(code=4403 if exc.status_code == 403 else 4401)
        return

    await manager.connect_admin_flow_scores(websocket)
    heartbeat_task = asyncio.create_task(_heartbeat_loop(websocket))
    try:
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("Admin flow-score WebSocket connection error")
    finally:
        heartbeat_task.cancel()
        manager.disconnect_admin_flow_scores(websocket)


async def _heartbeat_loop(websocket: WebSocket) -> None:
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            await websocket.send_json({"type": "heartbeat", "data": {}})
    except (asyncio.CancelledError, Exception):
        return
