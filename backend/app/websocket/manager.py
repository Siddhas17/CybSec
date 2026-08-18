"""WebSocket connection management for live dashboard updates (section 8).

Broadcasts one typed payload per newly-persisted analytical event -- never
re-streams the whole database. Handles multiple concurrent clients,
disconnect cleanup, and per-client send failures without taking down
other connections.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._active: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active.add(websocket)
        logger.info("WebSocket connected (%d active)", len(self._active))

    def disconnect(self, websocket: WebSocket) -> None:
        self._active.discard(websocket)
        logger.info("WebSocket disconnected (%d active)", len(self._active))

    async def broadcast(self, event_type: str, payload: dict[str, Any]) -> None:
        """Sends {"type": event_type, "data": payload} to every connected
        client. Dead connections are dropped rather than raising."""
        if not self._active:
            return
        message = json.dumps({"type": event_type, "data": payload}, default=str)
        stale: list[WebSocket] = []
        for connection in self._active:
            try:
                await connection.send_text(message)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self._active.discard(connection)

    @property
    def connection_count(self) -> int:
        return len(self._active)


manager = ConnectionManager()
