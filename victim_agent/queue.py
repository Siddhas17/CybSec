"""Bounded local retry queue for telemetry batches, used when the Admin is
temporarily unreachable. A plain collections.deque(maxlen=N) evicts the
oldest item silently on overflow -- this wrapper always logs an eviction
before it happens, per the requirement that data is never silently lost.
Heartbeats are NOT queued here (see agent.py): a failed heartbeat is
superseded by the next one on the following cycle, so queuing it would add
complexity for a self-correcting signal."""

from __future__ import annotations

import logging
from collections import deque
from typing import Callable

logger = logging.getLogger(__name__)


class BoundedRetryQueue:
    def __init__(self, maxsize: int):
        self._maxsize = maxsize
        self._items: deque = deque()

    def __len__(self) -> int:
        return len(self._items)

    def push(self, item: dict) -> None:
        if len(self._items) >= self._maxsize:
            dropped = self._items.popleft()
            logger.warning("Retry queue full (max=%d) -- discarding oldest queued telemetry batch (agent_id=%s, timestamp=%s)", self._maxsize, dropped.get("agent_id"), dropped.get("timestamp"))
        self._items.append(item)

    def flush(self, send_fn: Callable[[dict], None]) -> int:
        """Attempts to send every queued item in order. Stops at the first
        failure and leaves it (and everything after it) queued for the
        next cycle -- never reorders, never drops on a flush failure."""
        sent = 0
        while self._items:
            item = self._items[0]
            try:
                send_fn(item)
            except Exception as exc:  # noqa: BLE001 -- caller's send_fn defines what "failure" means
                logger.warning("Queue flush stopped after %d item(s): %s", sent, exc)
                break
            self._items.popleft()
            sent += 1
        return sent
