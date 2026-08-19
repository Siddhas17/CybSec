"""Response adapter interface (section 7 of the phase instructions). A
response adapter is the only kind of object in this codebase permitted to
attempt a real system-level response action -- API route handlers and
`response_service` never call a firewall/shell command directly, only
through an adapter implementing this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterResult:
    success: bool
    actual_action: str  # "would_block" | "blocked" | "unblocked" | "failed"
    message: str


class ResponseAdapter(ABC):
    name: str

    @abstractmethod
    def dry_run(self, target_ip: str, reason: str) -> AdapterResult:
        """Simulates a block: validates the request path is reachable,
        never modifies real state. Must not raise -- return a failed
        AdapterResult instead, so a caller can always record an audit row."""
        ...

    @abstractmethod
    def block(self, target_ip: str, reason: str) -> AdapterResult:
        """Attempts a real block. Must not raise for an expected failure
        mode (e.g. no privileged backend available) -- return
        AdapterResult(success=False, ...) so the caller can audit the
        failure rather than losing it to an unhandled exception."""
        ...

    @abstractmethod
    def unblock(self, target_ip: str) -> AdapterResult:
        """Reverses a previous successful block. Must not raise."""
        ...
