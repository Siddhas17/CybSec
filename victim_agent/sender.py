"""HTTP client for talking to the Admin backend. Bounded retry/backoff for
transient network failures (timeouts, connection errors, 5xx) -- never
retries indefinitely, and never retries a 4xx (a bad credential or
malformed payload won't succeed on retry). Never logs the agent token or
enrollment key."""

from __future__ import annotations

import logging
import time

import httpx

from victim_agent.config import AgentConfig

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = (1, 2, 4)


class SenderError(Exception):
    """Raised when a request could not be completed -- caller decides
    whether to enqueue for later retry (telemetry) or just log and wait for
    the next cycle (heartbeat)."""


class AgentSender:
    def __init__(self, config: AgentConfig):
        self._config = config
        self._client = httpx.Client(base_url=config.api_base_url, timeout=config.request_timeout_seconds)

    def close(self) -> None:
        self._client.close()

    def register(self, payload: dict) -> dict:
        headers = {"X-Enrollment-Key": self._config.agent_enrollment_key}
        return self._post_with_retry("/agents/register", payload, headers)

    def send_heartbeat(self, payload: dict, agent_id: str, token: str) -> dict:
        headers = self._agent_headers(agent_id, token)
        return self._post_with_retry("/agents/heartbeat", payload, headers)

    def send_telemetry_batch(self, payload: dict, agent_id: str, token: str) -> dict:
        headers = self._agent_headers(agent_id, token)
        return self._post_with_retry("/telemetry/events", payload, headers)

    def score_flow(self, payload: dict, agent_id: str, token: str) -> dict:
        """Submits one completed victim_agent.flow.Flow's already-computed
        representation (source_ip, destination_ip, source_port,
        destination_port, protocol, timestamp, and the 67-name
        Flow.to_cicids_features() dict -- built by the caller, never
        recomputed here) to POST /agents/flow-score, and returns the
        backend's score-only response (risk_score/risk_level/etc, never
        persisted server-side for this checkpoint)."""
        headers = self._agent_headers(agent_id, token)
        return self._post_with_retry("/agents/flow-score", payload, headers)

    @staticmethod
    def _agent_headers(agent_id: str, token: str) -> dict:
        return {"X-Agent-Id": agent_id, "Authorization": f"Bearer {token}"}

    def _post_with_retry(self, path: str, payload: dict, headers: dict) -> dict:
        last_error: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                response = self._client.post(path, json=payload, headers=headers)
            except (httpx.TimeoutException, httpx.ConnectError, httpx.TransportError) as exc:
                last_error = exc
                logger.warning("Request to %s failed (attempt %d/%d): %s", path, attempt + 1, _MAX_ATTEMPTS, exc)
            else:
                if response.status_code < 300:
                    return response.json()
                if response.status_code < 500:
                    # 4xx -- bad credentials/payload, retrying won't help.
                    raise SenderError(f"{path} rejected the request: HTTP {response.status_code} {response.text}")
                last_error = SenderError(f"{path} returned HTTP {response.status_code}: {response.text}")
                logger.warning("Request to %s failed (attempt %d/%d): %s", path, attempt + 1, _MAX_ATTEMPTS, last_error)

            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(_BACKOFF_SECONDS[attempt])

        raise SenderError(f"{path} failed after {_MAX_ATTEMPTS} attempts: {last_error}")
