from __future__ import annotations

import httpx
import pytest

from victim_agent import sender as sender_module
from victim_agent.sender import AgentSender, SenderError


class _FakeResponse:
    def __init__(self, status_code: int, data: dict | None = None):
        self.status_code = status_code
        self._data = data or {}
        self.text = str(data)

    def json(self) -> dict:
        return self._data


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    # Backoff sleeps would make these tests slow; retry/backoff logic itself
    # is exercised via call counts, not wall-clock time.
    monkeypatch.setattr(sender_module.time, "sleep", lambda _seconds: None)


@pytest.fixture()
def agent_sender(make_config):
    s = AgentSender(make_config())
    yield s
    s.close()


def test_succeeds_on_first_attempt(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(200, {"ok": True})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    result = agent_sender.send_heartbeat({"agent_id": "victim-01"}, "victim-01", "tok")
    assert result == {"ok": True}
    assert len(calls) == 1


def test_retries_on_connect_error_then_succeeds(agent_sender, monkeypatch):
    attempts = {"n": 0}

    def fake_post(path, json, headers):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx.ConnectError("connection refused")
        return _FakeResponse(200, {"ok": True})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    result = agent_sender.send_telemetry_batch({"agent_id": "victim-01"}, "victim-01", "tok")
    assert result == {"ok": True}
    assert attempts["n"] == 3


def test_gives_up_after_max_attempts_on_persistent_connect_error(agent_sender, monkeypatch):
    def fake_post(path, json, headers):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.send_telemetry_batch({"agent_id": "victim-01"}, "victim-01", "tok")


def test_4xx_response_is_not_retried(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(401, {"detail": "Invalid agent credentials"})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.send_heartbeat({"agent_id": "victim-01"}, "victim-01", "bad-tok")
    assert len(calls) == 1  # no retry for a 4xx


def test_5xx_response_is_retried_then_fails(agent_sender, monkeypatch):
    calls = []

    def fake_post(path, json, headers):
        calls.append(path)
        return _FakeResponse(500, {"detail": "boom"})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    with pytest.raises(SenderError):
        agent_sender.send_telemetry_batch({"agent_id": "victim-01"}, "victim-01", "tok")
    assert len(calls) == 3  # retried up to the max attempts


def test_register_sends_enrollment_key_header_not_agent_headers(agent_sender, monkeypatch):
    seen_headers = {}

    def fake_post(path, json, headers):
        seen_headers.update(headers)
        return _FakeResponse(200, {"agent_id": "victim-01", "agent_token": "new-token", "rotated": False})

    monkeypatch.setattr(agent_sender._client, "post", fake_post)
    agent_sender.register({"agent_id": "victim-01", "hostname": "VICTIM-PC1"})
    assert seen_headers == {"X-Enrollment-Key": "test-key"}
