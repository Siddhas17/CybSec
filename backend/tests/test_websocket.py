"""Section 16: WebSocket connection, and the end-to-end
test-event -> DB -> API -> WebSocket flow."""

from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from backend.app.core.security import create_access_token, hash_password
from backend.app.models.user import User


def test_websocket_connects_and_sends_connected_message(client):
    with client.websocket_connect("/ws/events") as ws:
        message = ws.receive_json()
        assert message["type"] == "connected"


def test_websocket_ping_pong(client):
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()  # the initial "connected" message
        ws.send_text("ping")
        response = ws.receive_text()
        assert response == "pong"


def test_websocket_clean_disconnect_does_not_raise(client):
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()
    # exiting the `with` block disconnects; no exception should propagate


def test_admin_flow_score_websocket_accepts_admin_jwt(client, auth_headers):
    token = auth_headers["Authorization"].removeprefix("Bearer ")
    with client.websocket_connect(f"/ws/admin/victim-flow-scores?token={token}") as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "pong"


def test_admin_flow_score_websocket_rejects_unauthenticated_connection(client):
    with pytest.raises(WebSocketDisconnect) as disconnected:
        with client.websocket_connect("/ws/admin/victim-flow-scores"):
            pass
    assert disconnected.value.code == 4401


def test_admin_flow_score_websocket_rejects_non_admin_user(client, db_session):
    user = User(username="analyst", hashed_password=hash_password("analyst-pw"), is_admin=False)
    db_session.add(user)
    db_session.commit()
    token = create_access_token(subject=user.username)

    with pytest.raises(WebSocketDisconnect) as disconnected:
        with client.websocket_connect(f"/ws/admin/victim-flow-scores?token={token}"):
            pass
    assert disconnected.value.code == 4403


def test_end_to_end_test_event_reaches_websocket(client, auth_headers):
    """test event -> analytical result -> DB (via the API) -> WebSocket
    broadcast -- the full section-16 end-to-end requirement."""
    with client.websocket_connect("/ws/events") as ws:
        ws.receive_json()  # "connected"

        response = client.post(
            "/api/v1/test-events",
            json={"source_ip": "172.31.0.1", "destination_ip": "172.31.0.2"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        event_id = response.json()["event_id"]

        broadcast = ws.receive_json()
        assert broadcast["type"] == "new_threat"
        assert broadcast["data"]["event_id"] == event_id
        assert broadcast["data"]["source_ip"] == "172.31.0.1"

    # and the event really is retrievable via the REST API afterward
    detail = client.get(f"/api/v1/events/{event_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["source"] == "test_event"
