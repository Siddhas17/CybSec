"""victim_agent entrypoint. Run as `python -m victim_agent.agent` from the
directory that contains the victim_agent/ folder (never `python
victim_agent/agent.py` directly -- see victim_agent/__init__.py for why).

Loads config -> loads/creates a stable local identity -> registers once if
no token is persisted yet -> runs heartbeat (default 15s) and telemetry
(default 5s) on independent schedules in one simple loop. Every cycle is
wrapped in try/except so one failed collection/send never kills the
process; a failed telemetry batch is queued (bounded, logged eviction) and
retried opportunistically; a failed heartbeat is just logged and
superseded by the next cycle. Never logs the agent token."""

from __future__ import annotations

import logging
import sys
import time
from datetime import UTC, datetime

from victim_agent import telemetry
from victim_agent.config import AgentConfig, load_config
from victim_agent.identity import AgentIdentity, load_or_create_identity, save_token
from victim_agent.queue import BoundedRetryQueue
from victim_agent.sender import AgentSender, SenderError

logger = logging.getLogger("victim_agent")


def setup_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level, logging.INFO), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")


def ensure_registered(config: AgentConfig, identity: AgentIdentity, sender: AgentSender) -> None:
    if identity.token is not None:
        logger.info("Using existing identity agent_id=%s", identity.agent_id)
        return

    if not config.agent_enrollment_key:
        logger.error("No local token and AGENT_ENROLLMENT_KEY is not set -- cannot register. Configure victim_agent/.env and try again.")
        sys.exit(1)

    logger.info("No local token found -- registering agent_id=%s with %s", identity.agent_id, config.admin_base_url)
    payload = {
        "agent_id": identity.agent_id,
        "hostname": telemetry.get_hostname(),
        "operating_system": sys.platform,
        "ip_address": telemetry.get_primary_local_ip(),
        "agent_version": "0.1.0",
    }
    try:
        result = sender.register(payload)
    except SenderError as exc:
        logger.error("Registration failed, cannot start without an identity: %s", exc)
        sys.exit(1)

    save_token(config, identity, result["agent_token"])
    logger.info("Registered successfully (rotated=%s)", result.get("rotated", False))


def do_heartbeat(config: AgentConfig, identity: AgentIdentity, sender: AgentSender) -> None:
    payload = {
        "agent_id": identity.agent_id,
        "hostname": telemetry.get_hostname(),
        "timestamp": datetime.now(UTC).isoformat(),
        "ip_address": telemetry.get_primary_local_ip(),
        "agent_version": "0.1.0",
    }
    try:
        sender.send_heartbeat(payload, identity.agent_id, identity.token)
        logger.info("Heartbeat sent")
    except SenderError as exc:
        # Not queued -- superseded by the next heartbeat cycle regardless.
        logger.warning("Heartbeat failed, will retry on the next cycle: %s", exc)


def collect_telemetry_batch(identity: AgentIdentity) -> dict:
    return {
        "agent_id": identity.agent_id,
        "hostname": telemetry.get_hostname(),
        "timestamp": datetime.now(UTC).isoformat(),
        "local_ip": telemetry.get_primary_local_ip(),
        "connections": telemetry.get_connections(),
    }


def do_telemetry(identity: AgentIdentity, sender: AgentSender, retry_queue: BoundedRetryQueue) -> None:
    batch = collect_telemetry_batch(identity)
    try:
        result = sender.send_telemetry_batch(batch, identity.agent_id, identity.token)
        logger.info("Telemetry sent: %d connection(s) accepted", result.get("connections_received", 0))
    except SenderError as exc:
        logger.warning("Telemetry send failed, queueing for retry: %s", exc)
        retry_queue.push(batch)


def flush_queue(identity: AgentIdentity, sender: AgentSender, retry_queue: BoundedRetryQueue) -> None:
    if len(retry_queue) == 0:
        return

    def _send(item: dict) -> None:
        sender.send_telemetry_batch(item, identity.agent_id, identity.token)

    sent = retry_queue.flush(_send)
    if sent:
        logger.info("Flushed %d queued telemetry batch(es) (%d remaining)", sent, len(retry_queue))


def run(config: AgentConfig) -> None:
    identity = load_or_create_identity(config)
    sender = AgentSender(config)
    retry_queue = BoundedRetryQueue(config.max_queue_size)

    ensure_registered(config, identity, sender)

    next_heartbeat = 0.0
    next_telemetry = 0.0
    logger.info("Agent loop starting (heartbeat=%ds, telemetry=%ds) -- Ctrl+C to stop", config.heartbeat_interval_seconds, config.telemetry_interval_seconds)

    try:
        while True:
            now = time.monotonic()

            if now >= next_heartbeat:
                try:
                    do_heartbeat(config, identity, sender)
                except Exception:  # never let one bad cycle kill the process
                    logger.exception("Unexpected error during heartbeat cycle")
                next_heartbeat = now + config.heartbeat_interval_seconds

            if now >= next_telemetry:
                try:
                    do_telemetry(identity, sender, retry_queue)
                except Exception:
                    logger.exception("Unexpected error during telemetry cycle")
                next_telemetry = now + config.telemetry_interval_seconds

            try:
                flush_queue(identity, sender, retry_queue)
            except Exception:
                logger.exception("Unexpected error flushing retry queue")

            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping (Ctrl+C received)")
    finally:
        sender.close()


def main() -> None:
    config = load_config()
    setup_logging(config.log_level)
    run(config)


if __name__ == "__main__":
    main()
