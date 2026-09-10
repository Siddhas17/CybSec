"""Lightweight victim-laptop agent (Phase 1): identity, registration,
heartbeat, and raw connection-telemetry reporting to the Admin backend.
Run as a package (`python -m victim_agent.agent`), never as a loose
script -- this is deliberate: a top-level `queue.py` module name would
shadow Python's stdlib `queue` (used internally by httpx and others) if
this directory were ever put on sys.path directly instead of imported as
the `victim_agent` package. See README.md for setup and usage."""
