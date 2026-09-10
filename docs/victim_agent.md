# Victim Agent (Phase 1: Identity, Registration, Heartbeat, Raw Telemetry)

## Status: implemented and verified end-to-end against a real backend with two distinct simulated victim laptops (2026-09-09)

> **This phase establishes real machine identity and real OS-connection
> telemetry ingestion. It does not detect anything.** Raw telemetry is
> validated and persisted, never scored. A future phase will build a
> feature extractor bridging this raw data to the trained autoencoder/KNN
> pipeline.

Not implemented (deliberately out of scope for this phase): any connection
between victim_agent telemetry and `AnalyticalPipeline.score()` (see
section 4), an admin-facing agent revoke/disable endpoint (the `agents.status`
column exists but has no toggle UI/API yet), persisting the victim_agent's
local retry queue to disk across restarts (it's in-memory only), a real
four-laptop LAN deployment (this phase was verified with two simulated
agents on the same development machine, pointed at a real backend over
HTTP -- the networking path is real, the physical second/third laptop is
not part of this repo's automated verification).

## 1. Why this exists

Before this phase, nothing in the codebase had any concept of a physical
machine other than the one running the backend itself -- no agent/host/
sensor identity table, no machine-auth mechanism (only human JWT), and no
HTTP endpoint that accepts telemetry from an external machine (the Phase 6
live sensor captures its own loopback traffic in-process; it never
receives a POST). This phase adds exactly that: identity, machine-auth,
heartbeat, and raw telemetry ingestion for real Windows victim laptops in
the lab.

## 2. Architecture

```
victim_agent (separate Windows laptop, own lightweight venv)
     |
     |  POST /api/v1/agents/register     (X-Enrollment-Key, one-time)
     |  POST /api/v1/agents/heartbeat    (X-Agent-Id + Bearer token)
     |  POST /api/v1/telemetry/events    (X-Agent-Id + Bearer token)
     v
Admin backend (this repo, FastAPI + MySQL)
     |
     +-- agents table            (identity, last_seen, computed "online")
     +-- agent_telemetry_events  (raw connection rows -- never scored)
     |
     v
GET /api/v1/agents, GET /api/v1/telemetry/events  (admin JWT, dashboard)
```

`backend/app/services/agent_service.py` owns all of this -- registration,
token rotation, `last_seen`/online computation, and telemetry persistence.
`backend/app/api/v1/agents.py` and `backend/app/api/v1/telemetry.py` are
thin route handlers, matching the project's existing "API layer stays
thin, services own the logic" convention (see `docs/live_telemetry.md`'s
`sensor.py` router for the same pattern).

## 3. Machine auth

A dedicated, non-JWT mechanism -- deliberately not the admin user's
username/password, and never a browser-copied JWT:

| Step | Mechanism |
|---|---|
| **Registration** (`POST /agents/register`) | Gated by a one-time shared secret, `X-Enrollment-Key`, checked against `Settings.agent_enrollment_key` (`AGENT_ENROLLMENT_KEY` in `.env`) using `secrets.compare_digest`. Checked *before* any DB lookup, so a caller without the key can never learn whether a given `agent_id` already exists. If the key isn't configured at all, registration refuses with 503 rather than silently accepting any/no key. |
| **Token issuance** | On success, a random `secrets.token_urlsafe(32)` is generated and returned once in the response body. Only its bcrypt hash (`backend.app.core.security.hash_password` -- reused as-is, it's a generic bcrypt wrapper, not user-password-specific) is stored, in `agents.token_hash`. |
| **Re-registration** | Registering an already-known `agent_id` with a valid enrollment key **rotates** its token (200, `rotated: true`) rather than refusing with 409 -- a re-imaged or identity-file-wiped laptop can recover without manual DB surgery. The old token stops working immediately. |
| **Heartbeat / telemetry auth** | Two headers: `X-Agent-Id` (which row to check) + `Authorization: Bearer <token>` (bcrypt-verified against `token_hash`). A single dependency, `get_current_agent` (`backend/app/api/deps.py`), handles this for both endpoints -- parallel to but entirely separate from `get_current_user`/`require_admin`. Every successful call bumps `agents.last_seen`, not just `/heartbeat`. |

## 4. Why raw telemetry is never scored

`backend/app/services/analytical_pipeline.py`'s `TelemetryEvent.features`
is built around the trained autoencoder's exact 67 named CICIDS2017-style
features (flow duration, packet-length statistics, inter-arrival-time
statistics, etc.). A victim_agent's telemetry is a point-in-time OS
connection snapshot from `psutil` -- local/remote IP, port, protocol,
connection status. It shares essentially zero fields with the trained
feature vector; running it through `AnalyticalPipeline.score()` would mean
~67 of ~67 features are imputed from training means, producing a
real-looking `anomaly_score`/`risk_score` that is actually
near-content-free. The existing `TestEventCreate` path already discloses
imputation for exactly this reason (`imputed_features` in its response) --
doing the same silently for agent telemetry would be worse, not
equivalent, since a `psutil` connection isn't even a partial flow.

So `agent_telemetry_events` is a dedicated table (`backend/app/models/
agent_telemetry_event.py`), one row per observed connection, matching
`Event`'s "one row per flow" convention but structurally separate from
`Event`/`Detection`/`RiskAssessment`. `backend/tests/test_telemetry_api.py
::test_telemetry_never_touches_the_scored_event_tables` asserts
`events`/`detections`/`risk_assessments` row counts are unchanged after
ingestion -- the regression test protecting this constraint.

**What the next phase needs to do:** inspect the trained preprocessing
pipeline (`ml/preprocessing/`) and build a legitimate live feature
extractor that produces the exact 67 named features from real traffic --
likely requiring the victim_agent (or a companion component) to observe
enough of a connection's lifecycle to compute flow-level statistics, not
just a point-in-time snapshot. Only then should agent-derived data feed
`AnalyticalPipeline.score()`.

## 5. Schema

**`agents`** (`backend/app/models/agent.py`): `id`, `agent_id` (unique),
`hostname`, `token_hash`, `ip_address`, `agent_version`, `status`
(administrative lifecycle flag, `"active"` by default -- distinct from
the dashboard's online/offline indicator), `last_seen`, `created_at`.

**`agent_telemetry_events`** (`backend/app/models/agent_telemetry_event.py`):
`id`, `agent_id` (FK, cascade delete), `collected_at` (agent's clock),
`received_at` (server insert time -- deliberately separate from
`collected_at` so telemetry delayed by the retry queue after an outage is
observable after the fact), `hostname`, `local_ip`, `local_port`,
`remote_ip` (nullable -- null for a `LISTEN` socket, never fabricated),
`remote_port`, `protocol` (`"TCP"`/`"UDP"`, psutil's own vocabulary, not
`Event.protocol`'s IANA integer), `connection_status` (psutil's `CONN_*`
vocabulary).

Migration: `backend/migrations/versions/627a550deef2_add_agents_and_agent_telemetry_events_.py`.

## 6. "Online" status

`GET /api/v1/agents` computes `online` per row via
`agent_service.is_online(agent, settings.agent_offline_threshold_seconds)`
-- `last_seen` within `AGENT_OFFLINE_THRESHOLD_SECONDS` (default 45,
independent of whatever heartbeat interval a given agent happens to be
configured with) counts as online. This is computed fresh on every read,
never stored, so it can't go stale.

## 7. Configuration

Backend (`.env`, see `.env.example`):

```
AGENT_ENROLLMENT_KEY=<generate your own, e.g. python -c "import secrets; print(secrets.token_urlsafe(32))">
AGENT_OFFLINE_THRESHOLD_SECONDS=45
```

Victim laptop (`victim_agent/.env`, see `victim_agent/.env.example`) --
entirely separate file, on a separate machine:

```
ADMIN_BASE_URL=http://<admin-laptop-lan-ip>:8000
AGENT_ENROLLMENT_KEY=<given to you by the Admin operator, out-of-band>
AGENT_ID=victim-01
HEARTBEAT_INTERVAL_SECONDS=15
TELEMETRY_INTERVAL_SECONDS=5
MAX_QUEUE_SIZE=1000
```

## 8. Operational runbook

1. On the Admin machine, set `AGENT_ENROLLMENT_KEY` in the project-root
   `.env` and restart the backend.
2. On each victim laptop: `cd victim_agent\.. && python -m venv .venv &&
   .venv\Scripts\activate && pip install -r victim_agent\requirements.txt`,
   copy `victim_agent/.env.example` to `victim_agent/.env` and fill in
   `ADMIN_BASE_URL`, `AGENT_ENROLLMENT_KEY`, and a distinct `AGENT_ID`.
3. `python -m victim_agent.agent` (always as a package -- see
   `victim_agent/README.md` for why not `python victim_agent/agent.py`
   directly).
4. Verify: `GET /api/v1/agents` (admin JWT) shows the agent with `last_seen`
   advancing and `online: true`; `GET /api/v1/telemetry/events?agent_id=...`
   shows real persisted rows; the dashboard's admin-only "Agents" page
   shows the same.
5. To test outage resilience: stop the backend, confirm the agent logs
   `WARNING`s and keeps running (never crashes), restart the backend,
   confirm the agent logs `Flushed N queued telemetry batch(es)`.

## 9. Verification performed

- `pytest backend/tests` -- all tests pass, including
  `test_agents_api.py` and `test_telemetry_api.py` (registration,
  duplicate/rotation, heartbeat auth, telemetry validation and
  persistence, the no-fabricated-score regression test) and the updated
  `test_admin_gating.py` (both new list endpoints require admin).
- `pytest victim_agent/tests` -- identity persistence/stability, bounded
  queue eviction/flush ordering, sender retry/backoff (bounded, no retry
  on 4xx), all with mocked network calls.
- Live end-to-end run: two real `victim_agent` processes (distinct
  `AGENT_ID`s) registered against a real running backend, sent real
  `psutil`-collected heartbeats and telemetry, verified via
  `GET /api/v1/agents` and `GET /api/v1/telemetry/events`. Backend was
  then killed mid-run: both agents logged warnings, queued telemetry, and
  kept running; on backend restart, both flushed their queues and resumed
  normal operation with zero data loss.
