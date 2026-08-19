# Application Architecture (Phase 5)

## Status: implemented (2026-08-18)

FastAPI + MySQL + WebSocket + React/TypeScript application layer around
the validated Phase 1-4 analytical core. Offline dataset demonstration
mode was the only mode as of this Phase 5 document -- a real, loopback-only
live sensor (`docs/live_telemetry.md`) and a dry-run-only lab response
layer (`docs/prevention.md`) were added in Phases 6-7 respectively, both
still lab-only and neither performing offensive attack-generation.

**Important evaluation caveat, preserved from Phase 4:** the risk engine's
graph-context signals are computed from an attack graph built once from
the full labeled CICIDS2017 dataset. Its excellent precision/recall
(`docs/risk_engine.md` section 11) is retrospective/forensic evidence --
"how well would prioritization work given comprehensive, already-labeled
attack-graph context" -- not proof of generalization to a genuinely novel
network relationship never seen before. Anything this application
displays derived from the risk engine inherits that caveat; the Model
Information page links back to `docs/risk_engine.md` for the full
discussion rather than repeating it out of context.

## 1. Target architecture

```
Event
  |
  +--> Autoencoder (ml/) --------> anomaly score
  |
  +--> Attack Graph (attack_graph/) --> graph context
        |
        v
  Risk Engine (risk_engine/) --> Risk Score 1-10
        |
        v
  backend/  (FastAPI + SQLAlchemy + MySQL + WebSocket)
        |
        v
  frontend/  (React + TypeScript admin dashboard)
```

`backend/` never duplicates ML/risk logic -- every analytical number
comes from calling `ml/`, `attack_graph/`, or `risk_engine/` directly
(`backend/app/services/analytical_pipeline.py`,
`backend/app/services/model_registry.py`). The autoencoder and the attack
graph remain architecturally independent, exactly as in Phases 2-4; this
layer is the only place their outputs are combined, and it still never
feeds graph objects into the autoencoder or vice versa.

## 2. Backend architecture

```
backend/
├── app/
│   ├── main.py               FastAPI app factory, CORS, lifespan (seeds admin user)
│   ├── core/
│   │   ├── config.py           pydantic-settings, reads the project-root .env
│   │   ├── logging.py
│   │   └── security.py         bcrypt password hashing (direct, not passlib -- see below), JWT
│   ├── db/
│   │   ├── base.py              SQLAlchemy declarative Base
│   │   └── session.py            engine + session factory
│   ├── models/                  SQLAlchemy ORM (see section 4)
│   ├── schemas/                 Pydantic request/response models
│   ├── services/
│   │   ├── model_registry.py     loads/caches the Phase 3/4 artifacts, tracks model_versions
│   │   ├── analytical_pipeline.py TelemetryEvent -> AnalyticalPipeline -> DetectionResult
│   │   ├── data_bridge (reused from risk_engine/) for bulk ingestion scoring
│   │   ├── graph_service.py       persists/queries the attack graph
│   │   ├── ingestion.py            Offline Dataset Demonstration (section 7)
│   │   ├── analytics_service.py    dashboard summary queries (never re-scans raw CSVs)
│   │   ├── auth_service.py
│   │   └── audit.py                system_logs writer
│   ├── api/v1/                  one module per resource (see section 5)
│   └── websocket/
│       ├── manager.py             connection tracking + broadcast
│       └── router.py               /ws/events endpoint
├── migrations/                  Alembic
└── tests/                       pytest, isolated in-memory SQLite (section 8)
```

**Why bcrypt is called directly, not via passlib:** passlib 1.7.4 (last
released 2020) runs an internal self-test against modern `bcrypt`
(>=4.1, which enforces bcrypt's 72-byte input limit strictly) that raises
`ValueError` before any real password is even hashed -- a documented
upstream incompatibility. `backend/app/core/security.py` calls the
`bcrypt` library's `hashpw`/`checkpw` directly instead.

## 3. Frontend architecture

```
frontend/
├── src/
│   ├── types/            TypeScript interfaces mirroring backend/app/schemas/*.py
│   ├── services/api.ts    axios client, JWT injection, typed endpoint functions
│   ├── hooks/
│   │   ├── useAuth.tsx      auth context (token in localStorage, /auth/me on load)
│   │   └── useWebSocket.ts   auto-reconnecting WS client, bounded message buffer
│   ├── layouts/DashboardLayout.tsx  sidebar nav + live-feed status + logout
│   ├── components/          RiskBadge, StatCard, EventSourceTag, ProtectedRoute
│   └── pages/                Login, Overview, LiveThreats, ThreatDetails, AttackGraph,
│                              Analytics, ModelInfo, SystemHealth
```

Built with Vite + React 19 + TypeScript, React Router for navigation,
`@xyflow/react` (React Flow) for the attack-graph visualization, and
Recharts for analytics charts. Runs on **native Windows** (not WSL2) --
Node.js/npm have no compiled-Python-extension dependency, so Smart App
Control (the reason the ML stack runs in WSL2 -- see
`docs/architecture.md`) doesn't affect it.

**Frontend data rule (section 10):** no dashboard number is hard-coded.
Every page fetches from the backend API, which reads from MySQL, which
was populated either by the Offline Dataset Demonstration ingestion (real
CICIDS2017 flows through the real analytical core) or a controlled test
event (also scored by the real core, with any unsupplied feature
explicitly disclosed as imputed). `EventSourceTag` labels every row with
its real origin ("Offline Dataset Demonstration" / "Test Event") so
nothing is ever presented as live detection.

## 4. Database schema (MySQL, SQLAlchemy + Alembic)

| Table | Purpose |
|---|---|
| `users` | Admin accounts (bcrypt-hashed passwords) |
| `model_versions` | Which artifact version (preprocessing/autoencoder/attack_graph/risk_engine) produced a result |
| `events` | Raw event data only: IPs, ports, protocol, timestamp, ground-truth label if known, `source` (offline_demo / test_event / live) |
| `detections` | Derived autoencoder output only: anomaly score, threshold, is_anomaly -- FK to `events` and `model_versions` |
| `risk_assessments` | Derived risk-engine output only: score, level, factors (JSON), rules applied, reason -- FK to `events`, `detections`, `model_versions` |
| `attack_nodes` | Persisted Phase 2 graph node summary (per `graph_version_id`) |
| `attack_edges` | Persisted Phase 2 graph edge summary (per `graph_version_id`) -- `total_forward_bytes`/`total_backward_bytes` use `BigInteger`, not `Integer`: the real dataset's DDoS mega-edge has ~2.8 billion backward bytes, which overflows a 32-bit `INT` (verified the hard way -- the first ingestion run failed with MySQL error 1264 until this was fixed) |
| `system_logs` | Audit log: logins, ingestion runs |

Raw event data, derived ML result, derived graph context, and derived
risk assessment are always separate tables/objects (section 5 of the
phase instructions) -- never merged into one row. Migrations are managed
by Alembic (`backend/migrations/`); the schema is created via
`alembic upgrade head`, not `create_all()` in application code.

**Not duplicated in MySQL:** the full 2.8M-flow CICIDS2017 dataset. Only
the attack graph's already-aggregated summary (~19K nodes, ~114K edges --
compact, not raw flows) and a small, explicitly-sampled set of
demonstration events are persisted.

## 5. API structure

All endpoints under `/api/v1/` (versioned, per section 3). All except
`/health` and `/auth/login` require a Bearer JWT.

| Endpoint | Purpose |
|---|---|
| `GET /health` | backend/DB/analytical-core status |
| `POST /auth/login`, `GET /auth/me` | JWT issuance/verification |
| `GET /events`, `GET /events/{id}` | raw events + full detail (detection + risk + graph context) |
| `GET /detections` | autoencoder outputs |
| `GET /threats` | combined Event+Detection+RiskAssessment view for the Live Threats table |
| `GET /risks`, `GET /risks/{event_id}` | risk-engine outputs, matching the section-14 example shape |
| `GET /attack-graph` | persisted graph, filterable (`min_attack_flow_count`, `node_ip` neighborhood, `limit`) -- never returns the unfiltered ~114K-edge graph |
| `GET /analytics/*` | summary, attacks-by-type, risk-distribution, timeline, top-sources, top-destinations, anomaly/risk score histograms, model-info -- all precomputed from persisted tables |
| `POST /test-events` | scores a controlled event through the real `AnalyticalPipeline`, persists it as `source=test_event`, broadcasts over WebSocket |
| `POST /admin/ingest` | triggers the Offline Dataset Demonstration (section 7) -- not a generic command-execution endpoint, does exactly one thing |

## 6. WebSocket flow

```
new event persisted (ingestion or a test event)
        |
        v
ConnectionManager.broadcast("new_threat", {...})
        |
        v
every connected client's onmessage fires
        |
        v
React: LiveThreats re-fetches; useWebSocket's rolling buffer updates
```

`GET /ws/events` (optionally `?token=<JWT>` for audit purposes; the
connection itself is read-only and doesn't require auth to keep a
dashboard viewable). Sends `{"type": "connected", ...}` on accept, a
`{"type": "heartbeat"}` every 30s, and `{"type": "new_threat", "data":
...}` per new event -- never re-streams the whole database. The frontend
hook (`useWebSocket.ts`) reconnects automatically 3s after any drop and
keeps a bounded 100-message buffer.

## 7. Authentication

Single-admin, bcrypt-hashed password, JWT bearer tokens (`python-jose`,
HS256, 8-hour expiry by default). The admin account is seeded on backend
startup from `.env` (`ADMIN_USERNAME`/`ADMIN_PASSWORD`) if no user exists
yet -- idempotent, safe on every restart. Deliberately not enterprise
IAM (no roles, no SSO, no password reset flow) per the explicit
instruction to keep this modular and appropriately scoped for a local
academic application.

## 8. Analytical-core integration

`backend/app/services/analytical_pipeline.py` defines the future-ready
interface:

```python
TelemetryEvent -> AnalyticalPipeline.score() -> DetectionResult
```

Used identically by:
- `POST /test-events` (a single event, arbitrary/partial features).
- **Not** used row-by-row by bulk ingestion, which instead reuses
  `risk_engine.data_bridge` directly for efficiency at scale (both paths
  ultimately call the same `ml.models.autoencoder` /
  `risk_engine.scoring` functions -- see the docstring in
  `backend/app/services/ingestion.py` for the full reasoning).
- A future live-sensor phase would construct `TelemetryEvent` objects the
  same way and call `.score()` identically -- no rewrite needed.

Model artifacts are loaded once per process and cached
(`model_registry.py`, `functools.lru_cache`) -- never reloaded per
request, never refit.

## 9. Offline Dataset Demonstration mode (section 7)

`backend/app/services/ingestion.py::run_offline_ingestion`:

1. Rebuilds the attack graph fresh from `ml/datasets/raw_labelled_flows/`
   (`attack_graph.generation.build_graph`, ~57s) and persists it.
2. Builds the joint per-flow dataset (real IPs + real anomaly scores,
   `risk_engine.data_bridge.build_joint_flow_dataset`, ~50s over the full
   2,827,876-flow dataset).
3. Draws a **deterministic, stratified sample** (default: up to 20 events
   per canonical label, capped at 300 total) -- every one of CICIDS2017's
   15 label categories is represented, including rare ones (Heartbleed,
   Infiltration, the Web Attack subtypes).
4. Scores the sample through `risk_engine.scoring.score_event` and
   persists Event + Detection + RiskAssessment rows, each labeled
   `source = EventSource.OFFLINE_DEMO`.

Every number produced this way is a genuine output of the real Phase
1-4 pipeline -- never a fabricated or precomputed detection. Full run:
~150s, 291 events across all 15 categories, verified end-to-end (see
completion report).

## 10. Future live-sensor integration (section 18, not implemented)

```python
TelemetryEvent  # already defined, already used by test-events
      |
      v
AnalyticalPipeline.score()  # already defined, already used
      |
      v
DetectionResult  # already defined, already persisted the same way
```

A live sensor phase would only need to: construct `TelemetryEvent`
objects from captured traffic, call the existing `.score()`, and persist
the result the same way `test_events.py` already does -- with
`source = EventSource.LIVE` (already reserved in the `EventSource` enum,
unused until that phase). No packet capture or traffic generation exists
in this repository, live or offensive.

## 11. Security (section 12)

- All DB access through the SQLAlchemy ORM (parameterized queries, no
  raw string-interpolated SQL).
- Pydantic validates every request body; malformed input returns 422,
  not a stack trace.
- CORS restricted to the configured frontend origin(s)
  (`CORS_ORIGINS` in `.env`), not `*`.
- JWT-gated on every endpoint except `/health` and `/auth/login`.
- No secrets in source code -- everything sensitive lives in `.env`
  (gitignored) with a placeholder-only `.env.example` committed.
- No generic "execute command" endpoint; `/admin/ingest` does exactly
  one fixed, non-parameterized-by-arbitrary-code action.
- `system_logs` records authentication events and ingestion runs.

## 12. Known environment specifics of this dev machine

- **MySQL 8.0 runs natively on Windows**, not inside WSL2. The backend
  (which must run in WSL2 for its ML dependencies) reaches it via the
  WSL2->Windows gateway IP (`ip route | grep default`), not `localhost`
  -- WSL2 is a separate network namespace here (no mirrored networking).
  This IP can change between WSL restarts; update `MYSQL_HOST` in `.env`
  if the backend loses DB connectivity after a reboot.
- A dedicated `attack_graph_app`@`172.20.%` MySQL user (least privilege,
  scoped to the `attack_graph_app` database only) was created for this
  purpose -- not root.
- The frontend runs as native Windows Node.js, entirely separate from
  the WSL2 Python environment.

## 13. Tests

- **Backend** (`backend/tests/`, 23 tests): app startup, health, DB
  connection, auth (success/failure/malformed), event validation,
  detection/risk persistence, attack-graph endpoint (filtered, against a
  tiny synthetic graph), WebSocket connect/ping-pong/clean-disconnect,
  and one full end-to-end test (test event -> DB -> REST API -> WebSocket
  broadcast). Runs against an isolated in-memory SQLite database --
  never the real MySQL demo data or the full CICIDS2017 dataset.
- **Frontend** (`frontend/src/**/*.test.tsx`, 15 tests, Vitest + React
  Testing Library): risk-level badge rendering, stat cards, threat-table
  rendering with mocked API data, API-failure error handling (a real gap
  the tests caught and fixed -- `LiveThreats` originally had no
  `.catch()`, causing an unhandled promise rejection), WebSocket
  auto-reconnect behavior (mocked `WebSocket`, fake timers), and risk
  visualization (factor bars, contribution values, applied context-rule
  badges).
- **Manual end-to-end verification**: real backend (real MySQL, real
  trained model, real persisted graph) driven through a real Chromium
  browser (Playwright, used once for this verification pass and then
  removed as a dependency) -- login, Overview, Live Threats, Threat
  Details, Attack Graph, Analytics, Model Information, System Health,
  and the interactive test-event submission form all confirmed rendering
  real data with zero browser console errors.
