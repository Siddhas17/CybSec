# Final Readiness Report

**Audit date:** 2026-08-19
**Audit type:** read-only readiness audit, with one narrow documentation-only correction (see "Audit findings and corrections" below)
**Final commit:** `1fcd790` (see "Why the commit hash changed" below)

---

## 1. Project architecture summary

A detection-and-analysis cybersecurity pipeline combining attack-graph
generation with autoencoder-based anomaly detection and explainable risk
scoring, extended with an application layer, a real (loopback-only) live
telemetry sensor, and a dry-run-only lab response layer.

```
CICIDS2017 dataset
     |
     v
Preprocessing (ml/preprocessing/) -- 67 model features, cleaned/scaled
     |
     +-----------------------------+
     |                             |
     v                             v
Autoencoder (ml/models/)   Attack graph (attack_graph/)
anomaly score                topology, edge attack ratios
     |                             |
     +-----------------------------+
                  |
                  v
     Risk engine (risk_engine/) -- 1-10 explainable score
                  |
                  v
     Analytical pipeline (backend/app/services/analytical_pipeline.py)
     -- the ONE place ml/ + risk_engine/ are combined; reused, unmodified,
        by every event source below
                  |
     +------------+------------+------------------+
     |            |            |                  |
     v            v            v                  v
 Offline      Test-event   Live sensor       (all four persist to)
 ingestion    API          (sensor/, Phase 6)      |
 (Phase 5)    (Phase 5)         |                  v
     |            |             v            MySQL (backend/app/models/)
     |            |     Response layer             |
     |            |     (Phase 7, dry-run)          v
     |            |             |            WebSocket -> React dashboard
     +------------+-------------+
```

**Directory map:**

| Path | Role |
|---|---|
| `ml/` | Preprocessing, autoencoder training/inference |
| `attack_graph/` | Topology graph generation, analysis, visualization |
| `risk_engine/` | Explainable 1-10 risk scoring |
| `backend/` | FastAPI + SQLAlchemy + MySQL + WebSocket application layer, including `backend/app/services/prevention/` (Phase 7) |
| `sensor/` | Real, loopback-only packet capture -> flow reconstruction -> feature adaptation (Phase 6) |
| `frontend/` | React + TypeScript admin dashboard |
| `tests/` | Pure-logic tests for ml/attack_graph/risk_engine/sensor (161 tests) |
| `backend/tests/` | API/service-level tests (63 tests) |
| `docs/` | Per-phase design documents (authoritative technical reference) |

## 2. Completed phases

| Phase | Scope | Status | Commit |
|---|---|---|---|
| 0-4 | WSL2 environment, preprocessing, attack graph, autoencoder, risk engine | Done | `79c8ae3`, `304bbc8`, `71499ce`, `749d61b` |
| 5 | FastAPI + MySQL + WebSocket + React, offline demonstration mode | Done | `6d5ad28` |
| 6 | Live telemetry sensor, loopback-only | Done | `62045f4` |
| 7 | Controlled lab response, dry-run only (real blocking not achievable in this environment) | Done | `fcc1bc5` |
| Audit | Final readiness audit + documentation correction | Done | `1fcd790` |
| Future | Multi-host lab deployment, real privileged blocking backend | Not started | — |

## 3. Exact startup sequence

1. **MySQL** must be reachable. On this dev machine it runs natively on
   Windows; `.env`'s `MYSQL_HOST` is the WSL2->Windows gateway IP
   (`ip route | grep default` inside WSL2), not `localhost`. Re-check this
   if MySQL connectivity fails after a WSL restart -- the IP can change.
2. **Backend** (WSL2, `attack-graph-ids` conda env, project root):
   ```bash
   source $HOME/miniconda3/bin/activate attack-graph-ids
   cd /mnt/e/MP
   cd backend && alembic upgrade head && cd ..
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
   ```
   Verify: `curl http://127.0.0.1:8000/api/v1/health` -> `{"status":"ok","database":"connected","analytical_core":"loaded",...}`.
3. **Frontend** (native Windows, no WSL2):
   ```powershell
   cd frontend
   npm install   # first time only
   npm run dev
   ```
   Open `http://localhost:5173`, sign in with `ADMIN_USERNAME`/`ADMIN_PASSWORD` from `.env`.
4. **Live sensor and prevention** stay off by default
   (`TELEMETRY_ENABLED=false`, `PREVENTION_ENABLED=false`) -- both are
   opt-in for a demonstration, not part of ordinary startup. See section 4.

All four steps above were re-verified directly in this audit session
(backend boot log clean, `/api/v1/health` returned healthy, frontend
`npm run dev` served HTTP 200, login + `/api/v1/auth/me` succeeded).

## 4. Demonstration sequence

**A. Offline Dataset Demonstration** (always safe, no config changes):
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<admin>","password":"<password>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST http://127.0.0.1:8000/api/v1/admin/ingest -H "Authorization: Bearer $TOKEN"
```
Or the "Run Offline Dataset Demonstration" button on the System Health
page. ~2-3 minutes; rebuilds the attack graph and scores a real
stratified CICIDS2017 sample. Every event is labeled "Offline Dataset
Demonstration" in the UI.

**B. Live sensor** (`docs/live_telemetry.md` §20): set
`TELEMETRY_ENABLED=true` in `.env`, restart the backend,
`POST /api/v1/sensor/start` (or the System Health page button). Generate
traffic for it to see by joining the running capture worker's namespace
from another shell: `nsenter --target <worker_pid> --user --net
--preserve-credentials -- <client/server pair>` (the `--preserve-credentials`
flag is required against a `--map-root-user` namespace). Real events
appear on Live Threats labeled "Live". `POST /api/v1/sensor/stop`
afterward; revert `TELEMETRY_ENABLED=false`.

**C. Dry-run lab response** (`docs/prevention.md`, `docs/live_validation.md`
§9): additionally set `PREVENTION_ENABLED=true` (`PREVENTION_DRY_RUN`
should stay `true`). A live event whose risk score crosses
`RESPONSE_ALERT_THRESHOLD` (default 7.0) produces a real "ALERTED" row on
the Prevention & Response page; crossing `RESPONSE_BLOCK_THRESHOLD`
(default 9.0) produces "WOULD BLOCK", delivered live over the WebSocket.
An operator can also manually exercise this path any time via
`POST /api/v1/prevention/dry-run` with a lab-scope IP. Revert
`PREVENTION_ENABLED=false` afterward.

**Honest note carried over from Phase 7's own verification** (see
`docs/live_validation.md` §4): synthetic loopback lab traffic generated
during that phase's testing reliably reached `ALERT` tier but plateaued
around risk 8.4-8.5, short of the default 9.0 block threshold -- a real,
calibrated property of the risk engine, not a bug. A live re-demonstration
of the `WOULD BLOCK` tier may need either sustained/varied traffic or a
temporarily lowered `RESPONSE_BLOCK_THRESHOLD` (documented, reverted
afterward) to reproduce, exactly as that phase did.

## 5. Known limitations

- **Live sensor is loopback-only.** No real LAN/multi-host capture --
  `unshare --map-root-user --net` isolation, not privilege (`docs/live_telemetry.md` §1-2, §10).
- **Real firewall blocking is not achievable in this environment.**
  Verified directly: no `iptables`/`nft` in WSL2, no passwordless sudo, the
  Windows account is not a local administrator. `ResponseAdapter.block()`/
  `unblock()` are real code paths that honestly report failure rather than
  fabricating success (`docs/prevention.md` §5, `docs/live_validation.md` §6).
- **Risk engine's excellent evaluation numbers are retrospective/forensic**, not a
  claim of prospective generalization to a genuinely novel network
  relationship (`docs/risk_engine.md` §11).
- **Autoencoder detection performance is uneven across attack categories**
  (`docs/autoencoder.md` §16).
- **Live telemetry feature adapter has documented approximations** for 7 of
  67 features (Subflow bytes, Active/Idle timing, non-TCP `min_seg_size_forward`)
  -- CICFlowMeter's exact proprietary algorithm was never reverse-engineered
  byte-for-byte (`docs/live_telemetry.md` §6, §17).
- **Two of three latency metrics are not reliably measurable** in this
  specific WSL2-guest/Windows-host split (consistent clock-offset artifact,
  not correctable without guessing) -- only same-machine detection-to-response
  latency (mean 6ms) is reported as reliable (`docs/live_validation.md` §7).
- **Synthetic lab traffic diversity is narrow** relative to real
  CICIDS2017 -- both benign and attack traffic generated for verification
  were simple HTTP/TCP-connect patterns, not a full traffic mix.

## 6. Environment requirements

- Windows host with WSL2 (Ubuntu) for all Python/ML/backend work (Smart
  App Control blocks native-Windows compiled ML extensions).
- Python 3.12 in a `attack-graph-ids` conda environment (Miniconda, no
  root/sudo required to install).
- MySQL 8.0, reachable from WSL2 (native Windows install on this dev
  machine, via the WSL2->host gateway IP).
- Node.js (native Windows) for the frontend -- no WSL2 dependency there.
- `unshare` (util-linux, already present in WSL2) for the live sensor's
  namespace isolation; `scapy` (Python, in `requirements.txt`) for packet
  parsing inside that namespace.
- **Not available on this dev machine, and not required for anything
  except real (non-dry-run) firewall blocking:** `iptables`/`nft`,
  passwordless sudo, Windows administrator rights.

## 7. Test totals

| Suite | Count | Status |
|---|---|---|
| Root (`tests/`) -- ml, attack_graph, risk_engine, sensor pure-logic | 161 | All pass |
| Backend (`backend/tests/`) -- API/service-level, including 35 prevention tests | 63 | All pass |
| Frontend (`frontend/src/**/*.test.tsx`) | 22 | All pass |
| **Total** | **246** | **All pass** |

Frontend production build (`npm run build`, tsc + vite): clean, no type
errors. All figures re-verified directly in this audit session, not
carried over from memory.

## 8. Final commit hash

**`1fcd790a3975828a3283acb7b406c38b87139457`** -- "Fix stale documentation and a wrong endpoint path found in readiness audit"

### Why the commit hash changed from `fcc1bc5`

The audit found two categories of real documentation error and corrected
them in one follow-up, documentation-only commit, per this task's explicit
allowance ("correcting a documentation error that would make the
documented startup/demo procedure objectively incorrect"):

1. `.env` and `.env.example` referenced a **nonexistent** endpoint,
   `POST /api/v1/admin/sensor/start` -- the real, working endpoint
   (confirmed against `backend/app/api/v1/router.py` and verified live) is
   `POST /api/v1/sensor/start`. Following the comment literally would have
   produced a 404.
2. `README.md` and `docs/application_architecture.md` still stated "no
   live network monitoring, no automatic prevention... none of which is
   implemented yet" and "`sensor/` ... intentionally not created yet" --
   false since Phases 6-7 shipped both (in loopback-only / dry-run-only
   form respectively). Left uncorrected, a reader starting from the
   project's main entry point would not discover the live sensor or
   prevention demonstration steps exist at all.

No source code was modified -- only `.env.example`, `.env` (gitignored,
not part of the commit), `README.md`, and `docs/application_architecture.md`.
Full diff is in commit `1fcd790`.

## 9. Recommended presentation claims

- "A working autoencoder anomaly detector combined with attack-graph
  context produces an explainable 1-10 risk score, evaluated against the
  real CICIDS2017 dataset (F1 0.641, ROC-AUC 0.916 for the autoencoder
  alone; high-risk classification F1 0.996 with graph context added)."
- "A full FastAPI/MySQL/WebSocket/React application layer serves this in
  real time, with an Offline Dataset Demonstration mode that replays real,
  labeled attack traffic through the unmodified analytical core."
- "A real live telemetry sensor captures genuine packets, reconstructs
  flows, and scores them through the identical analytical pipeline --
  verified end to end against real traffic in an isolated network
  namespace, not simulated."
- "A dry-run lab response layer demonstrates the full detection-to-response
  architecture -- policy, validated lab-scope targeting, audit trail,
  live dashboard delivery -- safely, with two independent switches
  defaulting off and real blocking never silently faked when unavailable."
- "246 automated tests pass across the ML/graph/risk-engine core, the
  backend API, and the frontend; the frontend production build is clean."

## 10. Claims that should NOT be made

- **Do not claim this is a working intrusion prevention system.** No real
  traffic has ever been blocked by this project in any environment it has
  actually run in -- only simulated (dry-run) and honestly-failed-to-block
  outcomes exist.
- **Do not claim multi-host or real-network live monitoring.** The sensor
  has only ever observed loopback traffic inside its own isolated
  namespace.
- **Do not present the risk engine's evaluation metrics as predictive of
  real-world, never-before-seen attack performance.** They are retrospective,
  computed with full graph context already available.
- **Do not claim uniform detection performance across attack types.** It
  is measurably uneven (`docs/autoencoder.md` §16).
- **Do not claim the live feature adapter is a byte-exact reproduction of
  CICFlowMeter.** Seven features are documented approximations.
- **Do not cite specific latency numbers for "sensor to detection" or
  "total" pipeline latency** -- those two were found not reliably
  measurable in this environment; only detection-to-response (mean 6ms)
  has a reliable, real measurement behind it.
- **Do not claim the project contains or has ever run offensive
  attack/exploit tooling.** Verified in this audit: no such code is
  tracked in the repository; traffic used to validate detection was
  generated ad hoc, against the project's own isolated test namespace
  only, and never committed.
