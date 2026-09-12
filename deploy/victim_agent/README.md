# Victim Agent -- deployable package

This folder is everything the **Victim laptop** needs. It does **not**
contain (and does not require) `backend/`, `ml/`, `risk_engine/`,
`attack_graph/`, MySQL, SQLAlchemy, PyTorch, pandas, scikit-learn, or any
model artifact -- none of that runs here. All ML inference and risk
scoring happen on the **Admin** machine; this package only:

- captures live packets (Npcap/Scapy),
- reconstructs bidirectional flows,
- computes the 67 CICIDS2017-style features per flow,
- registers/heartbeats/reports raw connection telemetry to the Admin, and
- can submit a completed flow's feature vector to the Admin's scoring
  endpoint (`POST /api/v1/agents/flow-score`) via the bounded
  `FlowScoringWorker` -- one capture-and-submit cycle at a time, not a
  continuous background service (see "What this checkpoint does NOT do"
  below).

Everything in this folder is a direct copy of the equivalent files under
the main project's `victim_agent/` package (not a rewrite) -- only test
files, the real `.env`, and the machine-specific `.agent_identity.json`
are excluded, because those either aren't part of the runtime or would
leak a secret if copied.

## 1. What must be installed on the Victim (Windows) laptop

- **Python 3.10+** (the source project is tested on 3.12) --
  https://www.python.org/downloads/windows/ (check "Add python.exe to
  PATH" during install)
- **Npcap** -- https://npcap.com -- required for packet capture (Scapy
  cannot capture without it). Install with default options.
- Network access from this laptop to the Admin machine's backend port
  (default `8000`) over the shared Wi-Fi/LAN.

Nothing else. No MySQL client, no Visual C++ ML wheels, no GPU drivers.

## 2. Copy this folder to the Victim laptop

Copy this entire `deploy/victim_agent/` directory (e.g. via a USB drive or
a zipped file transfer) to anywhere on the Victim laptop -- it is
self-contained and does not need the rest of the `E:\MP` repository.

## 3. Create a virtual environment

From the directory you copied this into (the one containing this
`README.md`, `requirements.txt`, and the `victim_agent\` subfolder):

```powershell
python -m venv .venv
.venv\Scripts\activate
```

## 4. Install requirements

```powershell
pip install -r requirements.txt
```

This installs exactly four packages -- `psutil`, `httpx`, `python-dotenv`,
`scapy` (see `requirements.txt` for pinned versions). No ML/backend/DB
dependency is ever installed here.

## 5. Configure `ADMIN_BASE_URL`

Copy the template and edit it:

```powershell
copy .env.example victim_agent\.env
notepad victim_agent\.env
```

Set, at minimum:

```
ADMIN_BASE_URL=http://<ADMIN_WIFI_IP>:8000
AGENT_ENROLLMENT_KEY=<value given to you by the Admin operator>
AGENT_ID=victim-01
```

Replace `<ADMIN_WIFI_IP>` with the Admin laptop's actual Wi-Fi IP address
on the shared network (e.g. `192.168.1.23`) -- find it on the Admin
machine with `ipconfig` (look at the "Wireless LAN adapter Wi-Fi" section).
**Never `127.0.0.1` or `localhost`** -- that would point at the Victim
laptop itself, not the Admin. `ADMIN_BASE_URL` is never hardcoded anywhere
in this package; it only ever comes from this `.env` file (or the real
process environment).

## 6. How the Victim talks to the Admin

Everything is a normal outbound HTTP request from the Victim to
`ADMIN_BASE_URL` over Wi-Fi -- no inbound port needs to be opened on the
Victim laptop, and no VPN/tunnel is required, only that both laptops are
on the same reachable network (e.g. the same Wi-Fi AP or router). The
Victim never needs a database connection, and never talks to MySQL
directly -- only to the Admin's FastAPI HTTP API.

## 7. The Admin side must be reachable

On the **Admin** machine, FastAPI must be bound to `0.0.0.0` (not
`127.0.0.1`) on the configured port so the LAN/Wi-Fi interface actually
accepts connections, e.g.:

```powershell
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

If the Admin's Windows Firewall blocks inbound connections on that port,
the operator will need to allow it (Admin-side change -- out of scope for
this Victim-side package).

## 8. Verify connectivity to the Admin

Before configuring the agent, confirm the Victim laptop can actually reach
the Admin over Wi-Fi. From the Victim laptop, open a browser (or use
`curl`) to:

```
http://<ADMIN_WIFI_IP>:8000/docs
```

You should see FastAPI's interactive Swagger UI. If this doesn't load,
fix connectivity (same Wi-Fi network, correct IP, firewall) before
proceeding -- nothing agent-side will work until this succeeds.

## 9. Running the agent

Always run as a package, from this directory (never
`python victim_agent\agent.py` directly -- see
`victim_agent/__init__.py` for why: a bare `queue.py` on `sys.path` would
shadow Python's own standard-library `queue` module):

```powershell
python -m victim_agent.agent
```

This runs the existing registration -> heartbeat -> telemetry -> retry-queue
loop (see `victim_agent/agent.py`). It does **not** capture packets or
call `FlowScoringWorker` -- that loop is intentionally kept single-threaded
and non-blocking (see "What this checkpoint does NOT do" below).

### Running the bounded flow-scoring worker manually

`FlowScoringWorker` (in `victim_agent/flow_worker.py`) is a small class
with one method, `run_once()`, that performs exactly one bounded
capture-and-submit cycle: capture for up to 10 seconds, reconstruct flows,
submit up to 10 of them to the Admin's `/agents/flow-score` endpoint, and
return a structured result.

This package ships a tiny CLI entry point, `run_flow_worker.py`, that does
exactly that -- one call, then exit. Run it from this same directory
(the one containing this README, alongside the `victim_agent\` folder),
with your `.venv` activated and `victim_agent\.env` already configured
(step 5 above):

```powershell
python run_flow_worker.py
```

It reuses your existing saved identity (registering first if no token has
been saved yet), captures for up to 10 seconds on the auto-discovered
Wi-Fi interface, reconstructs whatever flows resulted, submits up to 10 of
them to the Admin, and prints a summary like:

```
FLOW SCORING WORKER -- SINGLE BOUNDED RUN SUMMARY
==============================================================================
packets captured:    42
flows reconstructed: 3
flows considered:    3
flows submitted:     3
flows failed:        0

per-flow results:
  TCP 192.168.1.6:53386 -> 20.184.175.13:443  OK  risk_score=3.2 risk_level=Low anomaly=False
  ...
==============================================================================
```

It never prints the agent's bearer token or enrollment key, never writes
raw packets to disk, and never logs packet payloads -- only IP/port/
protocol flow metadata and the risk result the Admin returned. Contains no
packet-capture, flow-reconstruction, feature-extraction, or HTTP logic of
its own -- it only sequences the existing `victim_agent` functions, the
same way `victim_agent/agent.py` does for the normal continuous loop.

## 10. What this checkpoint does NOT do

- It does **not** run continuous/repeated packet capture. `run_once()`
  captures once, for a hard-bounded duration (never more than 10
  seconds), and returns.
- It does **not** add a loop, a scheduler, a background thread, or
  `asyncio` around the worker.
- It does **not** wire `FlowScoringWorker` into `agent.py`'s normal
  heartbeat/telemetry loop.
- It does **not** perform any ML inference, risk scoring, graph lookup,
  KNN, or prevention action locally -- all of that happens on the Admin
  after this package submits a flow's feature vector.

A future checkpoint may decide how/whether to call `run_once()`
repeatedly on a schedule; this package intentionally stops short of that.

## Resetting an agent's identity

Delete `victim_agent\.agent_identity.json` and restart. See the main
project's `victim_agent/README.md` / `docs/victim_agent.md` for the full
design rationale (identity/token lifecycle, why telemetry is never
scored, etc.) -- this README only covers what's specific to deploying
this package to a separate Victim laptop.
