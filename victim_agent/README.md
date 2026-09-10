# victim_agent

A lightweight, standalone Python app that runs on each Windows victim
laptop in the lab. It registers itself with the Admin backend, sends
periodic heartbeats, and reports real OS-level network connection
telemetry (via `psutil`) — never fabricated data. It never scores
anything: this is Phase 1, identity + ingestion only (see
`../docs/victim_agent.md` for the full design and why raw telemetry stays
separate from the trained autoencoder/KNN pipeline).

This directory is self-contained and has its own, minimal dependency set
— it does **not** need the root project's `requirements.txt`, PyTorch,
pandas, or any of the ML stack.

## Prerequisites

- Python 3.10+ (tested on 3.12)
- Network access from the victim laptop to the Admin machine's backend
  port (default `8000`)
- The Admin operator has given you: the Admin's base URL (e.g.
  `http://192.168.56.10:8000`) and a one-time `AGENT_ENROLLMENT_KEY`

## Setup

Copy this entire `victim_agent/` folder to the victim laptop (it does not
need the rest of the repository), then from the **parent** directory of
`victim_agent/`:

```powershell
cd path\to\victim_agent\..
python -m venv .venv
.venv\Scripts\activate
pip install -r victim_agent\requirements.txt
```

Create `victim_agent\.env` from the template and fill in your values:

```powershell
copy victim_agent\.env.example victim_agent\.env
notepad victim_agent\.env
```

At minimum, set:

```
ADMIN_BASE_URL=http://<admin-laptop-lan-ip>:8000
AGENT_ENROLLMENT_KEY=<value given to you by the Admin operator>
AGENT_ID=victim-01
```

Use a different `AGENT_ID` on each victim laptop (e.g. `victim-01`,
`victim-02`).

## Running

**Always run as a package, from the directory containing `victim_agent/`**
— never `python victim_agent\agent.py` directly (a bare `queue.py` module
on `sys.path` would shadow Python's own standard-library `queue` module,
which `httpx` and other libraries rely on internally):

```powershell
python -m victim_agent.agent
```

On first run, the agent generates a stable local identity (or uses
`AGENT_ID` if you set one), registers with the Admin using
`AGENT_ENROLLMENT_KEY`, and saves the returned per-agent token to
`victim_agent\.agent_identity.json` (gitignored, holds a secret — never
share or commit it). On every subsequent run it reuses that saved identity
and token; `AGENT_ENROLLMENT_KEY` is not needed again unless you delete
the identity file.

You should see log lines like:

```
INFO victim_agent: Registered successfully (rotated=False)
INFO victim_agent: Agent loop starting (heartbeat=15s, telemetry=5s) -- Ctrl+C to stop
INFO victim_agent: Heartbeat sent
INFO victim_agent: Telemetry sent: 12 connection(s) accepted
```

### Windows permissions note

`psutil.net_connections()` can only see the full system-wide connection
table when run with sufficient privileges. If you see repeated `WARNING`s
about permission denied and an empty/partial connection list, try running
your terminal as Administrator.

## Verifying it's working

From the Admin machine (or any machine with access to the backend), log
in as an admin user and check:

```bash
curl -H "Authorization: Bearer <admin JWT>" http://<admin-ip>:8000/api/v1/agents
```

Each registered agent should appear with `last_seen` advancing every
heartbeat/telemetry cycle and `online: true`. The Admin dashboard's
"Agents" page (admin-only) shows the same thing. To confirm telemetry is
actually persisted:

```bash
curl -H "Authorization: Bearer <admin JWT>" "http://<admin-ip>:8000/api/v1/telemetry/events?agent_id=victim-01"
```

## Stopping

`Ctrl+C` in the terminal running the agent. It shuts down cleanly; nothing
in the local queue is lost (it's held in memory and will start fresh next
run — see `docs/victim_agent.md` for why the retry queue is deliberately
not persisted to disk in this phase).

## Resetting an agent's identity

Delete `victim_agent\.agent_identity.json` and restart. The agent will
generate a new local ID (or reuse `AGENT_ID` if set) and re-register,
which rotates its token server-side — the Admin does not need any manual
cleanup.
