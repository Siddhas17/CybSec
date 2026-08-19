# Live Pipeline Validation (Phase 7)

## Status: benign + suspicious lab traffic validated end-to-end against the real running system, 2026-08-19

> Every number in this document is from a real run of this project's
> actual code against real captured loopback traffic in this session --
> nothing here is a projection, an estimate, or a fabricated example.
> Verification data was cleaned up from the database afterward (section 6)
> -- these are historical results, not currently-present rows.

## 1. Validation strategy

Per the phase instructions, the full pipeline was validated with benign
traffic first, then controlled suspicious traffic, both through the real
live sensor (not the test-events shortcut, which does not exercise
`sensor/`, `LIVE_GRAPH`, or the response layer's automatic wiring):

```
Real lab traffic (nsenter into the running capture worker's namespace)
     -> sensor (sensor/collectors/, flow reconstruction, feature adapter)
     -> TelemetryEvent
     -> AnalyticalPipeline (unmodified autoencoder + risk engine)
     -> Detection / RiskAssessment (MySQL)
     -> response_service.evaluate_and_respond (live_sensor_service.py::_respond)
     -> PreventionAction (MySQL, if ALERT or BLOCK_CANDIDATE tier)
     -> WebSocket broadcast
     -> React dashboard (Live Threats + Prevention & Response pages)
```

Response evaluation is wired into the live sensor path only, not offline
ingestion or test-events -- matching the phase instructions' own diagram,
which is specifically about live traffic, and avoiding thousands of
retroactive alerts on bulk historical replay.

## 2. Environment for this verification run

Temporarily, for the duration of this session's verification only (all
reverted afterward -- see section 6):

```
TELEMETRY_ENABLED=true          # sensor can start
PREVENTION_ENABLED=true         # response layer evaluates
PREVENTION_DRY_RUN=true         # never a real action
LAB_ALLOW_LOOPBACK_TARGET=true  # this sensor is loopback-only (docs/live_telemetry.md section 1)
RESPONSE_BLOCK_THRESHOLD=8.0    # lowered from the shipped default 9.0 -- see section 4
```

The block-threshold change is the one deliberate departure from shipped
defaults, done specifically to exercise the `BLOCK_CANDIDATE` code path
against real traffic within this session (section 4) -- not a claim that
9.0 was organically crossed.

## 3. Benign traffic validation

Two ordinary HTTP GET requests to a plain `python -m http.server` inside
the sensor's own namespace, generated via `nsenter --target <worker_pid>
--user --net --preserve-credentials` (the same technique verified in
`docs/live_telemetry.md` section 11).

**Result:** both flows were captured, scored, and persisted correctly
(`source=live`, `canonical_attack_label=None`). One produced
`risk_score=7.43` ("High"), which crossed the `ALERT` threshold and
produced a real, audited "alerted" `PreventionAction`.

**Honest finding, not hidden:** even genuinely benign synthetic loopback
traffic reads as moderately anomalous to this model. This is a real
consequence of domain mismatch, not a bug -- the autoencoder was trained
on real CICIDS2017 enterprise-network benign traffic (`docs/autoencoder.md`),
which looks statistically nothing like a bare `http.server` responding to
one `curl` on `127.0.0.1` (near-zero latency, tiny fixed payload, an
unusual ephemeral port). A live sensor that only ever sees synthetic
loopback test traffic should be expected to show elevated risk scores
more often than one watching a real multi-host network -- worth knowing
before reading too much into any single live-sensor alert in this
specific lab setup.

## 4. Suspicious traffic validation

A controlled port scan against the sensor's own isolated namespace --
sequential connection attempts to a range of closed local ports (real
SYN + immediate RST, near-zero payload, matching CICIDS2017's PortScan
category shape), then a larger and then a truly concurrent (threaded)
variant to test whether packet-rate anomaly pushed the score further:

| Run | Ports | Style | Max risk_score observed | Risk level |
|---|---|---|---|---|
| 1 | 40 | sequential | 8.30 | Critical |
| 2 | 200 | sequential | 8.41 | Critical |
| 3 | 300 | concurrent (threaded) | 8.48 | Critical |

**A real, measurable escalation over benign traffic** (7.43 -> 8.3-8.5),
and a real, visible rising trend *within* a single scan as `LIVE_GRAPH`
accumulated `edge_attack_ratio` context from the sensor's own prior
flagged flows on the same edge (individual `PreventionAction.reason`
values climbed from `risk_score 8.2557` to `8.2982` across one run's
`ALERT` sequence, in the actual order they were created).

**Also a real, honest finding:** across three escalating attempts, the
score plateaued around ~8.4-8.5 and did not organically reach the shipped
9.0 `BLOCK_CANDIDATE` default. This is not a failure to "tune" the
traffic harder -- it is a legible property of `risk_engine`'s five
weighted components (`docs/risk_engine.md`): a single repeated
`127.0.0.1 -> 127.0.0.1` edge cannot maximize `temporal_persistence` or
`attack_context` (distinct attack-category diversity) the way genuinely
sustained, multi-host attack activity would, so its ceiling is
structurally below what a more varied real attack could reach. Recorded
here rather than smoothed over.

## 5. Dry-run block-tier verification (section 14)

With `RESPONSE_BLOCK_THRESHOLD` temporarily lowered to `8.0` (section 2)
against the same real port-scan traffic, the full required chain was
verified with real data:

```
Real lab traffic -> live sensor -> AnalyticalPipeline -> risk_score 8.26-8.48 (real)
  -> ResponsePolicy.decide() -> BLOCK_CANDIDATE
  -> validate_lab_target("127.0.0.1") -> accepted (LAB_ALLOW_LOOPBACK_TARGET=true)
  -> LabDryRunAdapter.dry_run() -> AdapterResult(success=True, actual_action="would_block")
  -> PreventionAction row (dry_run=True, success=True, target_scope="loopback (LAB_ALLOW_LOOPBACK_TARGET=true)")
  -> WebSocket "prevention_action" frame
```

58 real `would_block` rows were created from this one scan run. Sample
(from the actual database during verification, since deleted -- section 6):

```json
{
  "source_ip": "127.0.0.1", "risk_score": 8.2641, "risk_level": "Critical",
  "requested_action": "block", "actual_action": "would_block",
  "dry_run": true, "success": true,
  "reason": "Dry-run: would block 127.0.0.1 (risk_score 8.26 crossed block threshold 8.0)",
  "adapter": "lab_dry_run", "target_scope": "loopback (LAB_ALLOW_LOOPBACK_TARGET=true)"
}
```

**No system modification occurred at any point** -- `dry_run=true` on
every row, and `LabDryRunAdapter.block()` was never called (verified by
code path: `PREVENTION_DRY_RUN=true` throughout this run means
`evaluate_and_respond` only ever calls `adapter.dry_run()`).

**Dashboard delivery without a page refresh, verified directly**: a raw
WebSocket client (not the React app, to test the wire protocol itself)
connected to `/ws/events`, generated one more small scan, and received
frames in this exact real order: `connected` -> `new_threat` ->
`prevention_action`. The Prevention & Response page's own
`useEffect`/`useWebSocket` wiring (unit-tested in
`frontend/src/pages/Prevention.test.tsx`) consumes exactly this message
shape to prepend new rows live.

## 6. Actual lab blocking -- STOPPED per section 21

Per the phase instructions' explicit stop condition ("if actual firewall
integration is not safely achievable in the current environment, STOP
after the dry-run response implementation and report the limitation").
`docs/prevention.md` section 5 records the direct environment audit: no
`iptables`/`nft` in WSL2, no passwordless sudo, no Windows admin rights.
Sections 15-16 of the phase instructions (real blocking test, recovery
verification) were not attempted, and the lab-scope safety controls were
not weakened to force a working block -- `LabDryRunAdapter.block()`
remains a real code path that honestly reports failure rather than a
fabricated success.

## 7. Latency measurements (section 17)

Measured from real timestamps recorded during this session's verification
runs (532 live events, 530 prevention actions, since cleaned up):

| Measurement | Result |
|---|---|
| Detection persisted -> response action persisted | n=530, min=0.000s, max=1.000s, **mean=0.006s** (same MySQL server clock on both ends -- reliable) |
| Sensor capture -> detection persisted | **not reliably measurable in this dev setup** |
| Sensor capture -> response action persisted (total) | **not reliably measurable in this dev setup** |

**Why two of the three are not reported:** `Event.timestamp` is written
from the WSL2 guest's clock; `created_at` columns are MySQL
`server_default=now()`, i.e. the Windows host's clock. The observed raw
delta was a *consistent* ~19,938 seconds (~5h32m) across every row
checked -- clearly a timezone/clock-configuration artifact between the two
machines, not real latency, but not a clean, confidently-correctable
offset either (5h32m18s, not exactly IST's 5h30m). Reporting a "corrected"
number here would mean guessing at the correction; reporting the raw
delta would be actively misleading. Documented as a real environmental
limitation of this specific WSL2-guest/Windows-host split
(`docs/live_telemetry.md`'s own environment notes) rather than a
performance claim either way. **Not claimed as a universal performance
guarantee** either way, per the phase instructions.

## 8. Cleanup performed

All verification data was identified by signature
(`source_ip`/`destination_ip` both `127.0.0.1` -- the only possible
origin, since this was the first-ever exercise of both the live sensor
and the response layer against real traffic) and removed in FK-safe
order after verification: 530 `prevention_actions`, 532
`risk_assessments`, 532 `detections`, 532 `events`. Confirmed zero
remain, and the demo database's `total_events` count was verified to
return to exactly its pre-verification value (292) afterward. `.env` was
reverted to its shipped safe defaults (`TELEMETRY_ENABLED=false`,
`PREVENTION_ENABLED=false`, `LAB_ALLOW_LOOPBACK_TARGET=false`,
`RESPONSE_BLOCK_THRESHOLD=9.0`) and the backend was restarted to confirm
the safe-default state holds for real, not just in config.

## 9. Repeatable demonstration script

1. Start backend: `uvicorn backend.app.main:app --host 0.0.0.0 --port 8000` (WSL2, `attack-graph-ids` conda env, project root).
2. Start frontend: `npm run dev` in `frontend/` (native Windows).
3. Set `.env`: `TELEMETRY_ENABLED=true`, `PREVENTION_ENABLED=true`, `PREVENTION_DRY_RUN=true`, `LAB_ALLOW_LOOPBACK_TARGET=true` (loopback sensor only -- omit the loopback flag entirely on a real lab-CIDR interface). Restart the backend.
4. Log in, `POST /api/v1/sensor/start` (or the System Health page's button). Verify `collector_status: "running"`.
5. Generate normal traffic: from another shell, `nsenter --target <worker_pid> --user --net --preserve-credentials -- <any ordinary client/server pair>`. Confirm a `source=live` event with a plausible risk level on the Live Threats page.
6. Generate controlled suspicious traffic: a rapid scan of several dozen closed local ports inside the same namespace (see section 4's script shape). Confirm detection, a visibly elevated anomaly/risk score, and attack-graph context (`LIVE_GRAPH` edge stats) on the event's detail page.
7. Confirm the dashboard alert and, if `RESPONSE_BLOCK_THRESHOLD` is reachable by the generated traffic (section 4's honest caveat), a "WOULD BLOCK" row on the Prevention & Response page, arriving live over the WebSocket.
8. `POST /api/v1/sensor/stop`. Revert `.env` to its safe defaults and restart the backend.
9. Clean up any verification-only rows the same way section 6/8 did, by signature, never touching unrelated data.

## 10. Limitations

- Loopback-only sensor (`docs/live_telemetry.md`) -- every "lab" IP in
  this validation is `127.0.0.1`; a real multi-host lab CIDR was never
  exercised end-to-end with real traffic in this session.
- Synthetic traffic shape is narrow (HTTP GETs, TCP connect scans) --
  real diversity of both benign and attack traffic in CICIDS2017 is far
  broader than what could be generated in one session.
- The 9.0 default `BLOCK_CANDIDATE` threshold was not organically reached
  (section 4); the dry-run block path was verified with a temporarily
  lowered threshold instead, documented as such.
- Two of three latency measurements are not reliably obtainable in this
  specific WSL2/Windows split (section 7).
- No real blocking was attempted or achieved (section 6) -- this document
  and `docs/prevention.md` together are the report of that limitation the
  phase instructions asked for, not a claim of a working prevention
  system.
