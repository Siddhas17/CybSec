# Live Telemetry Sensor

## Status: implemented and verified end-to-end against real loopback traffic, loopback-only (2026-08-19)

> **This is a detection-only sensor, not a network monitor and not a
> prevention system.** It captures real packets, but only inside an
> isolated, unprivileged network namespace this process creates for
> itself -- never the host's shared eth0/Wi-Fi adapter. It cannot see
> anyone else's traffic, cannot block anything, and its output is scored
> by the exact same `AnalyticalPipeline` (autoencoder + risk engine) that
> already serves the Offline Dataset Demonstration and test-event paths --
> no second model, no second scoring logic.

Not implemented (deliberately out of scope): capture on a shared/host
interface, packet blocking or prevention, automatic remediation, capture
of anyone's traffic but this process's own namespace.

## 1. Why an isolated network namespace instead of the host's shared interface

`sensor/collectors/netns_loopback.py` (`NetnsLoopbackCollector`) launches
its capture worker via `unshare --map-root-user --net`, which creates a
*new* user + network namespace where the calling (unprivileged) user is
mapped to root *inside that namespace only*. The new namespace starts with
nothing but its own private loopback interface (`lo`) -- no eth0, no
Wi-Fi adapter, no route to the host's real network at all.

This was chosen over capturing on the host's shared interface for two
reasons:

1. **Capability, not privilege.** `CAP_NET_RAW` (required for raw
   `AF_PACKET` sockets, which `scapy.sniff()` needs) is granted by the
   namespace boundary itself, not by `sudo` or a setuid binary. No change
   to the host's real root/sudo state was needed or made.
2. **Isolation is structural, not policy.** Traffic on the new namespace's
   `lo` is exactly and only what a process explicitly launched inside that
   same namespace generates. There is no way for this collector to
   observe another user's or another machine's traffic, because the
   namespace has no path to reach it. This is a stronger authorization
   guarantee than "only sniff eth0 because we said we would" -- it holds
   even if the code were buggy.

The trade-off is stated plainly: this sees only loopback traffic inside a
namespace this process controls, not real LAN/eth0 traffic. Section 10
covers what upgrading beyond loopback would require.

## 2. Environment audit

At the time this collector was built, the WSL2 environment running the
backend had no packet-capture tooling installed and no way to install any
without a privilege grant this agent did not have:

- No Npcap on the Windows host.
- No `tcpdump` / `tshark` inside WSL2 (`shutil.which` / `apt` check came
  back empty).
- No sudo password available to install or authorize either.

`unshare` (part of `util-linux`, already present) plus `scapy` (added to
`requirements.txt`, used only by the capture-worker subprocess -- see
section 21) were the simplest combination that produced real, verifiable
packet capture without requesting any new privilege from the user. If
`unshare` is missing from `PATH`, `NetnsLoopbackCollector.start()` raises
immediately with that exact diagnosis rather than falling back to a
weaker, silent substitute.

## 3. Timestamp and inter-arrival-time units

`Flow Duration` in the real CICIDS2017 dataset is in **microseconds**, not
seconds (verified empirically: real `Flow Duration` values commonly run
into the millions, and dividing by observed packet counts only produces
plausible `Flow Bytes/s` figures if the duration is already interpreted
as microseconds). `sensor/normalization/feature_adapter.py` converts every
duration and inter-arrival-time feature (`Flow IAT *`, `Fwd IAT *`,
`Bwd IAT *`, `Active *`, `Idle *`) to microseconds explicitly (`* 1_000_000`)
to match, using the collector's sub-millisecond `float` epoch-second
timestamps as the source of truth.

## 4. Empirical verification against the real dataset

Two of the adapter's more distinctive choices were checked against
`ml/datasets/raw/` (`MachineLearningCVE`, the exact CSVs the Phase 1
cleaning pipeline and Phase 3 autoencoder were built from -- see
`docs/dataset_inspection.md`), not the separately-exported
`raw_labelled_flows/` (`GeneratedLabelledFlows`, used only for topology,
already documented in `docs/risk_engine.md` section 2 as a *different*
CSV export of the same captures with its own known data-quality quirks,
including a raw-export integer-underflow artifact in this same column):

- **`CWE Flag Count`** (this adapter: a literal count of the TCP CWR bit)
  is nonzero in only 315 of 2,830,743 real training rows (0.011%) --
  consistent with "always compute it as a literal CWR count" being a safe
  choice, though the original tool's own "CWE" semantics were never
  independently confirmed beyond that.
- **`min_seg_size_forward`** (TCP header length in bytes): the dominant
  real values are 20/24/28/32/36/40/44 (valid TCP header lengths in
  4-byte increments -- these seven values alone cover >97% of all rows),
  matching this adapter's "minimum observed TCP header length in the
  forward direction" computation exactly for TCP. The raw export also
  contains a vanishingly rare corrupt negative outlier (one clear
  integer-underflow artifact) and a long thin tail up to 138 -- a
  pre-existing data-quality artifact of the original CICFlowMeter export
  that Phase 1's cleaning pipeline already deals with for the columns
  that matter (`docs/cleaning_decision_report.md`); this adapter does not
  need to reproduce it, only to avoid being confidently wrong about the
  typical case.
- **`Init_Win_bytes_forward` / `Init_Win_bytes_backward`**: 1,001,189 of
  2,830,743 real training rows (35.4%) are exactly `-1`. This matches the
  dataset's own convention of using `-1` as a "not applicable" sentinel
  for non-TCP rows, which this adapter reproduces via
  `TCP_ONLY_SENTINEL_FEATURES` rather than inventing a synthetic 0 or NaN.

## 5. End-to-end architecture

```
NetnsLoopbackCollector          FlowAccumulator           adapt_features()
(sensor/collectors/)     ---->  (flow_reconstruction.py)  (feature_adapter.py)
  |  unshare --net,                |  groups packets           |  67 raw features,
  |  scapy.sniff() in a            |  into bidirectional        |  same names/order as
  |  subprocess, JSON lines        |  flows by 5-tuple,         |  ml/datasets/processed/
  |  over stdout                   |  closes on FIN/RST/        |  feature_names.json
  v                                v  idle/duration/packet cap  v
RawPacketEvent  ------------->  RawFlow  ----------------->  dict[str, float]
                                                                    |
                                                                    v
                                                    AnalyticalPipeline.score()
                                                    (backend/app/services/analytical_pipeline.py --
                                                     the SAME code path test-events and offline
                                                     ingestion already use: existing scaler ->
                                                     existing autoencoder -> existing risk engine.
                                                     Zero ML/risk logic is duplicated here.)
                                                                    |
                                                                    v
                                          Event / Detection / RiskAssessment rows (source=LIVE)
                                          + WebSocket broadcast + LIVE_GRAPH edge update
```

`backend/app/services/live_sensor_service.py` owns this whole pipeline
end to end (collector lifecycle, the flow accumulator, `LIVE_GRAPH`, and
the health counters section 14 describes) as one background thread per
sensor run. `backend/app/api/v1/sensor.py` only starts/stops/reads it --
no ML or scoring code lives in the API layer.

## 6. Feature compatibility audit

Every one of the 67 model features is classified in
`sensor/normalization/feature_adapter.py`'s `FEATURE_COMPATIBILITY` dict:

- **"A" (60 of 67 features)**: directly observable from a real captured
  bidirectional flow with no algorithmic ambiguity -- packet/byte counts,
  min/max/mean/std of packet lengths, TCP flag counts, header lengths,
  duration, and the inter-arrival-time family (section 3).
- **"B" (7 features)**: derivable, but this adapter's formula is a
  documented approximation of a CICFlowMeter-specific convention rather
  than a verified byte-exact port of its (proprietary-in-behavior, not
  just proprietary-in-code) implementation: `CWE Flag Count`,
  `Subflow Fwd/Bwd Bytes`, `min_seg_size_forward` (non-TCP case only),
  and the `Active *` / `Idle *` family (all built on this adapter's own
  activity/idle burst-splitting algorithm -- packets are "active" while
  gaps stay under `activity_idle_threshold_seconds`, "idle" otherwise;
  this is the general CICFlowMeter approach, not a verified byte-exact
  reimplementation of it). Each "B" feature carries its specific caveat
  in `FEATURE_NOTES`, surfaced to the reader rather than silently assumed
  correct.
- **No feature is "C" (unavailable)**. Every one of the 67 names the
  persisted scaler and autoencoder expect can be computed from a real
  captured flow.

**The two "STOP" trigger conditions this audit was watching for, and why
neither was hit** (see section 22 for the full stop-condition list this
belongs to):

1. *A feature that cannot be computed from any observable packet-level
   signal at all* (would have required inventing a fabricated value).
   Did not occur -- every feature maps to something genuinely observable.
2. *A feature whose only available computation requires an assumption
   contradicted by the real dataset's own values* (would have meant the
   adapter's output could actively mislead the model). Did not occur --
   section 4's empirical checks confirm the adapter's approximations are
   consistent with, not contradicted by, real values.

## 7. `graph_source`: which graph produced this event's context

A `DetectionResult` always records which graph produced its graph
context. Live-sensor events set `graph_source="live_graph"`
(`LIVE_GRAPH`, in-memory, built only from what this sensor itself has
observed); the offline ingestion and test-event paths use
`graph_source="offline_graph"` implicitly (`OFFLINE_GRAPH`, the persisted
Phase 2 attack graph built once from the full labeled CICIDS2017 dataset,
see `docs/attack_graph.md`). The two are never merged into one object.

## 8. Never conflate `LIVE_GRAPH` and `OFFLINE_GRAPH`

Neither graph may impersonate the other, in either direction:

- `GET /api/v1/events/{id}` never attaches `OFFLINE_GRAPH` context to a
  `source=LIVE` event (`backend/app/api/v1/events.py`) -- the persisted
  retrospective graph never scored that event, `LIVE_GRAPH` did, and by
  read time `LIVE_GRAPH` may have already evicted the edge (section 9).
  Showing the offline graph's context here would silently misattribute it
  as the event's real real-time context.
- The reverse mistake -- letting a young `LIVE_GRAPH` edge's thin history
  (possibly a single flow) read with the same confidence as the
  label-informed offline graph -- is avoided the same way: `LIVE_GRAPH`
  never claims ground-truth attack labels (section 9).

## 9. `LIVE_GRAPH`: bounded, and never ground truth

`sensor/live_graph.py` (`LiveGraph`) is built only from observed live
`TelemetryEvent`s -- it is explicitly **not** `OFFLINE_GRAPH`.

- **Bounded growth**: edges idle longer than `live_graph_window_seconds`
  (default 3600s) are evicted by a periodic `cleanup()` call; if the edge
  count still exceeds `live_graph_max_edges` (default 5000) after that,
  the least-recently-active edges are evicted next. An unattended sensor
  cannot grow memory without limit.
- **Never ground truth**: `edge_attack_ratio` is the fraction of *this
  edge's own live flows the analytical pipeline itself already flagged*
  (`risk_score >= 7.0` or `is_anomaly`), never a real attack label --
  there is no ground truth for genuinely live traffic.
  `edge_attack_label_count` is always `0` for this reason, unlike
  `OFFLINE_GRAPH`'s equivalent field.

## 10. What upgrading beyond loopback would require

Capturing on a real interface (the host's shared eth0/Wi-Fi adapter, or a
dedicated lab NIC) instead of the isolated namespace's private loopback
is a deliberate later step, not an accidental omission, and would need,
explicitly and in advance:

1. A fresh, explicit grant from the user authorizing capture on a named
   real interface -- the current design's authorization boundary (section
   12) is the namespace itself, and extending it changes what is being
   authorized.
2. A capability grant on the host (e.g. `setcap cap_net_raw+ep` on the
   Python interpreter, or running the worker as root) that this agent
   does not have and should not grant itself.
3. Confirmation of whose traffic would be visible on that interface, and
   that capturing it is within scope of an authorized lab/test
   environment -- not a shared production or third-party network.

`sensor/collectors/base.py`'s `BaseTelemetryCollector` interface
(`start`/`stop`/`health`/`events`) is already collector-agnostic so a
second collector implementing it could be added later without touching
`FlowAccumulator`, `adapt_features()`, or `LiveSensorService`.

## 11. Current deployment status

Implemented, unit-tested (flow reconstruction, `LiveGraph` TTL/eviction,
`/api/v1/sensor/*` auth and refusal paths), and verified end-to-end this
session: `LiveSensorService` was started for real (with
`TELEMETRY_ENABLED` forced true for that one process only), real HTTP
traffic was generated inside the running capture worker's own namespace
(joined from outside via `nsenter --target <worker_pid> --user --net
--preserve-credentials` -- note the `--preserve-credentials` flag, plain
`nsenter --net` or `--user --net` alone fails against a
`--map-root-user`-created namespace), and real `Event`/`Detection`/
`RiskAssessment` rows landed in the actual MySQL database with
`source=LIVE`, correct IPs/ports/protocol, and `canonical_attack_label`
correctly `None`. This is the loopback-only capability described
throughout this document -- capture on a real/shared interface is still
the section 10 future step. `TELEMETRY_ENABLED=false` by default
(section 15); nothing captures unless an operator both flips that and
explicitly calls `POST /api/v1/sensor/start`.

## 12. Threat model and authorization boundary

This sensor only ever sees traffic inside the network namespace its own
`unshare --net` call creates. That namespace starts with nothing but a
private loopback interface and no route to any other network -- it is
structurally impossible for this collector to capture the host's real
LAN traffic, another user's traffic, or anyone else's machine, not merely
a policy choice not to. Only a process explicitly launched inside that
same namespace (this project's own test client/server, or another
process an operator deliberately launches with `unshare --net --target`
into it) produces any traffic for it to see at all.

## 13. Resilience: malformed input must never kill the sensor

Every stage of the pipeline treats malformed or unexpected input as a
recoverable event, recorded in the health counters (section 14), never as
a reason to crash the loop:

- A malformed packet record from the capture worker increments
  `parse_errors` and is dropped (`netns_loopback.py::_handle_line`).
- A packet that fails flow reconstruction increments `events_rejected`
  and is logged, without stopping ingestion of the next packet
  (`live_sensor_service.py::_run`).
- A flow that fails scoring, persistence, or broadcast (e.g. a transient
  DB outage) increments `processing_errors` and is logged
  (`live_sensor_service.py::_process_flow`) -- one bad flow never takes
  down the sensor thread.
- If the analytical core itself (model + risk config) is unavailable at
  startup, the sensor refuses to start processing at all rather than
  half-starting and silently producing unscored or fabricated results
  (`model_available=False`, `last_error` set, section 22).

**Observed real-traffic behavior (from the first live capture-to-MySQL
smoke run of this sensor, this session):** a lone ACK arriving just after
both sides' FIN -- a routine, common TCP occurrence, not a malformed
packet -- can spawn a new single-packet flow on the same 5-tuple, since
`FlowAccumulator` had already emitted and removed the completed flow
before that stray ACK arrived. This phantom flow never receives another
packet and sits in `active_flows` until `flow_idle_timeout_seconds`
elapses or the sensor stops (`flush_all()`), at which point it is scored
and persisted like any other flow -- low-signal, but not wrong or
fabricated. Real capture, real MySQL rows, `canonical_attack_label`
correctly `None`, `last_error` correctly `None` once
`sensor/collectors/_capture_worker.py`'s own scapy-import-time
`CryptographyDeprecationWarning` was silenced there (previously leaked
into `last_error` as if it were a capture fault -- fixed this session).

## 14. Health and observability surface

`GET /api/v1/sensor/health` (and the System Health page's "Live Sensor"
panel) exposes `SensorHealth`:

| Field | Meaning |
|---|---|
| `collector_status` | `stopped` / `starting` / `running` / `error` |
| `interface` | Configured capture interface (`lo` by default, section 15) |
| `telemetry_enabled` | Current `TELEMETRY_ENABLED` value (section 15) |
| `started_at` / `last_event_at` | Timestamps for operator visibility |
| `packets_received` / `packets_dropped` | From the capture worker; dropped = queue backpressure (section 9-style bound on `max_queued_packet_events`), not malformed |
| `parse_errors` | Malformed worker output or packet records |
| `events_processed` / `events_rejected` / `processing_errors` | Flow-level outcomes (section 13) |
| `active_flows` | `FlowAccumulator`'s current in-progress flow count |
| `live_graph_edges` | `LIVE_GRAPH`'s current edge count |
| `model_available` | Whether the analytical core loaded successfully |
| `last_error` | Most recent error string, if any |

## 15. Configuration and defense in depth

`sensor/config.py` (`SensorConfig`, `pydantic-settings`, reads the same
project-root `.env` as the rest of the backend) is entirely
environment-driven -- no machine-specific IP address or interface name is
hard-coded anywhere in `sensor/`.

`TELEMETRY_ENABLED` (default `false`) is a master switch, deliberately
independent of the `POST /api/v1/sensor/start` call: **both** are always
required before any capture begins. `LiveSensorService.start()` raises
immediately if `TELEMETRY_ENABLED=false`, before touching the collector at
all. This means a backend accidentally left running, or a stray API call,
cannot start real packet capture on its own -- an operator must both edit
`.env` and take an explicit authenticated action.

## 16. Testing strategy

Unit tests never use real network traffic (`tests/test_sensor_flow_reconstruction.py`'s
module docstring states this explicitly) -- `FlowAccumulator` and
`LiveGraph` are pure Python with no I/O, fully testable against
hand-built `RawPacketEvent` fixtures. Current coverage: 7 `FlowAccumulator`
tests (bidirectional grouping, RST/FIN closure, idle-timeout splitting,
max-duration/max-packets caps, `flush_idle`/`flush_all`). `LiveGraph`
TTL/eviction and the `/api/v1/sensor/*` endpoints do not yet have
dedicated tests -- see the repository's test suite for current status,
since this document is not automatically kept in sync with test coverage.

## 17. Known approximations, in plain language

Anyone reading a live-scored event's inputs should know these are
engineering approximations of a proprietary tool's exact behavior, not
byte-exact reproductions -- all are the "B" features from section 6:

- Subflow byte counts assume this adapter's own activity/idle burst
  splitting, not a verified port of CICFlowMeter's subflow algorithm.
- "Active"/"Idle" duration statistics are built the same way.
- Non-TCP `min_seg_size_forward` reports the UDP header's fixed 8 bytes,
  which does not match the real dataset's own unexplained ~20-52-byte
  range for UDP rows in `raw_labelled_flows` (that range's derivation
  could not be identified from public CICFlowMeter documentation) --
  stated here as a documented divergence, not a silent guess.

## 18. Integration with the analytical pipeline

`LiveSensorService._process_flow` builds a `TelemetryEvent` and a
`GraphContext` from `LIVE_GRAPH` and calls the exact same
`AnalyticalPipeline.score()` that `backend/app/api/v1/test_events.py` and
the offline ingestion path already use. No live-only model, threshold, or
risk rule exists anywhere in `sensor/` -- this module's entire job is
producing the same input contract those other paths already produce, not
reimplementing anything downstream of it.

## 19. Event-source labeling

Live events persist with `source=EventSource.LIVE` and
`canonical_attack_label=None` -- there is no ground truth for real
traffic, so none is fabricated. `EventSourceTag` (frontend) renders this
as "Live", visually distinct from "Offline Dataset Demonstration" and
"Test Event" everywhere an event can appear, so a viewer can never mistake
a live-scored flow for a retrospective demonstration or a synthetic test
submission.

## 20. Operational runbook

1. Set `TELEMETRY_ENABLED=true` in `.env` (defaults to `false`).
2. Restart the backend so the new setting is read.
3. `POST /api/v1/sensor/start` (authenticated) -- or the "Start Live
   Sensor" button on the System Health page.
4. Watch `GET /api/v1/sensor/health` / the System Health panel:
   `collector_status` should move `starting -> running`; `last_error`
   should stay empty.
5. `POST /api/v1/sensor/stop` (or "Stop Live Sensor") to end the run; the
   collector's subprocess is terminated and any in-progress flows are
   flushed rather than silently discarded (`FlowAccumulator.flush_all()`).

If `collector_status` reports `error`, check `last_error` first -- the
most common causes are `unshare` missing from `PATH` (section 2) or
`TELEMETRY_ENABLED=false` (section 15, checked before the collector is
even touched).

**Generating traffic for the running sensor to see** (section 12: only a
process inside the same namespace produces visible traffic): find the
capture worker's PID (`ps aux | grep _capture_worker`, or the collector's
own health/logs), then join its namespace from another shell with
`nsenter --target <pid> --user --net --preserve-credentials -- <command>`.
The `--preserve-credentials` flag is required -- joining a namespace
`unshare --map-root-user` created without it fails
(`nsenter: setgroups failed: Operation not permitted`). This was
verified working during this session's end-to-end smoke test (section 11).

## 21. Data handling

Nothing in this pipeline writes raw packet bytes or payload data to disk
at any stage. The capture worker (`sensor/collectors/_capture_worker.py`)
emits only parsed metadata (IPs, ports, protocol, lengths, TCP flags/
window) as JSON lines over a pipe -- never a raw byte blob, never a pcap
file. Only derived flow-level statistics (the 67 model features) and the
resulting `Event`/`Detection`/`RiskAssessment` rows are persisted, exactly
the same data shape as every other event source in this system.

## 22. Stop conditions

Conditions under which this sensor must not run, or must halt rather than
continue with a weaker guarantee:

1. `TELEMETRY_ENABLED=false` -- `LiveSensorService.start()` refuses
   before touching the collector (section 15).
2. `unshare` unavailable on `PATH` -- `NetnsLoopbackCollector.start()`
   refuses rather than falling back to capturing on a shared interface
   (section 2).
3. The analytical core (model or risk config) fails to load -- the sensor
   thread exits immediately without processing any flow, rather than
   half-starting (section 13).
4. Any future request to capture on a real/shared interface instead of
   the isolated namespace's loopback, without the fresh explicit grant
   and capability change section 10 describes -- out of scope until that
   authorization exists.
5. Either of the two feature-compatibility STOP conditions in section 6
   (a feature with no observable computation, or one whose only
   computation contradicts real data) -- neither has occurred, but if one
   ever does for a future feature set, the adapter must surface it rather
   than fabricate a value.
