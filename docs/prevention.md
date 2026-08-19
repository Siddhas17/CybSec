# Controlled Lab Response (Prevention)

## Status: implemented, dry-run verified end-to-end against real traffic; real blocking not achievable in this project's actual development environment (2026-08-19)

> **This is a detection-and-alert system with a dry-run response
> simulator, not a working intrusion prevention system in this
> environment.** Every dry-run decision below is genuine -- real traffic,
> real risk scores, real validated targets, real audit rows. Real
> blocking (`PREVENTION_DRY_RUN=false`) is a real code path too, not a
> stub, but it honestly reports failure in this project's actual
> environment rather than fabricating a block that never happened. See
> "Environment audit" below.

Not implemented: any actual firewall/network modification in this
project's environment (confirmed unavailable, not merely unattempted --
see below), automatic escalation without an explicit policy match,
anything targeting a system outside the configured lab scope.

## 1. Response architecture

```
Detection (autoencoder + risk engine, unmodified)
     |
     v
Response Policy (risk_score -> LOG / ALERT / BLOCK_CANDIDATE)
     |
     v
[validate target IP against lab scope]  -- rejected targets stop here, audited
     |
     v
Response Adapter (dry_run / block / unblock)
     |
     v
PreventionAction (audit row, MySQL, never deleted)
     |
     v
WebSocket broadcast -> Dashboard (Prevention & Response page)
```

`backend/app/services/prevention/response_service.py` is the only module
that wires these together. API route handlers
(`backend/app/api/v1/prevention.py`) and the live sensor
(`backend/app/services/live_sensor_service.py::_respond`) both call into
it -- neither calls a `ResponseAdapter`, the policy, or a firewall/shell
command directly. The response layer never modifies `ml/`, `attack_graph/`,
or `risk_engine/` -- it only reads an already-computed `risk_score` and
`risk_level`.

## 2. Dry-run mode

Two independent master switches, both default to the safe state:

| Setting | Default | Effect |
|---|---|---|
| `PREVENTION_ENABLED` | `false` | With this false, the response layer evaluates nothing at all -- not even a dry-run decision. Mirrors `sensor/config.py`'s `TELEMETRY_ENABLED` "defense in depth" pattern exactly. |
| `PREVENTION_DRY_RUN` | `true` | With this true (and prevention enabled), a `BLOCK_CANDIDATE` decision calls `adapter.dry_run()`, never `adapter.block()`. No system modification occurs, regardless of what the adapter could theoretically do. |

`POST /api/v1/prevention/block` is refused outright (HTTP 400, before any
validation or adapter call) unless **both** `PREVENTION_ENABLED=true` and
`PREVENTION_DRY_RUN=false` -- an operator must make two explicit changes,
not one, before a real block is even attempted.

## 3. Response policy and thresholds

`backend/app/services/prevention/policy.py`'s `ResponsePolicy` is a pure
function of `risk_score` (the existing 1-10 `risk_engine` scale, see
`docs/risk_engine.md`) -- no network or database access, cannot itself
take an action.

| Tier | Default threshold | Rationale |
|---|---|---|
| `LOG` | `risk_score < 7.0` | Already fully captured by ordinary Event/Detection/RiskAssessment persistence -- no separate audit row. |
| `ALERT` | `risk_score >= 7.0` | Reuses the same "High" boundary already used elsewhere in this project (`risk_engine.config.HIGH_RISK_THRESHOLD`, `live_sensor_service.HIGH_RISK_FLAG_THRESHOLD`, both 7.0) rather than introducing an unrelated fourth number. |
| `BLOCK_CANDIDATE` | `risk_score >= 9.0` | One bucket further in than "Critical"'s own 8.0 boundary, deliberately -- blocking is a stronger action than alerting and asks for a stronger signal than merely crossing into the highest labeled risk bucket. |

**Not claimed to be objectively correct** -- both are configurable via
`RESPONSE_ALERT_THRESHOLD` / `RESPONSE_BLOCK_THRESHOLD` in `.env`, and
`ResponsePolicy` validates them at construction (must stay on the 1-10
scale, block >= alert).

**Empirically observed ceiling for this project's synthetic lab traffic**
(see `docs/live_validation.md` for the full record): a sustained,
loopback-only, single-edge port scan against this sensor's own isolated
test namespace reliably reaches `ALERT` tier (Critical, ~8.3-8.5) but did
not organically reach the default 9.0 `BLOCK_CANDIDATE` threshold within
this session's testing. This is a real, calibrated property of the risk
engine's five-component weighted score (a single repeated loopback edge
cannot maximize `temporal_persistence`/`attack_context`, which need
sustained, diverse activity, the way a real multi-host CICIDS2017 attack
does) -- not a bug, and not "gamed" by loosening validation. The dry-run
`BLOCK_CANDIDATE` code path was still verified end-to-end against this
same real traffic by temporarily lowering the threshold for one
verification run, documented transparently in `docs/live_validation.md`
rather than silently changing the shipped default.

## 4. Validated identifier handling and lab scope

`backend/app/services/prevention/ip_validation.py`'s `validate_lab_target()`
is the only path a response action's target IP takes before reaching an
adapter -- never accepted raw from API input. Rejects, in order:

1. Unparseable input (not a real IP address).
2. Multicast, unspecified (`0.0.0.0`), broadcast (`255.255.255.255`), or
   IANA-reserved addresses -- never valid response targets under any
   configuration.
3. Loopback (`127.0.0.0/8`), **unless** `LAB_ALLOW_LOOPBACK_TARGET=true` is
   set explicitly -- default `false` even though this project's live
   sensor is loopback-only (`docs/live_telemetry.md` section 1). This is
   the one setting flipped, temporarily, to exercise the response path
   against this sensor's actual real traffic (see `docs/live_validation.md`).
4. Anything outside `LAB_NETWORK_CIDRS` (comma-separated CIDRs, default
   `192.168.56.0/24` -- an example VirtualBox host-only range, never
   hard-coded into the validation logic itself).

Every rejection raises `InvalidTargetError` with a specific, auditable
reason -- a caller cannot forget to check a boolean and silently proceed
to call an adapter with an unvalidated target.

## 5. Response adapter and environment audit

`backend/app/services/prevention/adapters/base.py` defines the
`ResponseAdapter` interface (`dry_run` / `block` / `unblock`, none may
raise -- each returns an `AdapterResult(success, actual_action, message)`
so a caller can always create an audit row, even for a failure).

`backend/app/services/prevention/adapters/lab_adapter.py`'s
`LabDryRunAdapter` is the one adapter this project ships.

**Environment audit, checked directly this session, not assumed:**

| Check | Result |
|---|---|
| `iptables` on `PATH` inside WSL2 | Not found |
| `nft` on `PATH` inside WSL2 | Not found |
| Passwordless `sudo` inside WSL2 | `sudo -n true` -> "a password is required" |
| Windows host account is a local administrator | `IsInRole(Administrator)` -> `False` |

There is therefore **no privileged mechanism available in this project's
actual development environment** to modify a real firewall -- not on the
Linux side (no `iptables`/`nft` binary, no way to install or invoke one
without a password this agent does not have) and not on the Windows side
(`netsh advfirewall` would need admin rights the account does not have
either). `dry_run()` is fully real regardless. `block()`/`unblock()` are
real code paths, not stubs, but honestly return `success=False` with this
exact capability gap as the reason. A future environment with a real
privileged backend would implement a second `ResponseAdapter` (the
interface is already environment-agnostic); the policy/API/audit layers
above it would not change.

## 6. API

All endpoints require authentication (`Depends(get_current_user)`,
consistent with every other endpoint in this project).

| Endpoint | Effect |
|---|---|
| `POST /api/v1/prevention/dry-run` | Always simulates, regardless of the global `PREVENTION_DRY_RUN` setting -- requires `PREVENTION_ENABLED=true` only. Lets an operator exercise the whole validated path at any time with zero risk. |
| `POST /api/v1/prevention/block` | Attempts a real block. Refused (HTTP 400) unless both `PREVENTION_ENABLED=true` and `PREVENTION_DRY_RUN=false`. |
| `POST /api/v1/prevention/unblock` | Reverses a previous block. Requires `PREVENTION_ENABLED=true` only -- unblocking is the safe direction; an adapter with nothing real blocked reports `success=false` honestly rather than being refused outright. |
| `GET /api/v1/prevention/actions` | Lists the audit trail, newest first, paginated. |

No endpoint accepts an arbitrary firewall rule, shell command, or
unvalidated identifier -- every request body is `{source_ip, reason?}` or
`{source_ip}`, and `source_ip` always passes through
`validate_lab_target()` before anything else happens.

## 7. Audit logging

Every dry-run, alert, block, unblock, and rejected attempt --
policy-driven or manually triggered -- creates one `prevention_actions`
row (`backend/app/models/prevention_action.py`), never deleted (an
`unblock` is its own new row, not an edit of the original `block` row, so
history stays intact -- section 10 of the phase instructions). Fields:
`event_id` / `detection_id` / `risk_assessment_id` (nullable -- null for a
manual action with no triggering event), `user_id` (nullable -- null for
an automatic policy-driven action), `source_ip`, `risk_score`,
`risk_level`, `requested_action`, `actual_action` (may differ --
e.g. requested "block", actual "rejected"), `dry_run`, `success`,
`reason`, `adapter`, `target_scope`, `created_at`. No secrets are ever
stored here.

## 8. Database

`prevention_actions` (Alembic migration `0cf1e41c6d30`), foreign keys to
`events`, `detections`, `risk_assessments`, `users` -- all `ON DELETE SET
NULL`, so removing an old event never removes its response history.

## 9. Test coverage

`backend/tests/test_prevention_policy.py` (6 tests, pure), `backend/tests/
test_prevention_ip_validation.py` (9 tests, pure), `backend/tests/
test_prevention_api.py` (20 tests: policy tiers, prevention disabled,
dry-run mode never reaching `block()`, invalid/out-of-scope/loopback
rejection with audit, full audit-field verification, auth enforcement on
all 4 endpoints, dry-run-mode refusal of the real block endpoint, adapter
failure handling, duplicate block handling, unblock behavior). A
`FakeAdapter` stands in for `LabDryRunAdapter` wherever a "real"
block/unblock outcome needs exercising -- **never real firewall
modification in the automated suite**, matching this project's existing
policy (`docs/live_telemetry.md` section 16) of hand-built fixtures over
real system calls in unit tests.

## 10. Limitations

- No real blocking is achievable in this project's actual environment
  (section 5) -- this is a structural property of the current dev machine
  (no root/sudo/admin anywhere in the stack), not a design gap in the
  adapter interface.
- The response layer is currently wired into the live sensor path only
  (`live_sensor_service.py::_respond`) -- offline dataset demonstration
  ingestion and controlled test-events do not trigger automatic response
  evaluation, by design (see `docs/live_validation.md` section 1 for why).
- `LabDryRunAdapter`'s in-process `_blocked` set (used only to make
  duplicate-block/unblock behavior meaningful) is not a source of truth
  and does not survive a backend restart -- the persisted `PreventionAction`
  audit trail is the real record, always.
