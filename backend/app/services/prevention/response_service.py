"""Orchestrates the section-2 architecture end to end:

    Detection -> Response Policy -> [validate target] -> Response Adapter -> PreventionAction (audit) -> WebSocket

This is the only module that wires those pieces together. API route
handlers (backend/app/api/v1/prevention.py) and live_sensor_service call
into this -- never a ResponseAdapter or the policy directly, and never a
firewall/shell command (section 2's explicit "do not place firewall/shell
commands directly inside API route handlers").
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.models.prevention_action import PreventionAction
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.models.user import User
from backend.app.services.prevention.adapters.base import ResponseAdapter
from backend.app.services.prevention.adapters.lab_adapter import LabDryRunAdapter
from backend.app.services.prevention.ip_validation import InvalidTargetError, validate_lab_target
from backend.app.services.prevention.policy import ResponseDecision, ResponsePolicy
from backend.app.websocket.manager import manager

logger = logging.getLogger(__name__)

default_adapter: ResponseAdapter = LabDryRunAdapter()


class PreventionDisabledError(ValueError):
    """PREVENTION_ENABLED=false -- the caller should turn this into HTTP 400, never attempt the action anyway."""


class DryRunModeError(ValueError):
    """DRY_RUN=true -- a real block/unblock was requested while dry-run mode is still on."""


def _policy() -> ResponsePolicy:
    # Read live, not cached at import time, so an operator's env change is
    # honored without restarting -- consistent with settings elsewhere.
    return ResponsePolicy(alert_threshold=settings.response_alert_threshold, block_threshold=settings.response_block_threshold)


def _broadcast(loop: asyncio.AbstractEventLoop | None, payload: dict[str, Any]) -> None:
    """Same safe cross-thread pattern as live_sensor_service.py's own
    _broadcast: works whether called from an async API handler's own loop
    or from the sensor's background thread, and never raises out to the
    caller if the loop is gone."""
    if loop is None:
        return
    try:
        future = asyncio.run_coroutine_threadsafe(manager.broadcast("prevention_action", payload), loop)
        future.add_done_callback(_log_broadcast_failure)
    except RuntimeError as exc:
        logger.warning("prevention: could not schedule websocket broadcast: %s", exc)


def _log_broadcast_failure(future: "asyncio.Future[None]") -> None:
    exc = future.exception()
    if exc is not None:
        logger.warning("prevention: websocket broadcast failed: %s", exc)


def _record(
    db: Session,
    *,
    event: Event | None,
    detection: Detection | None,
    risk_assessment: RiskAssessment | None,
    user: User | None,
    source_ip: str,
    risk_score: float | None,
    risk_level: str | None,
    requested_action: str,
    actual_action: str,
    dry_run: bool,
    success: bool,
    reason: str,
    adapter_name: str,
    target_scope: str | None,
    loop: asyncio.AbstractEventLoop | None,
) -> PreventionAction:
    action = PreventionAction(
        event_id=event.id if event is not None else None,
        detection_id=detection.id if detection is not None else None,
        risk_assessment_id=risk_assessment.id if risk_assessment is not None else None,
        user_id=user.id if user is not None else None,
        source_ip=source_ip,
        risk_score=risk_score,
        risk_level=risk_level,
        requested_action=requested_action,
        actual_action=actual_action,
        dry_run=dry_run,
        success=success,
        reason=reason,
        adapter=adapter_name,
        target_scope=target_scope,
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    _broadcast(
        loop,
        {
            "id": action.id,
            "event_id": action.event_id,
            "source_ip": action.source_ip,
            "risk_score": action.risk_score,
            "risk_level": action.risk_level,
            "requested_action": action.requested_action,
            "actual_action": action.actual_action,
            "dry_run": action.dry_run,
            "success": action.success,
            "reason": action.reason,
            "adapter": action.adapter,
            "target_scope": action.target_scope,
            "created_at": action.created_at.isoformat() if action.created_at else None,
        },
    )
    return action


def evaluate_and_respond(
    db: Session,
    *,
    event: Event,
    detection: Detection | None,
    risk_assessment: RiskAssessment,
    loop: asyncio.AbstractEventLoop | None = None,
    adapter: ResponseAdapter | None = None,
    policy: ResponsePolicy | None = None,
) -> PreventionAction | None:
    """Automatic, policy-driven evaluation -- called after a real detection
    is persisted (currently: the live sensor path only, section 1's
    validation-strategy diagram). Returns None when nothing worth auditing
    happened (prevention disabled, or risk_score stayed at plain LOG tier)."""
    if not settings.prevention_enabled:
        return None  # master switch off -- mirrors sensor_config.telemetry_enabled

    policy = policy or _policy()
    adapter = adapter or default_adapter
    decision = policy.decide(risk_assessment.risk_score)

    if decision == ResponseDecision.LOG:
        return None  # ordinary detection/risk persistence already covers this tier -- no audit row

    if decision == ResponseDecision.ALERT:
        return _record(
            db,
            event=event,
            detection=detection,
            risk_assessment=risk_assessment,
            user=None,
            source_ip=event.source_ip,
            risk_score=risk_assessment.risk_score,
            risk_level=risk_assessment.risk_level,
            requested_action="alert",
            actual_action="alerted",
            dry_run=False,
            success=True,
            reason=f"risk_score {risk_assessment.risk_score:.2f} crossed alert threshold {policy.alert_threshold}",
            adapter_name=adapter.name,
            target_scope=None,
            loop=loop,
        )

    # BLOCK_CANDIDATE
    try:
        target = validate_lab_target(event.source_ip)
    except InvalidTargetError as exc:
        return _record(
            db,
            event=event,
            detection=detection,
            risk_assessment=risk_assessment,
            user=None,
            source_ip=event.source_ip,
            risk_score=risk_assessment.risk_score,
            risk_level=risk_assessment.risk_level,
            requested_action="block",
            actual_action="rejected",
            dry_run=settings.prevention_dry_run,
            success=False,
            reason=exc.reason,
            adapter_name=adapter.name,
            target_scope=None,
            loop=loop,
        )

    reason = f"risk_score {risk_assessment.risk_score:.2f} crossed block threshold {policy.block_threshold}"
    result = adapter.dry_run(target.ip, reason) if settings.prevention_dry_run else adapter.block(target.ip, reason)

    return _record(
        db,
        event=event,
        detection=detection,
        risk_assessment=risk_assessment,
        user=None,
        source_ip=target.ip,
        risk_score=risk_assessment.risk_score,
        risk_level=risk_assessment.risk_level,
        requested_action="block",
        actual_action=result.actual_action,
        dry_run=settings.prevention_dry_run,
        success=result.success,
        reason=result.message,
        adapter_name=adapter.name,
        target_scope=target.scope,
        loop=loop,
    )


def manual_dry_run(
    db: Session,
    *,
    source_ip: str,
    reason: str,
    user: User,
    loop: asyncio.AbstractEventLoop | None = None,
    adapter: ResponseAdapter | None = None,
) -> PreventionAction:
    """POST /prevention/dry-run: always simulates, regardless of the global
    DRY_RUN setting -- lets an operator exercise the whole validated path
    at any time without ever risking a real action. Still requires
    PREVENTION_ENABLED=true (section 11: 'enforce prevention configuration')."""
    if not settings.prevention_enabled:
        raise PreventionDisabledError("PREVENTION_ENABLED=false -- the response layer is disabled")
    adapter = adapter or default_adapter
    try:
        target = validate_lab_target(source_ip)
    except InvalidTargetError as exc:
        return _record(
            db, event=None, detection=None, risk_assessment=None, user=user, source_ip=source_ip,
            risk_score=None, risk_level=None, requested_action="dry_run", actual_action="rejected",
            dry_run=True, success=False, reason=exc.reason, adapter_name=adapter.name, target_scope=None, loop=loop,
        )
    result = adapter.dry_run(target.ip, reason)
    return _record(
        db, event=None, detection=None, risk_assessment=None, user=user, source_ip=target.ip,
        risk_score=None, risk_level=None, requested_action="dry_run", actual_action=result.actual_action,
        dry_run=True, success=result.success, reason=result.message, adapter_name=adapter.name,
        target_scope=target.scope, loop=loop,
    )


def manual_block(
    db: Session,
    *,
    source_ip: str,
    reason: str,
    user: User,
    loop: asyncio.AbstractEventLoop | None = None,
    adapter: ResponseAdapter | None = None,
) -> PreventionAction:
    """POST /prevention/block: attempts a REAL block. Refused outright
    (raises, never silently downgrades to dry-run) unless both
    PREVENTION_ENABLED=true and DRY_RUN=false -- section 8's 'actual
    blocking must require an explicit configuration change'."""
    if not settings.prevention_enabled:
        raise PreventionDisabledError("PREVENTION_ENABLED=false -- the response layer is disabled")
    if settings.prevention_dry_run:
        raise DryRunModeError("DRY_RUN=true -- real blocking is disabled; use POST /prevention/dry-run instead, or set DRY_RUN=false")
    adapter = adapter or default_adapter
    try:
        target = validate_lab_target(source_ip)
    except InvalidTargetError as exc:
        return _record(
            db, event=None, detection=None, risk_assessment=None, user=user, source_ip=source_ip,
            risk_score=None, risk_level=None, requested_action="block", actual_action="rejected",
            dry_run=False, success=False, reason=exc.reason, adapter_name=adapter.name, target_scope=None, loop=loop,
        )
    result = adapter.block(target.ip, reason)
    return _record(
        db, event=None, detection=None, risk_assessment=None, user=user, source_ip=target.ip,
        risk_score=None, risk_level=None, requested_action="block", actual_action=result.actual_action,
        dry_run=False, success=result.success, reason=result.message, adapter_name=adapter.name,
        target_scope=target.scope, loop=loop,
    )


def manual_unblock(
    db: Session,
    *,
    source_ip: str,
    user: User,
    loop: asyncio.AbstractEventLoop | None = None,
    adapter: ResponseAdapter | None = None,
) -> PreventionAction:
    """POST /prevention/unblock: reverses a previous successful block.
    Requires PREVENTION_ENABLED=true but not DRY_RUN=false -- unblocking is
    the safe direction, and an adapter with nothing real blocked simply
    reports success=False honestly rather than being refused outright."""
    if not settings.prevention_enabled:
        raise PreventionDisabledError("PREVENTION_ENABLED=false -- the response layer is disabled")
    adapter = adapter or default_adapter
    try:
        target = validate_lab_target(source_ip)
    except InvalidTargetError as exc:
        return _record(
            db, event=None, detection=None, risk_assessment=None, user=user, source_ip=source_ip,
            risk_score=None, risk_level=None, requested_action="unblock", actual_action="rejected",
            dry_run=settings.prevention_dry_run, success=False, reason=exc.reason, adapter_name=adapter.name,
            target_scope=None, loop=loop,
        )
    result = adapter.unblock(target.ip)
    return _record(
        db, event=None, detection=None, risk_assessment=None, user=user, source_ip=target.ip,
        risk_score=None, risk_level=None, requested_action="unblock", actual_action=result.actual_action,
        dry_run=settings.prevention_dry_run, success=result.success, reason=result.message, adapter_name=adapter.name,
        target_scope=target.scope, loop=loop,
    )
