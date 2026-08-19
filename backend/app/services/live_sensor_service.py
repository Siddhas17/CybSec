"""Bridges sensor/ (collector -> flow reconstruction -> feature adapter)
into the exact same TelemetryEvent -> AnalyticalPipeline.score() ->
DetectionResult path test-events and offline ingestion already use
(section 1: no second ML implementation for live traffic -- this module
contains zero scoring logic of its own).

The API layer (backend/app/api/v1/sensor.py) only starts/stops/reads this
service -- no ML code lives there (section 10). This module owns the
collector, the flow accumulator, LIVE_GRAPH, and the health counters the
System Health page reads (section 14).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from backend.app.db.session import SessionLocal
from backend.app.models.detection import Detection
from backend.app.models.event import Event, EventSource
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.services.analytical_pipeline import AnalyticalPipeline, DetectionResult, GraphContext, TelemetryEvent
from backend.app.services.model_registry import ensure_all_model_versions, get_predictor, get_risk_config
from backend.app.websocket.manager import manager
from sensor.collectors.netns_loopback import NetnsLoopbackCollector
from sensor.config import sensor_config
from sensor.live_graph import LiveGraph
from sensor.normalization.feature_adapter import adapt_features
from sensor.normalization.flow_reconstruction import FlowAccumulator, RawFlow

logger = logging.getLogger(__name__)

# What LiveGraph treats as "this edge's own live detections flagged it" --
# matches risk_engine's own "High" boundary (docs/risk_engine.md section
# 7), but this is never ground truth (section 9): it is the analytical
# pipeline's own live output feeding back into LIVE_GRAPH's edge stats.
HIGH_RISK_FLAG_THRESHOLD = 7.0


@dataclass
class SensorHealth:
    collector_status: str
    interface: str
    telemetry_enabled: bool
    started_at: str | None
    last_event_at: str | None
    packets_received: int
    packets_dropped: int
    parse_errors: int
    events_processed: int
    events_rejected: int
    processing_errors: int
    active_flows: int
    live_graph_edges: int
    model_available: bool
    last_error: str | None


class LiveSensorService:
    def __init__(self) -> None:
        self._collector = NetnsLoopbackCollector()
        self._flow_accumulator = FlowAccumulator()
        self._live_graph = LiveGraph(
            window_seconds=sensor_config.live_graph_window_seconds,
            max_edges=sensor_config.live_graph_max_edges,
        )
        self._worker_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

        self._events_processed = 0
        self._events_rejected = 0
        self._processing_errors = 0
        self._last_error: str | None = None
        self._model_available = True

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        if not sensor_config.telemetry_enabled:
            raise RuntimeError("TELEMETRY_ENABLED=false in .env -- refusing to start the live sensor (section 15)")
        with self._lock:
            if self._worker_thread is not None and self._worker_thread.is_alive():
                return  # start() is idempotent
            self._loop = loop
            self._stop_event.clear()
            self._collector.start()
            self._worker_thread = threading.Thread(target=self._run, daemon=True, name="live-sensor")
            self._worker_thread.start()

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            self._collector.stop()
            thread = self._worker_thread
        if thread is not None:
            thread.join(timeout=10)

    def health(self) -> SensorHealth:
        collector_health = self._collector.health()
        return SensorHealth(
            collector_status=collector_health.status.value,
            interface=collector_health.interface,
            telemetry_enabled=sensor_config.telemetry_enabled,
            started_at=collector_health.started_at,
            last_event_at=collector_health.last_event_at,
            packets_received=collector_health.packets_received,
            packets_dropped=collector_health.packets_dropped,
            parse_errors=collector_health.parse_errors,
            events_processed=self._events_processed,
            events_rejected=self._events_rejected,
            processing_errors=self._processing_errors,
            active_flows=self._flow_accumulator.active_flow_count,
            live_graph_edges=self._live_graph.edge_count,
            model_available=self._model_available,
            last_error=self._last_error or collector_health.last_error,
        )

    # -- internals --------------------------------------------------------

    def _run(self) -> None:
        try:
            pipeline = AnalyticalPipeline(get_predictor(), get_risk_config())
            self._model_available = True
        except Exception as exc:  # model/config unavailable -- section 13/7: never half-start
            self._model_available = False
            self._last_error = f"analytical core unavailable, sensor not processing: {exc}"
            logger.error(self._last_error)
            self._collector.stop()
            return

        last_cleanup = time.monotonic()
        for packet_event in self._collector.events():
            if self._stop_event.is_set():
                break
            try:
                completed_flows = self._flow_accumulator.ingest(packet_event)
            except Exception as exc:  # malformed telemetry must never kill the loop (section 13)
                self._events_rejected += 1
                self._last_error = f"flow reconstruction rejected an event: {exc}"
                logger.warning(self._last_error)
                continue

            for flow in completed_flows:
                self._process_flow(flow, pipeline)

            if time.monotonic() - last_cleanup > sensor_config.live_graph_cleanup_interval_seconds:
                self._cleanup(pipeline)
                last_cleanup = time.monotonic()

        # Drain flows still in progress rather than silently dropping
        # whatever was observed right before stop() was called.
        for flow in self._flow_accumulator.flush_all():
            self._process_flow(flow, pipeline)

    def _cleanup(self, pipeline: AnalyticalPipeline) -> None:
        now = time.time()
        for flow in self._flow_accumulator.flush_idle(now):
            self._process_flow(flow, pipeline)
        removed = self._live_graph.cleanup(now)
        if removed:
            logger.info("live sensor: evicted %d idle LIVE_GRAPH edge(s)", removed)

    def _process_flow(self, flow: RawFlow, pipeline: AnalyticalPipeline) -> None:
        try:
            adapted = adapt_features(flow, activity_idle_threshold_seconds=sensor_config.activity_idle_threshold_seconds)

            telemetry = TelemetryEvent(
                source_ip=flow.forward_ip,
                destination_ip=flow.backward_ip,
                source_port=flow.forward_port,
                destination_port=flow.backward_port,
                protocol=flow.protocol,
                timestamp=datetime.fromtimestamp(flow.first_ts, tz=UTC),
                features=adapted.features,
            )

            live_context = self._live_graph.get_context(flow.forward_ip, flow.backward_ip)
            graph_context = GraphContext(
                edge_attack_ratio=live_context.edge_attack_ratio,
                edge_attack_flow_count=live_context.edge_attack_flow_count,
                edge_flow_count=live_context.edge_flow_count,
                edge_first_seen=live_context.edge_first_seen,
                edge_last_seen=live_context.edge_last_seen,
                edge_attack_label_count=live_context.edge_attack_label_count,
            )

            result = pipeline.score(telemetry, graph_context)
            event = self._persist(telemetry, result)
            self._broadcast(event, result)

            is_flagged = result.is_anomaly or result.risk_score >= HIGH_RISK_FLAG_THRESHOLD
            self._live_graph.record_flow(
                flow.forward_ip,
                flow.backward_ip,
                flow.forward_port,
                flow.backward_port,
                flow.protocol,
                flow.last_ts,
                is_flagged,
            )
            self._events_processed += 1
        except Exception as exc:  # one bad flow (e.g. DB unavailable) must not stop the sensor (section 13)
            self._processing_errors += 1
            self._last_error = str(exc)
            logger.exception("live sensor: failed to process a completed flow")

    def _persist(self, telemetry: TelemetryEvent, result: DetectionResult) -> Event:
        db: Session = SessionLocal()
        try:
            versions = ensure_all_model_versions(db)
            event = Event(
                event_uid=f"live-{uuid.uuid4()}",
                timestamp=telemetry.timestamp or datetime.now(UTC),
                source_ip=telemetry.source_ip,
                source_port=telemetry.source_port,
                destination_ip=telemetry.destination_ip,
                destination_port=telemetry.destination_port,
                protocol=telemetry.protocol,
                canonical_attack_label=None,  # genuinely unknown for live traffic -- never fabricated
                traffic_class=None,
                source=EventSource.LIVE,
                status="processed",
            )
            db.add(event)
            db.flush()

            detection = Detection(
                event_id=event.id,
                anomaly_score=result.anomaly_score,
                reconstruction_error=result.reconstruction_error,
                is_anomaly=result.is_anomaly,
                threshold_used=result.threshold_used,
                model_version_id=versions["autoencoder"].id,
            )
            db.add(detection)
            db.flush()

            db.add(
                RiskAssessment(
                    event_id=event.id,
                    detection_id=detection.id,
                    risk_score=result.risk_score,
                    risk_level=result.risk_level,
                    factors=result.factors,
                    rules_applied=result.rules_applied,
                    reason=result.reason,
                    risk_config_version_id=versions["risk_engine"].id,
                )
            )
            db.commit()
            db.refresh(event)
            return event
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _broadcast(self, event: Event, result: DetectionResult) -> None:
        if self._loop is None:
            return
        payload = {
            "event_id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "event_source": "live",
        }
        try:
            future = asyncio.run_coroutine_threadsafe(manager.broadcast("new_threat", payload), self._loop)
            future.add_done_callback(self._log_broadcast_failure)
        except RuntimeError as exc:  # event loop unavailable/closed -- section 13's "WebSocket unavailable"
            logger.warning("live sensor: could not schedule websocket broadcast: %s", exc)

    @staticmethod
    def _log_broadcast_failure(future) -> None:
        exc = future.exception()
        if exc is not None:
            logger.warning("live sensor: websocket broadcast failed: %s", exc)


live_sensor_service = LiveSensorService()
