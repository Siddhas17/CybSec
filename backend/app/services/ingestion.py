"""Offline Dataset Demonstration ingestion (section 7 of the phase
instructions): reads real CICIDS2017 flows through the actual analytical
core (attack_graph + autoencoder + risk_engine, all Phase 2-4 artifacts,
none retrained or refit here) and persists a small, deterministic,
stratified sample -- never fake/precomputed detections, and never the
full 2.8M-flow dataset (section 7 explicitly forbids both).

Every event this produces has `source = EventSource.OFFLINE_DEMO` --
clearly distinguished from a future live sensor (section 19: never let
this be confused with live detection).

Bulk scoring reuses risk_engine.data_bridge (the same module
risk_engine/run_pipeline.py already uses) rather than routing each row
individually through AnalyticalPipeline.score() -- that class exists for
single-event scoring (test events, a future live sensor); re-deriving and
re-scaling 67 features one row at a time here would just be a slower,
duplicated path to the same numbers data_bridge already computes in
batches. Both paths ultimately call the same underlying
ml.models.autoencoder / risk_engine.scoring functions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pandas as pd
from sqlalchemy import delete
from sqlalchemy.orm import Session

from attack_graph.analysis.graph_metrics import annotate_degree_metrics
from attack_graph.config import TOPOLOGY_RAW_DIR
from attack_graph.generation.build_graph import build_graph_from_directory
from backend.app.models.detection import Detection
from backend.app.models.event import Event, EventSource
from backend.app.models.risk_assessment import RiskAssessment
from backend.app.services.graph_service import persist_graph
from backend.app.services.model_registry import ensure_all_model_versions, get_predictor, get_risk_config
from risk_engine.data_bridge import attach_graph_context, build_joint_flow_dataset
from risk_engine.schemas import FlowRiskContext
from risk_engine.scoring import score_event

DEFAULT_SAMPLE_PER_CATEGORY = 20
DEFAULT_MAX_TOTAL = 300


@dataclass
class IngestionReport:
    graph_nodes: int
    graph_edges: int
    total_real_flows_scanned: int
    sample_size: int
    categories_represented: list[str]
    runtime_seconds: float


def _none_if_nan(value):
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def _clear_offline_demo_events(db: Session) -> None:
    ids = [row.id for row in db.query(Event.id).filter(Event.source == EventSource.OFFLINE_DEMO)]
    if ids:
        db.execute(delete(Event).where(Event.id.in_(ids)))  # cascades to detections/risk_assessments
        db.commit()


def run_offline_ingestion(
    db: Session,
    sample_per_category: int = DEFAULT_SAMPLE_PER_CATEGORY,
    max_total: int = DEFAULT_MAX_TOTAL,
    seed: int = 42,
) -> IngestionReport:
    import time

    start = time.monotonic()

    predictor = get_predictor()
    risk_config = get_risk_config()
    versions = ensure_all_model_versions(db)

    graph, build_report = build_graph_from_directory(raw_dir=TOPOLOGY_RAW_DIR)
    annotate_degree_metrics(graph)
    persist_graph(db, graph)

    joint_df, bridge_report = build_joint_flow_dataset(TOPOLOGY_RAW_DIR, predictor)
    joint_df = attach_graph_context(joint_df, graph)

    sample = (
        joint_df.groupby("canonical_label", group_keys=False)
        .apply(lambda g: g.sample(n=min(len(g), sample_per_category), random_state=seed), include_groups=True)
    )
    if len(sample) > max_total:
        sample = sample.sample(n=max_total, random_state=seed)
    sample = sample.reset_index(drop=True)

    _clear_offline_demo_events(db)

    now = datetime.now(UTC)
    for i, row in sample.iterrows():
        last_seen = row.get("edge_last_seen")
        if pd.notna(last_seen):
            timestamp = pd.Timestamp(last_seen).to_pydatetime()
        else:
            # No graph context for this pair -- spread deterministically
            # over the last `len(sample)` minutes rather than fabricating
            # a specific historical time we don't actually have.
            timestamp = now - timedelta(minutes=len(sample) - i)

        risk_context = FlowRiskContext(
            anomaly_score=float(row["anomaly_score"]),
            edge_attack_ratio=_none_if_nan(row.get("edge_attack_ratio")),
            edge_attack_flow_count=_none_if_nan(row.get("edge_attack_flow_count")),
            edge_flow_count=_none_if_nan(row.get("edge_flow_count")),
            edge_first_seen=row.get("edge_first_seen") if pd.notna(row.get("edge_first_seen")) else None,
            edge_last_seen=row.get("edge_last_seen") if pd.notna(row.get("edge_last_seen")) else None,
            edge_attack_label_count=_none_if_nan(row.get("edge_attack_label_count")),
        )
        risk_result = score_event(risk_context, risk_config)

        event = Event(
            event_uid=f"offline-demo-{uuid.uuid4()}",
            timestamp=timestamp,
            source_ip=row["src_ip"],
            destination_ip=row["dst_ip"],
            canonical_attack_label=row["canonical_label"],
            traffic_class=row["traffic_class"],
            source=EventSource.OFFLINE_DEMO,
            status="processed",
        )
        db.add(event)
        db.flush()

        detection = Detection(
            event_id=event.id,
            anomaly_score=float(row["anomaly_score"]),
            reconstruction_error=float(row["anomaly_score"]),
            is_anomaly=bool(row["anomaly_score"] >= predictor.threshold),
            threshold_used=predictor.threshold,
            model_version_id=versions["autoencoder"].id,
        )
        db.add(detection)
        db.flush()

        db.add(
            RiskAssessment(
                event_id=event.id,
                detection_id=detection.id,
                risk_score=risk_result.risk_score,
                risk_level=risk_result.risk_level,
                factors=risk_result.factors,
                rules_applied=risk_result.rules_applied,
                reason=risk_result.reason,
                risk_config_version_id=versions["risk_engine"].id,
            )
        )

    db.commit()

    return IngestionReport(
        graph_nodes=graph.number_of_nodes(),
        graph_edges=graph.number_of_edges(),
        total_real_flows_scanned=bridge_report["total_scored_rows"],
        sample_size=len(sample),
        categories_represented=sorted(sample["canonical_label"].unique().tolist()),
        runtime_seconds=round(time.monotonic() - start, 2),
    )
