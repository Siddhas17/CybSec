"""Dashboard analytics: every query reads from already-persisted tables
(events/detections/risk_assessments/attack_edges) -- never re-scans the
raw CICIDS2017 CSVs at request time (section 15)."""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.models.attack_graph import AttackEdge
from backend.app.models.detection import Detection
from backend.app.models.event import Event
from backend.app.models.risk_assessment import RiskAssessment
from risk_engine.config import HIGH_RISK_THRESHOLD


def get_summary(db: Session) -> dict:
    total_events = db.query(func.count(Event.id)).scalar() or 0
    anomaly_count = db.query(func.count(Detection.id)).filter(Detection.is_anomaly.is_(True)).scalar() or 0
    high_risk_events = db.query(func.count(RiskAssessment.id)).filter(RiskAssessment.risk_score >= HIGH_RISK_THRESHOLD).scalar() or 0
    benign_count = db.query(func.count(Event.id)).filter(Event.traffic_class == "BENIGN").scalar() or 0
    last_event = db.query(func.max(Event.created_at)).scalar()

    return {
        "total_events": total_events,
        "active_threats": anomaly_count,
        "high_risk_events": high_risk_events,
        "anomaly_count": anomaly_count,
        "benign_count": benign_count,
        "last_ingested_at": last_event.isoformat() if last_event else None,
        "system_health": "operational" if total_events > 0 else "no_data",
    }


def get_attacks_by_type(db: Session) -> list[dict]:
    rows = (
        db.query(Event.canonical_attack_label, func.count(Event.id))
        .filter(Event.canonical_attack_label.isnot(None), Event.canonical_attack_label != "BENIGN")
        .group_by(Event.canonical_attack_label)
        .order_by(func.count(Event.id).desc())
        .all()
    )
    return [{"attack_type": label, "count": count} for label, count in rows]


def get_risk_distribution(db: Session) -> list[dict]:
    rows = db.query(RiskAssessment.risk_level, func.count(RiskAssessment.id)).group_by(RiskAssessment.risk_level).all()
    return [{"risk_level": level, "count": count} for level, count in rows]


def get_timeline(db: Session) -> list[dict]:
    """Events per hour bucket. MySQL DATE_FORMAT for portable hour
    truncation."""
    bucket = func.date_format(Event.timestamp, "%Y-%m-%d %H:00:00")
    rows = (
        db.query(bucket.label("bucket"), func.count(Event.id), func.sum(func.if_(Event.traffic_class == "ATTACK", 1, 0)))
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    return [{"bucket": str(b), "event_count": int(c), "attack_count": int(a or 0)} for b, c, a in rows]


def get_top_sources(db: Session, limit: int = 10) -> list[dict]:
    rows = (
        db.query(AttackEdge.src_ip, func.sum(AttackEdge.attack_flow_count), func.sum(AttackEdge.flow_count))
        .group_by(AttackEdge.src_ip)
        .order_by(func.sum(AttackEdge.attack_flow_count).desc())
        .limit(limit)
        .all()
    )
    return [{"ip": ip, "attack_flow_count": int(a or 0), "total_flow_count": int(t or 0)} for ip, a, t in rows]


def get_top_destinations(db: Session, limit: int = 10) -> list[dict]:
    rows = (
        db.query(AttackEdge.dst_ip, func.sum(AttackEdge.attack_flow_count), func.sum(AttackEdge.flow_count))
        .group_by(AttackEdge.dst_ip)
        .order_by(func.sum(AttackEdge.attack_flow_count).desc())
        .limit(limit)
        .all()
    )
    return [{"ip": ip, "attack_flow_count": int(a or 0), "total_flow_count": int(t or 0)} for ip, a, t in rows]


def get_anomaly_score_distribution(db: Session, buckets: int = 10) -> list[dict]:
    scores = [row[0] for row in db.query(Detection.anomaly_score).all()]
    if not scores:
        return []
    import numpy as np

    hist, edges = np.histogram(scores, bins=buckets)
    return [{"range_start": float(edges[i]), "range_end": float(edges[i + 1]), "count": int(hist[i])} for i in range(len(hist))]


def get_risk_score_distribution(db: Session, buckets: int = 10) -> list[dict]:
    scores = [row[0] for row in db.query(RiskAssessment.risk_score).all()]
    if not scores:
        return []
    import numpy as np

    hist, edges = np.histogram(scores, bins=buckets, range=(1, 10))
    return [{"range_start": float(edges[i]), "range_end": float(edges[i + 1]), "count": int(hist[i])} for i in range(len(hist))]
