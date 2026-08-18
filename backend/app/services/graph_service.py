"""Persists the Phase 2 attack graph's node/edge summary statistics into
MySQL (so the API/dashboard never re-scans raw CSVs or rebuilds the graph
per request -- section 15), and provides lookup/query helpers.
"""

from __future__ import annotations

from datetime import datetime

import networkx as nx
from sqlalchemy import delete
from sqlalchemy.orm import Session

from backend.app.models.attack_graph import AttackEdge, AttackNode
from backend.app.services.analytical_pipeline import GraphContext
from backend.app.services.model_registry import ATTACK_GRAPH_VERSION, get_or_create_model_version


def _parse_ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def persist_graph(db: Session, graph: nx.DiGraph) -> int:
    """Replaces any previously persisted graph snapshot for
    ATTACK_GRAPH_VERSION with the given (freshly built) graph. Bulk
    inserts for reasonable performance against ~19K nodes / ~114K edges."""
    version = get_or_create_model_version(db, "attack_graph", ATTACK_GRAPH_VERSION)

    db.execute(delete(AttackNode).where(AttackNode.graph_version_id == version.id))
    db.execute(delete(AttackEdge).where(AttackEdge.graph_version_id == version.id))

    db.bulk_insert_mappings(
        AttackNode,
        [
            {
                "ip": ip,
                "total_flow_count": data.get("total_flow_count", 0),
                "benign_flow_count": data.get("benign_flow_count", 0),
                "attack_flow_count": data.get("attack_flow_count", 0),
                "attack_ratio": data.get("attack_ratio", 0.0),
                "in_degree": data.get("in_degree", 0),
                "out_degree": data.get("out_degree", 0),
                "degree": data.get("degree", 0),
                "graph_version_id": version.id,
            }
            for ip, data in graph.nodes(data=True)
        ],
    )
    db.bulk_insert_mappings(
        AttackEdge,
        [
            {
                "src_ip": u,
                "dst_ip": v,
                "flow_count": d.get("flow_count", 0),
                "benign_flow_count": d.get("benign_flow_count", 0),
                "attack_flow_count": d.get("attack_flow_count", 0),
                "attack_ratio": d.get("attack_ratio", 0.0),
                "unique_source_ports": d.get("unique_source_ports", 0),
                "unique_destination_ports": d.get("unique_destination_ports", 0),
                "protocols_seen": d.get("protocols_seen", []),
                "first_seen": _parse_ts(d.get("first_seen")),
                "last_seen": _parse_ts(d.get("last_seen")),
                "total_forward_bytes": d.get("total_forward_bytes", 0),
                "total_backward_bytes": d.get("total_backward_bytes", 0),
                "attack_labels": d.get("attack_labels", []),
                "graph_version_id": version.id,
            }
            for u, v, d in graph.edges(data=True)
        ],
    )
    db.commit()
    return graph.number_of_edges()


def get_edge_context(db: Session, src_ip: str, dst_ip: str) -> GraphContext:
    """Looks up persisted edge context for a (src, dst) pair -- used by
    the test-events endpoint. Returns an empty GraphContext (all fields
    None) if the pair has never been observed, rather than raising."""
    edge = (
        db.query(AttackEdge)
        .filter(AttackEdge.src_ip == src_ip, AttackEdge.dst_ip == dst_ip)
        .order_by(AttackEdge.id.desc())
        .first()
    )
    if edge is None:
        return GraphContext()
    return GraphContext(
        edge_attack_ratio=edge.attack_ratio,
        edge_attack_flow_count=edge.attack_flow_count,
        edge_flow_count=edge.flow_count,
        edge_first_seen=edge.first_seen.isoformat() if edge.first_seen else None,
        edge_last_seen=edge.last_seen.isoformat() if edge.last_seen else None,
        edge_attack_label_count=len(edge.attack_labels or []),
    )
