"""Serves the persisted Phase 2 attack-graph summary (section 13) --
never the raw CICIDS2017 CSVs or a rebuilt-per-request NetworkX graph.
Filtering is required, not optional: the full graph has ~19K nodes /
~114K edges, far too many for a browser graph visualization."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.attack_graph import AttackEdge, AttackNode
from backend.app.models.user import User
from backend.app.schemas.graph import AttackEdgeOut, AttackGraphOut, AttackNodeOut
from backend.app.services.model_registry import ATTACK_GRAPH_VERSION

router = APIRouter(prefix="/attack-graph", tags=["attack-graph"])


@router.get("", response_model=AttackGraphOut)
def get_attack_graph(
    limit: int = Query(50, ge=1, le=1000, description="Max edges to return"),
    min_attack_flow_count: int = Query(0, ge=0, description="Only edges with at least this many attack flows"),
    node_ip: str | None = Query(None, description="Only edges touching this IP (its neighborhood)"),
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> AttackGraphOut:
    edge_q = db.query(AttackEdge).filter(AttackEdge.attack_flow_count >= min_attack_flow_count)
    if node_ip:
        edge_q = edge_q.filter((AttackEdge.src_ip == node_ip) | (AttackEdge.dst_ip == node_ip))
        filter_applied = f"neighborhood(node_ip={node_ip}, min_attack_flow_count={min_attack_flow_count})"
    else:
        filter_applied = f"top_by_attack_flow_count(min_attack_flow_count={min_attack_flow_count})"

    total_edge_count = edge_q.count()
    edges = edge_q.order_by(AttackEdge.attack_flow_count.desc()).limit(limit).all()

    touched_ips = {e.src_ip for e in edges} | {e.dst_ip for e in edges}
    nodes = db.query(AttackNode).filter(AttackNode.ip.in_(touched_ips)).all() if touched_ips else []
    total_node_count = db.query(func.count(AttackNode.id)).scalar() or 0

    return AttackGraphOut(
        nodes=[AttackNodeOut.model_validate(n) for n in nodes],
        edges=[AttackEdgeOut.model_validate(e) for e in edges],
        graph_version=ATTACK_GRAPH_VERSION,
        total_node_count=total_node_count,
        total_edge_count=total_edge_count,
        returned_node_count=len(nodes),
        returned_edge_count=len(edges),
        filter_applied=filter_applied,
    )
