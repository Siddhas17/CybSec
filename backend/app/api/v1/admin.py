"""Admin-only actions -- currently just triggering the offline dataset
demonstration ingestion (section 7). Not a generic "execute command" API
(section 12) -- this endpoint does exactly one thing, with no
user-supplied code or shell access."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.user import User
from backend.app.services import audit
from backend.app.services.ingestion import run_offline_ingestion

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/ingest")
def trigger_offline_ingestion(
    sample_per_category: int = Query(20, ge=1, le=200),
    max_total: int = Query(300, ge=1, le=2000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Rebuilds the attack graph and re-ingests a fresh stratified sample
    of real, labeled flows -- takes roughly 2 minutes (full dataset scan).
    Clearly an administrative action, not something the dashboard calls on
    every page load."""
    report = run_offline_ingestion(db, sample_per_category=sample_per_category, max_total=max_total)
    audit.log(
        db,
        "INFO",
        "ingestion",
        f"Offline demo ingestion run: {report.sample_size} events, {report.graph_edges} graph edges",
        user_id=current_user.id,
        metadata={
            "graph_nodes": report.graph_nodes,
            "graph_edges": report.graph_edges,
            "sample_size": report.sample_size,
            "runtime_seconds": report.runtime_seconds,
        },
    )
    return {
        "status": "Offline Dataset Demonstration ingestion complete",
        "graph_nodes": report.graph_nodes,
        "graph_edges": report.graph_edges,
        "total_real_flows_scanned": report.total_real_flows_scanned,
        "sample_size": report.sample_size,
        "categories_represented": report.categories_represented,
        "runtime_seconds": report.runtime_seconds,
    }
