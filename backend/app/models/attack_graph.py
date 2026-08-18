from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, BigInteger, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class AttackNode(Base):
    """Persisted node-level summary from attack_graph (Phase 2) -- not the
    full flow-level data, just the already-aggregated statistics, per the
    instruction to precompute/persist summaries rather than re-scan raw
    CSVs per request."""

    __tablename__ = "attack_nodes"
    __table_args__ = (UniqueConstraint("ip", "graph_version_id", name="uq_attack_node_ip_version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    total_flow_count: Mapped[int] = mapped_column(Integer, nullable=False)
    benign_flow_count: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_flow_count: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    attack_ratio: Mapped[float] = mapped_column(Float, nullable=False)
    in_degree: Mapped[int] = mapped_column(Integer, nullable=False)
    out_degree: Mapped[int] = mapped_column(Integer, nullable=False)
    degree: Mapped[int] = mapped_column(Integer, nullable=False, index=True)

    graph_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class AttackEdge(Base):
    """Persisted edge-level summary from attack_graph (Phase 2)."""

    __tablename__ = "attack_edges"
    __table_args__ = (UniqueConstraint("src_ip", "dst_ip", "graph_version_id", name="uq_attack_edge_pair_version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    flow_count: Mapped[int] = mapped_column(Integer, nullable=False)
    benign_flow_count: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_flow_count: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    attack_ratio: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    unique_source_ports: Mapped[int] = mapped_column(Integer, nullable=False)
    unique_destination_ports: Mapped[int] = mapped_column(Integer, nullable=False)
    protocols_seen: Mapped[list] = mapped_column(JSON, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_forward_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_backward_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attack_labels: Mapped[list] = mapped_column(JSON, nullable=False)

    graph_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
