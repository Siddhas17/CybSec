from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AttackNodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    total_flow_count: int
    benign_flow_count: int
    attack_flow_count: int
    attack_ratio: float
    in_degree: int
    out_degree: int
    degree: int


class AttackEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    src_ip: str
    dst_ip: str
    flow_count: int
    benign_flow_count: int
    attack_flow_count: int
    attack_ratio: float
    unique_source_ports: int
    unique_destination_ports: int
    protocols_seen: list[int]
    first_seen: datetime | None
    last_seen: datetime | None
    total_forward_bytes: int
    total_backward_bytes: int
    attack_labels: list[str]


class AttackGraphOut(BaseModel):
    nodes: list[AttackNodeOut]
    edges: list[AttackEdgeOut]
    graph_version: str
    total_node_count: int
    total_edge_count: int
    returned_node_count: int
    returned_edge_count: int
    filter_applied: str
