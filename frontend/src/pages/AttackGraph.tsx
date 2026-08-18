import { useCallback, useEffect, useMemo, useState } from "react";
import { ReactFlow, Background, Controls, MiniMap, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "../services/api";
import type { AttackGraphResponse } from "../types";

const ATTACK_COLOR = "#d64550";
const BENIGN_COLOR = "#3b9eff";

function layoutNodes(ips: string[]): Record<string, { x: number; y: number }> {
  // Simple circular layout -- no external layout library dependency for
  // this phase. Real coordinates, not decorative: every node/edge drawn
  // here comes directly from the /attack-graph API response.
  const radius = Math.max(220, ips.length * 18);
  const positions: Record<string, { x: number; y: number }> = {};
  ips.forEach((ip, i) => {
    const angle = (2 * Math.PI * i) / Math.max(1, ips.length);
    positions[ip] = { x: radius + radius * Math.cos(angle), y: radius + radius * Math.sin(angle) };
  });
  return positions;
}

export function AttackGraph() {
  const [data, setData] = useState<AttackGraphResponse | null>(null);
  const [minAttackFlowCount, setMinAttackFlowCount] = useState(1);
  const [limit, setLimit] = useState(30);
  const [nodeIp, setNodeIp] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    api
      .getAttackGraph({ limit, min_attack_flow_count: minAttackFlowCount, node_ip: nodeIp || undefined })
      .then(setData)
      .finally(() => setLoading(false));
  }, [limit, minAttackFlowCount, nodeIp]);

  useEffect(load, [load]);

  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const positions = layoutNodes(data.nodes.map((n) => n.ip));

    const rfNodes: Node[] = data.nodes.map((n) => ({
      id: n.ip,
      position: positions[n.ip] ?? { x: 0, y: 0 },
      data: { label: `${n.ip}\n${n.attack_flow_count.toLocaleString()} attack flows` },
      style: {
        background: n.attack_flow_count > 0 ? ATTACK_COLOR : BENIGN_COLOR,
        color: "white",
        fontSize: 10,
        borderRadius: 8,
        padding: 6,
        whiteSpace: "pre-line",
        border: "none",
      },
    }));

    const rfEdges: Edge[] = data.edges.map((e) => ({
      id: `${e.src_ip}->${e.dst_ip}`,
      source: e.src_ip,
      target: e.dst_ip,
      animated: e.attack_flow_count > 0,
      style: { stroke: e.attack_flow_count > 0 ? ATTACK_COLOR : BENIGN_COLOR, strokeWidth: Math.min(6, 1 + Math.log1p(e.flow_count)) },
      label: `${e.flow_count.toLocaleString()} flows`,
      labelStyle: { fontSize: 9, fill: "#8ea0b5" },
    }));

    return { nodes: rfNodes, edges: rfEdges };
  }, [data]);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Attack Graph</h1>
          <div className="page-subtitle">
            Live from the persisted Phase 2 attack graph
            {data && ` -- version ${data.graph_version}, showing ${data.returned_edge_count} of ${data.total_edge_count} edges`}.
            Red = attack-related, blue = benign only.
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginBottom: "1rem" }}>
        <div style={{ display: "flex", gap: "1rem", alignItems: "flex-end", flexWrap: "wrap" }}>
          <div>
            <label className="page-subtitle">Max edges</label>
            <input type="number" min={1} max={200} value={limit} onChange={(e) => setLimit(Number(e.target.value))} style={{ marginBottom: 0, width: 100 }} />
          </div>
          <div>
            <label className="page-subtitle">Min attack flow count</label>
            <input
              type="number"
              min={0}
              value={minAttackFlowCount}
              onChange={(e) => setMinAttackFlowCount(Number(e.target.value))}
              style={{ marginBottom: 0, width: 140 }}
            />
          </div>
          <div>
            <label className="page-subtitle">Neighborhood of IP (optional)</label>
            <input placeholder="e.g. 172.16.0.1" value={nodeIp} onChange={(e) => setNodeIp(e.target.value)} style={{ marginBottom: 0, width: 180 }} />
          </div>
        </div>
      </div>

      <div className="panel" style={{ height: 600, padding: 0 }}>
        {loading ? (
          <div className="empty-state">Loading graph...</div>
        ) : nodes.length === 0 ? (
          <div className="empty-state">No edges match this filter. Try lowering the minimum attack flow count.</div>
        ) : (
          <ReactFlow nodes={nodes} edges={edges} fitView>
            <Background />
            <Controls />
            <MiniMap />
          </ReactFlow>
        )}
      </div>
    </>
  );
}
