import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { TopNode } from "../types";

export function Victims() {
  const [destinations, setDestinations] = useState<TopNode[]>([]);

  useEffect(() => {
    api.analytics.topDestinations(25).then(setDestinations);
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Victims -- Top Attacked Destination IPs</h1>
          <div className="page-subtitle">Ranked by observed attack-flow count in the attack graph.</div>
        </div>
      </div>

      <div className="notice-banner">
        This is a single-machine environment; these are destination IPs observed in captured traffic, not
        separate physical victim hosts. There is no live multi-host laboratory in this deployment.
      </div>

      <div className="panel">
        {destinations.length === 0 ? (
          <div className="empty-state">No data yet.</div>
        ) : (
          <table>
            <thead>
              <tr><th>IP</th><th>Attack Flows</th><th>Total Flows</th><th>Attack Ratio</th></tr>
            </thead>
            <tbody>
              {destinations.map((n) => (
                <tr key={n.ip}>
                  <td className="mono">{n.ip}</td>
                  <td>{n.attack_flow_count.toLocaleString()}</td>
                  <td>{n.total_flow_count.toLocaleString()}</td>
                  <td>{n.total_flow_count ? `${((n.attack_flow_count / n.total_flow_count) * 100).toFixed(1)}%` : "--"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
