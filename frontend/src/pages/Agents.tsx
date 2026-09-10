import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { AgentOut } from "../types";

function OnlineDot({ online }: { online: boolean }) {
  return (
    <span className="pill">
      <span className={`dot ${online ? "ok" : "bad"}`} />
      {online ? "Online" : "Offline"}
    </span>
  );
}

export function Agents() {
  const [agents, setAgents] = useState<AgentOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    api.agents
      .list()
      .then((data) => {
        setAgents(data);
        setError(null);
      })
      .catch(() => setError("Could not load agents -- check that the backend is running."))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Agents</h1>
          <div className="page-subtitle">
            Victim-laptop agents registered with this Admin (victim_agent, Phase 1) -- identity, heartbeat, and real
            connection telemetry only. Status is computed from <code>last_seen</code>, never hardcoded. See{" "}
            <code>docs/victim_agent.md</code> for the full design and why raw telemetry is not yet scored.
          </div>
        </div>
      </div>

      {error && <div className="notice-banner">{error}</div>}

      <div className="panel">
        <div className="section-title">Registered Agents ({agents.length})</div>
        {loading ? (
          <div className="empty-state">Loading...</div>
        ) : agents.length === 0 ? (
          <div className="empty-state">No agents have registered yet. See victim_agent/README.md to set one up.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th>Agent Version</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.agent_id}</td>
                  <td>{a.hostname}</td>
                  <td className="mono">{a.ip_address ?? "-"}</td>
                  <td>
                    <OnlineDot online={a.online} />
                  </td>
                  <td>{a.last_seen ? new Date(a.last_seen).toLocaleString() : "never"}</td>
                  <td>{a.agent_version ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
