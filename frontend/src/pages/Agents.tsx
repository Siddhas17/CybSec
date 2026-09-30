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
  const [updatingAgentId, setUpdatingAgentId] = useState<number | null>(null);

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

  async function updateStatus(agent: AgentOut, status: AgentOut["status"]) {
    setUpdatingAgentId(agent.id);
    setError(null);
    try {
      const updatedAgent = await api.agents.updateStatus(agent.agent_id, status);
      setAgents((current) => current.map((item) => (item.id === updatedAgent.id ? updatedAgent : item)));
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(detail ?? "Could not update agent status -- check that the backend is running.");
    } finally {
      setUpdatingAgentId(null);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Agents</h1>
          <div className="page-subtitle">
            Victim-laptop agent identity, connectivity, and administrative lifecycle.
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
                <th>Connection</th>
                <th>Lifecycle</th>
                <th>Last Seen</th>
                <th>Agent Version</th>
                <th>Actions</th>
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
                  <td><span className="badge outline">{a.status === "active" ? "Active" : "Disabled"}</span></td>
                  <td>{a.last_seen ? new Date(a.last_seen).toLocaleString() : "never"}</td>
                  <td>{a.agent_version ?? "-"}</td>
                  <td>
                    <button
                      className="secondary"
                      disabled={updatingAgentId !== null}
                      onClick={() => updateStatus(a, a.status === "active" ? "disabled" : "active")}
                      style={{ width: "auto" }}
                    >
                      {updatingAgentId === a.id ? "Updating..." : a.status === "active" ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
