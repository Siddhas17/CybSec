import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../services/api";
import { RiskBadge } from "../components/RiskBadge";
import { EventSourceTag } from "../components/EventSourceTag";
import { useWebSocket } from "../hooks/useWebSocket";
import type { ThreatRow } from "../types";

export function LiveThreats() {
  const [threats, setThreats] = useState<ThreatRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { messages } = useWebSocket();

  function reload() {
    setLoading(true);
    setError(null);
    api
      .listThreats({ limit: 100 })
      .then(setThreats)
      .catch(() => setError("Could not load threats -- check that the backend is running."))
      .finally(() => setLoading(false));
  }

  useEffect(reload, []);

  // Re-fetch when a new_threat event streams in over the WebSocket, so the
  // table reflects newly-persisted results without a full page reload.
  useEffect(() => {
    if (messages.length > 0 && messages[0].type === "new_threat") {
      reload();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messages]);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Live Threats</h1>
          <div className="page-subtitle">Persisted analytical results, newest first. Click a row for full details.</div>
        </div>
      </div>

      {error && <div className="notice-banner">{error}</div>}

      <div className="panel">
        {loading ? (
          <div className="empty-state">Loading...</div>
        ) : threats.length === 0 ? (
          <div className="empty-state">No events yet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Attack Label</th>
                <th>Anomaly Score</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>Origin</th>
              </tr>
            </thead>
            <tbody>
              {threats.map((t) => (
                <tr key={t.event_id} onClick={() => navigate(`/threats/${t.event_id}`)}>
                  <td>{new Date(t.timestamp).toLocaleString()}</td>
                  <td className="mono">
                    {t.source_ip}
                    {t.source_port ? `:${t.source_port}` : ""}
                  </td>
                  <td className="mono">
                    {t.destination_ip}
                    {t.destination_port ? `:${t.destination_port}` : ""}
                  </td>
                  <td>{t.protocol ?? "-"}</td>
                  <td>{t.canonical_attack_label ?? "-"}</td>
                  <td>{t.anomaly_score !== null ? t.anomaly_score.toFixed(4) : "-"}</td>
                  <td>{t.risk_score !== null ? t.risk_score.toFixed(2) : "-"}</td>
                  <td>
                    <RiskBadge level={t.risk_level} />
                  </td>
                  <td>
                    <EventSourceTag source={t.event_source} />
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
