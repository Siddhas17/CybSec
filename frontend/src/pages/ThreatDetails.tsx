import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../services/api";
import { RiskBadge } from "../components/RiskBadge";
import { EventSourceTag } from "../components/EventSourceTag";
import type { EventDetail } from "../types";

export function ThreatDetails() {
  const { eventId } = useParams<{ eventId: string }>();
  const [event, setEvent] = useState<EventDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!eventId) return;
    api
      .getEvent(Number(eventId))
      .then(setEvent)
      .catch(() => setError("Event not found."));
  }, [eventId]);

  if (error) return <div className="notice-banner">{error}</div>;
  if (!event) return <div className="empty-state">Loading...</div>;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Threat Details -- Event #{event.id}</h1>
          <div className="page-subtitle">
            <Link to="/threats">&larr; Back to Live Threats</Link>
          </div>
        </div>
        <EventSourceTag source={event.source} />
      </div>

      <div className="grid grid-2">
        <div className="panel">
          <div className="section-title">Event Information</div>
          <dl className="mono" style={{ fontSize: "0.85rem", lineHeight: 1.8 }}>
            <div>UID: {event.event_uid}</div>
            <div>Timestamp: {new Date(event.timestamp).toLocaleString()}</div>
            <div>
              Source: {event.source_ip}
              {event.source_port ? `:${event.source_port}` : ""}
            </div>
            <div>
              Destination: {event.destination_ip}
              {event.destination_port ? `:${event.destination_port}` : ""}
            </div>
            <div>Protocol: {event.protocol ?? "n/a"}</div>
            <div>Canonical Label: {event.canonical_attack_label ?? "n/a (unlabeled)"}</div>
            <div>Traffic Class (ground truth, if known): {event.traffic_class ?? "n/a"}</div>
          </dl>
        </div>

        <div className="panel">
          <div className="section-title">Detected Anomaly</div>
          {event.detection ? (
            <>
              <div style={{ fontSize: "1.6rem", fontWeight: 600 }}>{event.detection.anomaly_score.toFixed(6)}</div>
              <div className="page-subtitle">
                Reconstruction error &middot; threshold {event.detection.threshold_used.toFixed(6)}
              </div>
              <div style={{ marginTop: 8 }}>
                {event.detection.is_anomaly ? (
                  <span className="badge critical">Detected Anomaly</span>
                ) : (
                  <span className="badge outline">Within normal range</span>
                )}
              </div>
            </>
          ) : (
            <div className="empty-state">No detection recorded.</div>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="section-title">Risk Assessment</div>
        {event.risk_assessment ? (
          <>
            <div style={{ display: "flex", alignItems: "baseline", gap: "1rem" }}>
              <div style={{ fontSize: "2rem", fontWeight: 700 }}>{event.risk_assessment.risk_score.toFixed(2)} / 10</div>
              <RiskBadge level={event.risk_assessment.risk_level} />
            </div>
            <p style={{ color: "var(--text-muted)" }}>{event.risk_assessment.reason}</p>

            <div className="section-title" style={{ marginTop: "1rem" }}>
              Risk Factors
            </div>
            {event.risk_assessment.factors.map((f) => (
              <div key={f.name} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.85rem" }}>
                  <span>{f.name.replace(/_/g, " ")}</span>
                  <span className="mono">
                    value {f.value.toFixed(3)} &middot; contribution {f.contribution.toFixed(3)}
                  </span>
                </div>
                <div className="factor-bar-track">
                  <div className="factor-bar-fill" style={{ width: `${Math.min(100, f.value * 100)}%` }} />
                </div>
              </div>
            ))}

            {event.risk_assessment.rules_applied.length > 0 && (
              <div style={{ marginTop: "0.75rem" }}>
                <div className="page-subtitle">Context rules applied:</div>
                {event.risk_assessment.rules_applied.map((r) => (
                  <span key={r} className="badge outline" style={{ marginRight: 6, marginTop: 4, display: "inline-block" }}>
                    {r.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            )}
          </>
        ) : (
          <div className="empty-state">No risk assessment recorded.</div>
        )}
      </div>

      <div className="panel">
        <div className="section-title">Attack-Graph Context</div>
        {event.graph_context ? (
          <dl className="mono" style={{ fontSize: "0.85rem", lineHeight: 1.8 }}>
            <div>Edge attack ratio: {event.graph_context.edge_attack_ratio?.toFixed(4) ?? "n/a"}</div>
            <div>Edge attack flow count: {event.graph_context.edge_attack_flow_count ?? "n/a"}</div>
            <div>Edge total flow count: {event.graph_context.edge_flow_count ?? "n/a"}</div>
            <div>First seen: {event.graph_context.edge_first_seen ? new Date(event.graph_context.edge_first_seen).toLocaleString() : "n/a"}</div>
            <div>Last seen: {event.graph_context.edge_last_seen ? new Date(event.graph_context.edge_last_seen).toLocaleString() : "n/a"}</div>
          </dl>
        ) : (
          <div className="empty-state">No attack-related communication history found for this source/destination pair.</div>
        )}
      </div>
    </>
  );
}
