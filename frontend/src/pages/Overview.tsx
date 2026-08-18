import { useEffect, useState } from "react";
import { api } from "../services/api";
import { StatCard } from "../components/StatCard";
import type { HealthStatus, Summary } from "../types";

export function Overview() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.analytics.summary(), api.health()])
      .then(([s, h]) => {
        setSummary(s);
        setHealth(h);
      })
      .catch(() => setError("Could not load dashboard summary."));
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Overview</h1>
          <div className="page-subtitle">System-wide summary of persisted analytical results.</div>
        </div>
      </div>

      {error && <div className="notice-banner">{error}</div>}

      {summary && (
        <>
          {summary.total_events === 0 && (
            <div className="notice-banner">
              No events ingested yet. Run the Offline Dataset Demonstration ingestion (POST /api/v1/admin/ingest) or submit a
              test event to populate the dashboard with real analytical results.
            </div>
          )}
          <div className="grid grid-stats">
            <StatCard label="Total Events" value={summary.total_events} />
            <StatCard label="Detected Anomalies" value={summary.anomaly_count} hint="Autoencoder flagged (>= threshold)" />
            <StatCard label="High-Risk Events" value={summary.high_risk_events} hint="Risk score >= 7" />
            <StatCard label="Benign Events" value={summary.benign_count} />
            <StatCard
              label="System Health"
              value={health?.status ?? "..."}
              hint={health ? `DB: ${health.database} · Core: ${health.analytical_core}` : undefined}
            />
          </div>
          {summary.last_ingested_at && (
            <div className="panel" style={{ marginTop: "1rem" }}>
              <div className="page-subtitle">Last data ingested: {new Date(summary.last_ingested_at).toLocaleString()}</div>
            </div>
          )}
        </>
      )}
    </>
  );
}
