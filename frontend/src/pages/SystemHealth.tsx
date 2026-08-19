import { useEffect, useState, type FormEvent } from "react";
import { api } from "../services/api";
import { useWebSocket } from "../hooks/useWebSocket";
import type { HealthStatus, SensorHealth, TestEventResult } from "../types";

export function SystemHealth() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const { status: wsStatus } = useWebSocket();

  const [ingesting, setIngesting] = useState(false);
  const [ingestResult, setIngestResult] = useState<string | null>(null);

  const [sourceIp, setSourceIp] = useState("10.0.0.1");
  const [destIp, setDestIp] = useState("10.0.0.2");
  const [testResult, setTestResult] = useState<TestEventResult | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [sensorHealth, setSensorHealth] = useState<SensorHealth | null>(null);
  const [sensorBusy, setSensorBusy] = useState(false);
  const [sensorMessage, setSensorMessage] = useState<string | null>(null);

  function loadHealth() {
    api.health().then(setHealth);
  }

  function loadSensorHealth() {
    api.sensor.health().then(setSensorHealth).catch(() => setSensorHealth(null));
  }

  useEffect(loadHealth, []);
  useEffect(() => {
    loadSensorHealth();
    const interval = setInterval(loadSensorHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  async function startSensor() {
    setSensorBusy(true);
    setSensorMessage(null);
    try {
      await api.sensor.start();
      setSensorMessage("Live sensor started.");
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setSensorMessage(detail ?? "Failed to start the live sensor -- check backend logs.");
    } finally {
      setSensorBusy(false);
      loadSensorHealth();
    }
  }

  async function stopSensor() {
    setSensorBusy(true);
    setSensorMessage(null);
    try {
      await api.sensor.stop();
      setSensorMessage("Live sensor stopped.");
    } finally {
      setSensorBusy(false);
      loadSensorHealth();
    }
  }

  async function runIngestion() {
    setIngesting(true);
    setIngestResult(null);
    try {
      const report = await api.triggerIngestion();
      setIngestResult(`Ingested ${report.sample_size} events across ${report.categories_represented.length} categories in ${report.runtime_seconds}s.`);
    } catch {
      setIngestResult("Ingestion failed -- check backend logs.");
    } finally {
      setIngesting(false);
    }
  }

  async function submitTestEvent(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setTestResult(null);
    try {
      const result = await api.createTestEvent({ source_ip: sourceIp, destination_ip: destIp });
      setTestResult(result);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>System Health</h1>
          <div className="page-subtitle">Backend, database, WebSocket, and analytical-core status, plus administrative actions.</div>
        </div>
      </div>

      <div className="grid grid-stats">
        <div className="stat-card">
          <div className="label">Backend</div>
          <div className="value">{health?.status ?? "checking..."}</div>
        </div>
        <div className="stat-card">
          <div className="label">Database</div>
          <div className="value">{health?.database ?? "checking..."}</div>
        </div>
        <div className="stat-card">
          <div className="label">Analytical Core</div>
          <div className="value">{health?.analytical_core ?? "checking..."}</div>
        </div>
        <div className="stat-card">
          <div className="label">WebSocket</div>
          <div className="value">{wsStatus}</div>
        </div>
      </div>

      <div className="panel">
        <div className="section-title">Live Sensor (Phase 6)</div>
        <p className="page-subtitle">
          Real, authorized lab telemetry captured inside an isolated network namespace, reconstructed into flows, and
          scored through the same analytical pipeline as everything else on this dashboard -- never a second model.
          See <code>docs/live_telemetry.md</code> for the full compatibility audit and limitations.
        </p>
        {!sensorHealth?.telemetry_enabled && (
          <div className="notice-banner" style={{ marginBottom: "0.75rem" }}>
            TELEMETRY_ENABLED=false in .env -- the sensor cannot be started until this is set to true.
          </div>
        )}
        {sensorHealth && (
          <div className="grid grid-stats" style={{ marginBottom: "0.75rem" }}>
            <div className="stat-card">
              <div className="label">Collector</div>
              <div className="value">{sensorHealth.collector_status}</div>
            </div>
            <div className="stat-card">
              <div className="label">Packets Received</div>
              <div className="value">{sensorHealth.packets_received}</div>
            </div>
            <div className="stat-card">
              <div className="label">Events Processed</div>
              <div className="value">{sensorHealth.events_processed}</div>
            </div>
            <div className="stat-card">
              <div className="label">Active Flows</div>
              <div className="value">{sensorHealth.active_flows}</div>
            </div>
            <div className="stat-card">
              <div className="label">LIVE_GRAPH Edges</div>
              <div className="value">{sensorHealth.live_graph_edges}</div>
            </div>
            <div className="stat-card">
              <div className="label">Errors / Rejected</div>
              <div className="value">
                {sensorHealth.processing_errors} / {sensorHealth.events_rejected}
              </div>
            </div>
          </div>
        )}
        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button className="primary" onClick={startSensor} disabled={sensorBusy || sensorHealth?.collector_status === "running"} style={{ width: "auto", padding: "0.5rem 1.2rem" }}>
            Start Live Sensor
          </button>
          <button className="secondary" onClick={stopSensor} disabled={sensorBusy || sensorHealth?.collector_status !== "running"} style={{ width: "auto", padding: "0.5rem 1.2rem" }}>
            Stop Live Sensor
          </button>
        </div>
        {sensorMessage && <div className="notice-banner" style={{ marginTop: "0.75rem" }}>{sensorMessage}</div>}
        {sensorHealth?.last_error && (
          <div className="notice-banner" style={{ marginTop: "0.75rem" }}>Last error: {sensorHealth.last_error}</div>
        )}
      </div>

      <div className="panel">
        <div className="section-title">Offline Dataset Demonstration</div>
        <p className="page-subtitle">
          Rebuilds the attack graph and re-ingests a fresh stratified sample of real, labeled CICIDS2017 flows through the
          actual analytical core. Takes roughly 2-3 minutes (full dataset scan). This is a demonstration mode, not live
          detection.
        </p>
        <button className="secondary" onClick={runIngestion} disabled={ingesting}>
          {ingesting ? "Running (this takes a couple minutes)..." : "Run Offline Dataset Demonstration"}
        </button>
        {ingestResult && <div className="notice-banner" style={{ marginTop: "0.75rem" }}>{ingestResult}</div>}
      </div>

      <div className="panel">
        <div className="section-title">Submit a Controlled Test Event</div>
        <p className="page-subtitle">
          Scores a synthetic event through the real analytical pipeline. Any feature not supplied is filled with the
          training-mean value and disclosed in the result -- never a fabricated score.
        </p>
        <form onSubmit={submitTestEvent} style={{ display: "flex", gap: "1rem", alignItems: "flex-end", flexWrap: "wrap" }}>
          <div>
            <label className="page-subtitle">Source IP</label>
            <input value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} style={{ marginBottom: 0, width: 160 }} />
          </div>
          <div>
            <label className="page-subtitle">Destination IP</label>
            <input value={destIp} onChange={(e) => setDestIp(e.target.value)} style={{ marginBottom: 0, width: 160 }} />
          </div>
          <button className="primary" type="submit" disabled={submitting} style={{ width: "auto", padding: "0.5rem 1.2rem" }}>
            {submitting ? "Scoring..." : "Submit Test Event"}
          </button>
        </form>
        {testResult && (
          <div className="notice-banner" style={{ marginTop: "0.75rem" }}>
            Event #{testResult.event_id}: anomaly score {testResult.anomaly_score.toFixed(4)}, risk score{" "}
            {testResult.risk_score.toFixed(2)} ({testResult.risk_level}). {testResult.imputed_features.length} of 67 model
            features were imputed from training means (none of the real 67 features were supplied in this quick test form).
          </div>
        )}
      </div>
    </>
  );
}
