import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { ModelInfo as ModelInfoType } from "../types";

export function ModelInfo() {
  const [info, setInfo] = useState<ModelInfoType | null>(null);

  useEffect(() => {
    api.analytics.modelInfo().then(setInfo);
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Model Information</h1>
          <div className="page-subtitle">Which analytical artifacts produced the results shown throughout this dashboard.</div>
        </div>
      </div>

      {!info ? (
        <div className="empty-state">Loading...</div>
      ) : (
        <div className="grid grid-2">
          <div className="panel">
            <div className="section-title">Preprocessing</div>
            <div className="mono">{info.preprocessing_version}</div>
            <div className="page-subtitle">67-feature CICIDS2017 contract (Phase 1)</div>
          </div>
          <div className="panel">
            <div className="section-title">Autoencoder</div>
            <div className="mono">{info.autoencoder_version}</div>
            <div className="page-subtitle">Anomaly threshold: {info.autoencoder_threshold.toFixed(6)}</div>
          </div>
          <div className="panel">
            <div className="section-title">Attack Graph</div>
            <div className="mono">{info.attack_graph_version}</div>
            <div className="page-subtitle">Communication topology from CICIDS2017 (Phase 2)</div>
          </div>
          <div className="panel">
            <div className="section-title">Risk Engine</div>
            <div className="mono">{info.risk_engine_version}</div>
            <table style={{ marginTop: "0.75rem" }}>
              <thead>
                <tr><th>Weight</th><th>Value</th></tr>
              </thead>
              <tbody>
                {Object.entries(info.risk_engine_weights).map(([k, v]) => (
                  <tr key={k}><td>{k.replace(/_/g, " ")}</td><td>{v}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="notice-banner" style={{ marginTop: "1rem" }}>
        The risk score is a project-specific prioritization score, not a standardized measure of compromise probability or
        universal cybersecurity severity. See docs/risk_engine.md for the full methodology, weight rationale, and evaluation
        results, including the documented caveat that graph-context evaluation results are retrospective/forensic evidence,
        not proof of generalization to novel network relationships.
      </div>
    </>
  );
}
