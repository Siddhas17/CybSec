import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { ConfusionMatrixHeatmap } from "../components/ConfusionMatrixHeatmap";
import type {
  AutoencoderMetrics,
  DatasetStats,
  KnnMetrics,
  LiveVsOfflineStats,
  ModelComparison,
  ModelStatus,
  TrainingRun,
} from "../types";

const CHART_COLOR = "#3b9eff";
const ATTACK_COLOR = "#d64550";

function pct(value: number | undefined | null): string {
  return value == null ? "--" : `${(value * 100).toFixed(2)}%`;
}

function num(value: number | undefined | null, digits = 4): string {
  return value == null ? "--" : value.toFixed(digits);
}

function ChartPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="panel">
      <div className="section-title">{title}</div>
      <div style={{ height: 260 }}>{children}</div>
    </div>
  );
}

function StatusBadge({ valid }: { valid: boolean }) {
  return <span className={`badge ${valid ? "very-low" : "critical"}`}>{valid ? "ACTIVE" : "NOT ACTIVE"}</span>;
}

export function ModelEvaluation() {
  const [status, setStatus] = useState<ModelStatus | null>(null);
  const [autoencoder, setAutoencoder] = useState<AutoencoderMetrics | null>(null);
  const [knn, setKnn] = useState<KnnMetrics | null>(null);
  const [comparison, setComparison] = useState<ModelComparison | null>(null);
  const [liveVsOffline, setLiveVsOffline] = useState<LiveVsOfflineStats | null>(null);
  const [datasetStats, setDatasetStats] = useState<DatasetStats | null>(null);
  const [history, setHistory] = useState<TrainingRun[]>([]);
  const [syncing, setSyncing] = useState(false);

  function load() {
    api.modelEval.status().then(setStatus);
    api.modelEval.autoencoderMetrics().then(setAutoencoder);
    api.modelEval.knnMetrics().then(setKnn);
    api.modelEval.comparison().then(setComparison);
    api.modelEval.liveVsOffline().then(setLiveVsOffline);
    api.modelEval.datasetStats().then(setDatasetStats);
    api.modelEval.trainingHistory().then(setHistory);
  }

  useEffect(load, []);

  async function handleSync() {
    setSyncing(true);
    try {
      await api.modelEval.syncTrainingHistory();
      load();
    } finally {
      setSyncing(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Model Evaluation</h1>
          <div className="page-subtitle">
            Real metrics computed from held-out test-set predictions -- never hardcoded. Admin-only.
          </div>
        </div>
        <button className="secondary" onClick={handleSync} disabled={syncing}>
          {syncing ? "Syncing..." : "Sync Training History"}
        </button>
      </div>

      {status && (
        <div className="grid grid-2">
          <div className="panel">
            <div className="section-title">Autoencoder Status</div>
            <StatusBadge valid={status.autoencoder.valid} />
            <table style={{ marginTop: "0.75rem" }}>
              <tbody>
                {status.autoencoder.checks.map((c) => (
                  <tr key={c.name}>
                    <td>{c.name.replace(/_/g, " ")}</td>
                    <td>{c.passed ? "OK" : "FAIL"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel">
            <div className="section-title">KNN Status</div>
            <StatusBadge valid={status.knn.valid} />
            <table style={{ marginTop: "0.75rem" }}>
              <tbody>
                {status.knn.checks.map((c) => (
                  <tr key={c.name}>
                    <td>{c.name.replace(/_/g, " ")}</td>
                    <td>{c.passed ? "OK" : "FAIL"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="section-title">Autoencoder -- Anomaly Detection Evaluation (Held-Out Test Set)</div>
        {!autoencoder ? (
          <div className="empty-state">Loading...</div>
        ) : !autoencoder.available ? (
          <div className="empty-state">{autoencoder.reason}</div>
        ) : (
          <>
            <div className="notice-banner">
              This is anomaly-detection evaluation, not classification accuracy: the model is trained only on BENIGN
              traffic and flags deviation from it. {autoencoder.positive_class_definition}
            </div>
            <div className="grid grid-stats">
              <div className="stat-card"><div className="label">Precision</div><div className="value">{pct(autoencoder.precision)}</div></div>
              <div className="stat-card"><div className="label">Recall</div><div className="value">{pct(autoencoder.recall)}</div></div>
              <div className="stat-card"><div className="label">F1</div><div className="value">{pct(autoencoder.f1)}</div></div>
              <div className="stat-card"><div className="label">ROC-AUC</div><div className="value">{num(autoencoder.roc_auc)}</div></div>
              <div className="stat-card"><div className="label">PR-AUC</div><div className="value">{num(autoencoder.pr_auc)}</div></div>
              <div className="stat-card"><div className="label">Anomaly Threshold</div><div className="value">{num(autoencoder.threshold, 6)}</div></div>
            </div>
            <div className="grid grid-2" style={{ marginTop: "1rem" }}>
              <div>
                <ConfusionMatrixHeatmap matrix={autoencoder.confusion_matrix ?? { tp: null, tn: null, fp: null, fn: null }} />
              </div>
              <table>
                <tbody>
                  <tr><td>Mean reconstruction error (BENIGN)</td><td>{num(autoencoder.mean_reconstruction_error_benign, 6)}</td></tr>
                  <tr><td>Median reconstruction error (BENIGN)</td><td>{num(autoencoder.median_reconstruction_error_benign, 6)}</td></tr>
                  <tr><td>Mean reconstruction error (ATTACK)</td><td>{num(autoencoder.mean_reconstruction_error_attack, 6)}</td></tr>
                  <tr><td>Median reconstruction error (ATTACK)</td><td>{num(autoencoder.median_reconstruction_error_attack, 6)}</td></tr>
                  <tr><td>Normal (BENIGN) samples</td><td>{autoencoder.normal_samples?.toLocaleString() ?? "--"}</td></tr>
                  <tr><td>Anomalous (ATTACK) samples</td><td>{autoencoder.anomalous_samples?.toLocaleString() ?? "--"}</td></tr>
                  <tr><td>Threshold strategy</td><td>{autoencoder.threshold_strategy ?? "--"}</td></tr>
                  <tr><td>Trained at</td><td>{autoencoder.trained_at ?? "unrecorded (trained before this field was added)"}</td></tr>
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      <div className="panel">
        <div className="section-title">KNN -- Supervised Classification Evaluation (Held-Out Test Set)</div>
        {!knn ? (
          <div className="empty-state">Loading...</div>
        ) : !knn.available ? (
          <div className="empty-state">{knn.reason}</div>
        ) : (
          <>
            <div className="notice-banner">
              Primary averaging method: <strong>{knn.primary_averaging_method}</strong>. {knn.note_on_averaging}
            </div>
            <div className="grid grid-stats">
              <div className="stat-card"><div className="label">Accuracy</div><div className="value">{pct(knn.accuracy)}</div></div>
              <div className="stat-card"><div className="label">Precision (weighted)</div><div className="value">{pct(knn.precision_weighted)}</div></div>
              <div className="stat-card"><div className="label">Recall (weighted)</div><div className="value">{pct(knn.recall_weighted)}</div></div>
              <div className="stat-card"><div className="label">F1 (weighted)</div><div className="value">{pct(knn.f1_weighted)}</div></div>
              <div className="stat-card"><div className="label">Precision (macro)</div><div className="value">{pct(knn.precision_macro)}</div></div>
              <div className="stat-card"><div className="label">Recall (macro)</div><div className="value">{pct(knn.recall_macro)}</div></div>
              <div className="stat-card"><div className="label">F1 (macro)</div><div className="value">{pct(knn.f1_macro)}</div></div>
              <div className="stat-card"><div className="label">ROC-AUC</div><div className="value">{num(knn.roc_auc)}</div></div>
              <div className="stat-card"><div className="label">K</div><div className="value">{knn.k ?? "--"}</div></div>
              <div className="stat-card"><div className="label">Feature count</div><div className="value">{knn.feature_count ?? "--"}</div></div>
              <div className="stat-card"><div className="label">Training time</div><div className="value">{num(knn.training_time_seconds, 2)}s</div></div>
              <div className="stat-card"><div className="label">Inference time</div><div className="value">{num(knn.inference_time_seconds, 2)}s</div></div>
            </div>
            <div className="grid grid-2" style={{ marginTop: "1rem" }}>
              <div>
                <ConfusionMatrixHeatmap matrix={knn.confusion_matrix ?? { tp: null, tn: null, fp: null, fn: null }} />
              </div>
              {knn.test_class_distribution && (
                <div>
                  <div className="section-title" style={{ fontSize: "0.85rem" }}>Test Set Class Distribution</div>
                  <table>
                    <tbody>
                      <tr><td>BENIGN</td><td>{knn.test_class_distribution.benign_count.toLocaleString()} ({knn.test_class_distribution.benign_pct.toFixed(2)}%)</td></tr>
                      <tr><td>ATTACK</td><td>{knn.test_class_distribution.attack_count.toLocaleString()} ({knn.test_class_distribution.attack_pct.toFixed(2)}%)</td></tr>
                    </tbody>
                  </table>
                  <div className="notice-banner" style={{ marginTop: "0.75rem" }}>
                    This dataset is highly imbalanced toward BENIGN traffic -- accuracy alone can be misleading here.
                    Precision, recall, and F1 (above) are the more reliable indicators of attack-detection performance.
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {comparison && comparison.autoencoder.available && comparison.knn.available && (
        <div className="panel">
          <div className="section-title">Model Comparison</div>
          <div className="notice-banner">{comparison.comparability_note}</div>
          <div className="grid grid-2">
            <table>
              <thead>
                <tr><th></th><th>Autoencoder</th><th>KNN</th></tr>
              </thead>
              <tbody>
                <tr><td>Precision</td><td>{pct(comparison.autoencoder.precision)}</td><td>{pct(comparison.knn.precision_weighted)}</td></tr>
                <tr><td>Recall</td><td>{pct(comparison.autoencoder.recall)}</td><td>{pct(comparison.knn.recall_weighted)}</td></tr>
                <tr><td>F1</td><td>{pct(comparison.autoencoder.f1)}</td><td>{pct(comparison.knn.f1_weighted)}</td></tr>
                <tr><td>ROC-AUC</td><td>{num(comparison.autoencoder.roc_auc)}</td><td>{num(comparison.knn.roc_auc)}</td></tr>
                <tr><td>Inference time</td><td>--</td><td>{num(comparison.knn.inference_time_seconds, 2)}s</td></tr>
              </tbody>
            </table>
            <div style={{ height: 220 }}>
              <ResponsiveContainer>
                <BarChart
                  data={[
                    { metric: "Precision", Autoencoder: (comparison.autoencoder.precision ?? 0) * 100, KNN: (comparison.knn.precision_weighted ?? 0) * 100 },
                    { metric: "Recall", Autoencoder: (comparison.autoencoder.recall ?? 0) * 100, KNN: (comparison.knn.recall_weighted ?? 0) * 100 },
                    { metric: "F1", Autoencoder: (comparison.autoencoder.f1 ?? 0) * 100, KNN: (comparison.knn.f1_weighted ?? 0) * 100 },
                  ]}
                >
                  <CartesianGrid stroke="#223044" />
                  <XAxis dataKey="metric" tick={{ fontSize: 10, fill: "#8ea0b5" }} />
                  <YAxis tick={{ fontSize: 10, fill: "#8ea0b5" }} unit="%" />
                  <Tooltip contentStyle={{ background: "#161f2c", border: "1px solid #223044" }} />
                  <Bar dataKey="Autoencoder" fill={CHART_COLOR} />
                  <Bar dataKey="KNN" fill={ATTACK_COLOR} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {liveVsOffline && (
        <div className="grid grid-2">
          <div className="panel">
            <div className="section-title">{liveVsOffline.offline.label}</div>
            <div className="page-subtitle">Same figures as the autoencoder/KNN panels above, shown here for direct comparison against live stats.</div>
          </div>
          <div className="panel">
            <div className="section-title">{liveVsOffline.live.label}</div>
            <div className="grid grid-stats">
              <div className="stat-card"><div className="label">Total Live Events</div><div className="value">{liveVsOffline.live.total_live_events.toLocaleString()}</div></div>
              <div className="stat-card"><div className="label">Detected Anomalies</div><div className="value">{liveVsOffline.live.detected_anomalies.toLocaleString()}</div></div>
              <div className="stat-card"><div className="label">Alerts</div><div className="value">{liveVsOffline.live.alerts.toLocaleString()}</div></div>
              <div className="stat-card"><div className="label">Prevented / Would-Block</div><div className="value">{liveVsOffline.live.threats_prevented_or_would_block.toLocaleString()}</div></div>
              <div className="stat-card"><div className="label">Avg Risk Score</div><div className="value">{num(liveVsOffline.live.average_risk_score, 2)}</div></div>
            </div>
            <div className="notice-banner" style={{ marginTop: "0.75rem" }}>{liveVsOffline.live.live_accuracy_note}</div>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="section-title">Dataset Statistics</div>
        {!datasetStats ? (
          <div className="empty-state">Loading...</div>
        ) : !datasetStats.available ? (
          <div className="empty-state">{datasetStats.reason}</div>
        ) : (
          <>
            <div className="grid grid-stats">
              <div className="stat-card"><div className="label">Rows Before Dedup</div><div className="value">{datasetStats.rows_before_dedup?.toLocaleString()}</div></div>
              <div className="stat-card"><div className="label">Duplicate Rows Removed</div><div className="value">{datasetStats.exact_duplicate_rows?.toLocaleString()}</div></div>
              <div className="stat-card"><div className="label">Rows After Cleaning</div><div className="value">{datasetStats.rows_after_inf_nan_handling?.toLocaleString()}</div></div>
              {datasetStats.split_sizes && Object.entries(datasetStats.split_sizes).map(([split, count]) => (
                <div className="stat-card" key={split}><div className="label">{split} rows</div><div className="value">{count.toLocaleString()}</div></div>
              ))}
            </div>
            {datasetStats.label_distribution_after && (
              <table style={{ marginTop: "1rem" }}>
                <thead><tr><th>Label</th><th>Count (after cleaning)</th></tr></thead>
                <tbody>
                  {Object.entries(datasetStats.label_distribution_after).map(([label, count]) => (
                    <tr key={label}><td>{label}</td><td>{count.toLocaleString()}</td></tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>

      <div className="panel">
        <div className="section-title">Training History</div>
        {history.length === 0 ? (
          <div className="empty-state">No synced training runs yet -- click "Sync Training History" above after training a model.</div>
        ) : (
          <>
            {(["autoencoder", "knn"] as const).map((component) => {
              const runs = history
                .filter((r) => r.component === component)
                .slice()
                .reverse()
                .map((r, i) => ({
                  index: i + 1,
                  f1: ((component === "autoencoder" ? r.metrics.f1 : r.metrics.f1_weighted) as number | undefined ?? 0) * 100,
                }));
              if (runs.length < 2) return null;
              return (
                <ChartPanel key={component} title={`${component === "autoencoder" ? "Autoencoder" : "KNN"} F1 Trend Across Synced Runs`}>
                  <ResponsiveContainer>
                    <LineChart data={runs}>
                      <CartesianGrid stroke="#223044" />
                      <XAxis dataKey="index" tick={{ fontSize: 10, fill: "#8ea0b5" }} label={{ value: "Run #", position: "insideBottom", fontSize: 10 }} />
                      <YAxis tick={{ fontSize: 10, fill: "#8ea0b5" }} unit="%" />
                      <Tooltip contentStyle={{ background: "#161f2c", border: "1px solid #223044" }} />
                      <Line type="monotone" dataKey="f1" stroke={CHART_COLOR} name="F1" />
                    </LineChart>
                  </ResponsiveContainer>
                </ChartPanel>
              );
            })}
          </>
        )}
        {history.length > 0 && (
          <table>
            <thead>
              <tr><th>Component</th><th>Run ID</th><th>Trained At</th><th>Feature Count</th><th>Key Metric</th><th>Synced</th></tr>
            </thead>
            <tbody>
              {history.map((run) => (
                <tr key={run.id}>
                  <td>{run.component}</td>
                  <td className="mono">{run.run_id.slice(0, 12)}</td>
                  <td>{run.trained_at ?? "unrecorded"}</td>
                  <td>{run.feature_count ?? "--"}</td>
                  <td>{run.component === "autoencoder" ? pct(run.metrics.f1 as number) : pct(run.metrics.f1_weighted as number)} F1</td>
                  <td>{new Date(run.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
