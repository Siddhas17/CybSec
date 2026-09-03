import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { DatasetStats } from "../types";

export function DatasetManagement() {
  const [stats, setStats] = useState<DatasetStats | null>(null);

  useEffect(() => {
    api.modelEval.datasetStats().then(setStats);
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Dataset Management</h1>
          <div className="page-subtitle">
            Real statistics from the last CICIDS2017 preprocessing run. Read-only -- upload and training are
            CLI-driven (<code>python -m ml.preprocessing.clean</code>, <code>python -m ml.training.train_autoencoder</code>,{" "}
            <code>python -m ml.training.train_knn</code>) in this deployment, admin-only.
          </div>
        </div>
      </div>

      {!stats ? (
        <div className="empty-state">Loading...</div>
      ) : !stats.available ? (
        <div className="empty-state">{stats.reason}</div>
      ) : (
        <>
          <div className="panel">
            <div className="section-title">Source Files</div>
            {stats.files_loaded && stats.files_loaded.length > 0 ? (
              <table>
                <tbody>
                  {stats.files_loaded.map((f) => (
                    <tr key={f}><td className="mono">{f}</td></tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">No file list recorded.</div>
            )}
          </div>

          <div className="grid grid-stats">
            <div className="stat-card"><div className="label">Rows Before Dedup</div><div className="value">{stats.rows_before_dedup?.toLocaleString() ?? "--"}</div></div>
            <div className="stat-card"><div className="label">Duplicate Rows</div><div className="value">{stats.exact_duplicate_rows?.toLocaleString() ?? "--"}</div></div>
            <div className="stat-card"><div className="label">Rows After Dedup</div><div className="value">{stats.rows_after_dedup?.toLocaleString() ?? "--"}</div></div>
            <div className="stat-card"><div className="label">Rows After Cleaning</div><div className="value">{stats.rows_after_inf_nan_handling?.toLocaleString() ?? "--"}</div></div>
          </div>

          {stats.split_sizes && (
            <div className="panel">
              <div className="section-title">Train / Validation / Test Split</div>
              <table>
                <thead><tr><th>Split</th><th>Rows</th><th>% of Cleaned Data</th></tr></thead>
                <tbody>
                  {Object.entries(stats.split_sizes).map(([split, count]) => {
                    const total = Object.values(stats.split_sizes ?? {}).reduce((a, b) => a + b, 0);
                    return (
                      <tr key={split}>
                        <td style={{ textTransform: "capitalize" }}>{split}</td>
                        <td>{count.toLocaleString()}</td>
                        <td>{total ? `${((count / total) * 100).toFixed(1)}%` : "--"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {stats.label_distribution_after && (
            <div className="panel">
              <div className="section-title">Class Distribution (After Cleaning)</div>
              <table>
                <thead><tr><th>Label</th><th>Count</th><th>Before Cleaning</th></tr></thead>
                <tbody>
                  {Object.entries(stats.label_distribution_after)
                    .sort((a, b) => b[1] - a[1])
                    .map(([label, count]) => (
                      <tr key={label}>
                        <td>{label}</td>
                        <td>{count.toLocaleString()}</td>
                        <td>{stats.label_distribution_before?.[label]?.toLocaleString() ?? "--"}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </>
  );
}
