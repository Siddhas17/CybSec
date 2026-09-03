import { useEffect, useState } from "react";
import { api } from "../services/api";
import { downloadBlob, openBlobInNewTab } from "../services/downloadFile";
import type { SecurityReport } from "../types";

const CSV_EXPORTS: { kind: Parameters<typeof api.reports.exportCsvUrl>[0]; label: string }[] = [
  { kind: "events", label: "Security Events" },
  { kind: "alerts", label: "Alerts" },
  { kind: "anomalies", label: "Anomalies" },
  { kind: "risk-assessments", label: "Risk Assessments" },
  { kind: "prevention-actions", label: "Prevention Actions" },
  { kind: "model-metrics", label: "Model Evaluation Metrics" },
];

function StatusBadge({ status }: { status: SecurityReport["generation_status"] }) {
  return <span className={`badge ${status === "complete" ? "very-low" : "critical"}`}>{status}</span>;
}

export function Reports() {
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [generating, setGenerating] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  function load() {
    api.reports.list().then(setReports);
  }

  useEffect(load, []);

  async function handleGenerate() {
    setGenerating(true);
    try {
      await api.reports.generate();
      load();
    } finally {
      setGenerating(false);
    }
  }

  async function handleDownloadPdf(report: SecurityReport) {
    setBusyAction(`download-${report.id}`);
    try {
      await downloadBlob(api.reports.pdfUrl(report.id, "attachment"), `security_report_${report.id}.pdf`);
    } finally {
      setBusyAction(null);
    }
  }

  async function handleViewPdf(report: SecurityReport) {
    setBusyAction(`view-${report.id}`);
    try {
      await openBlobInNewTab(api.reports.pdfUrl(report.id, "inline"));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleExportCsv(kind: Parameters<typeof api.reports.exportCsvUrl>[0]) {
    setBusyAction(`csv-${kind}`);
    try {
      await downloadBlob(api.reports.exportCsvUrl(kind), `${kind}.csv`);
    } finally {
      setBusyAction(null);
    }
  }

  const summary = reports[0]?.summary_stats as Record<string, number> | undefined;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Reports</h1>
          <div className="page-subtitle">Generate and download PDF security reports built from real, currently-computed data.</div>
        </div>
        <button className="primary" style={{ width: "auto" }} onClick={handleGenerate} disabled={generating}>
          {generating ? "Generating..." : "Generate Report"}
        </button>
      </div>

      {summary && (
        <div className="grid grid-stats">
          <div className="stat-card"><div className="label">Total Events</div><div className="value">{summary.total_events?.toLocaleString() ?? "--"}</div></div>
          <div className="stat-card"><div className="label">Anomalies</div><div className="value">{summary.anomaly_count?.toLocaleString() ?? "--"}</div></div>
          <div className="stat-card"><div className="label">High-Risk Events</div><div className="value">{summary.high_risk_events?.toLocaleString() ?? "--"}</div></div>
          <div className="stat-card"><div className="label">Benign Events</div><div className="value">{summary.benign_count?.toLocaleString() ?? "--"}</div></div>
        </div>
      )}

      <div className="panel">
        <div className="section-title">Report History</div>
        {reports.length === 0 ? (
          <div className="empty-state">No reports generated yet -- click "Generate Report" above.</div>
        ) : (
          <table>
            <thead>
              <tr><th>Title</th><th>Status</th><th>Size</th><th>Created</th><th></th></tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td>{r.title}</td>
                  <td><StatusBadge status={r.generation_status} /></td>
                  <td>{r.file_size_bytes ? `${(r.file_size_bytes / 1024).toFixed(0)} KB` : "--"}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    {r.generation_status === "complete" ? (
                      <>
                        <button className="secondary" onClick={() => handleViewPdf(r)} disabled={busyAction === `view-${r.id}`} style={{ marginRight: 6 }}>
                          View Report
                        </button>
                        <button className="secondary" onClick={() => handleDownloadPdf(r)} disabled={busyAction === `download-${r.id}`}>
                          Download PDF
                        </button>
                      </>
                    ) : (
                      <span className="page-subtitle" title={r.error_message ?? undefined}>{r.error_message ?? "Generation failed"}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="section-title">CSV Exports</div>
        <div className="page-subtitle" style={{ marginBottom: "0.75rem" }}>
          Exported directly from the current MySQL data at the time of download.
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.6rem" }}>
          {CSV_EXPORTS.map((c) => (
            <button
              key={c.kind}
              className="secondary"
              onClick={() => handleExportCsv(c.kind)}
              disabled={busyAction === `csv-${c.kind}`}
            >
              Download CSV -- {c.label}
            </button>
          ))}
        </div>
      </div>
    </>
  );
}
