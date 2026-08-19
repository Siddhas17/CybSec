import { useEffect, useState, type FormEvent } from "react";
import { api } from "../services/api";
import { RiskBadge } from "../components/RiskBadge";
import { useWebSocket } from "../hooks/useWebSocket";
import type { PreventionAction } from "../types";

// Section 12: precise terminology -- DETECTED (risk_score alone, shown
// elsewhere on Live Threats) is never conflated with WOULD BLOCK (a
// dry-run response decision) or BLOCKED (a real one). This label map is
// the dashboard's one place that turns actual_action into the exact
// phrase an operator should read.
const ACTUAL_ACTION_LABEL: Record<PreventionAction["actual_action"], string> = {
  alerted: "ALERTED",
  would_block: "WOULD BLOCK",
  blocked: "BLOCKED",
  unblocked: "UNBLOCKED",
  rejected: "REJECTED",
  failed: "FAILED",
};

function ActionBadge({ action }: { action: PreventionAction }) {
  const color = action.success
    ? action.actual_action === "blocked" || action.actual_action === "would_block"
      ? "#b45309"
      : "#15803d"
    : "#b91c1c";
  return (
    <span className="badge outline" style={{ borderColor: color, color }}>
      {ACTUAL_ACTION_LABEL[action.actual_action] ?? action.actual_action}
    </span>
  );
}

export function Prevention() {
  const [actions, setActions] = useState<PreventionAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState<"dry-run" | "block" | "unblock" | null>(null);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const { messages } = useWebSocket();

  function reload() {
    setLoading(true);
    setError(null);
    api
      .prevention.listActions({ limit: 100 })
      .then(setActions)
      .catch(() => setError("Could not load prevention actions -- check that the backend is running."))
      .finally(() => setLoading(false));
  }

  useEffect(reload, []);

  // Live-updates without a page refresh (section 14's demonstration
  // requirement): a new prevention_action WebSocket frame prepends
  // directly rather than triggering a full reload, matching how new_threat
  // events are handled elsewhere but without the extra round-trip.
  useEffect(() => {
    const latest = messages[0];
    if (latest?.type === "prevention_action") {
      const action = latest.data as PreventionAction;
      setActions((prev) => [action, ...prev.filter((a) => a.id !== action.id)].slice(0, 100));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messages]);

  const currentlyBlocked = new Set(
    actions
      .slice()
      .reverse()
      .reduce((acc, a) => {
        if (a.actual_action === "blocked") acc.add(a.source_ip);
        if (a.actual_action === "unblocked") acc.delete(a.source_ip);
        return acc;
      }, new Set<string>()),
  );

  async function submit(kind: "dry-run" | "block" | "unblock", e?: FormEvent) {
    e?.preventDefault();
    if (!ip.trim()) return;
    setSubmitting(kind);
    setFormMessage(null);
    try {
      const call = kind === "dry-run" ? api.prevention.dryRun : kind === "block" ? api.prevention.block : api.prevention.unblock;
      const result = kind === "unblock" ? await api.prevention.unblock(ip.trim()) : await call(ip.trim(), reason || undefined);
      setFormMessage(`${ACTUAL_ACTION_LABEL[result.actual_action]}: ${result.reason}`);
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setFormMessage(detail ?? `Request failed -- check backend logs.`);
    } finally {
      setSubmitting(null);
      reload();
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Prevention &amp; Response</h1>
          <div className="page-subtitle">
            Controlled lab response only -- DETECTED (risk score alone) is distinct from WOULD BLOCK (dry-run) and BLOCKED
            (real). See <code>docs/prevention.md</code> for the response architecture, thresholds, and safety defaults.
          </div>
        </div>
      </div>

      {error && <div className="notice-banner">{error}</div>}

      <div className="panel">
        <div className="section-title">Manual Response Action</div>
        <p className="page-subtitle">
          Every action here is validated against the configured lab scope before anything is attempted -- an IP outside
          it is always rejected and audited, never silently acted on.
        </p>
        <form onSubmit={(e) => submit("dry-run", e)} style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", alignItems: "flex-end" }}>
          <div>
            <label htmlFor="prevention-ip">Source IP</label>
            <input id="prevention-ip" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="192.168.56.10" />
          </div>
          <div>
            <label htmlFor="prevention-reason">Reason (optional)</label>
            <input id="prevention-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="manual review" />
          </div>
          <button className="primary" type="submit" disabled={submitting !== null} style={{ width: "auto", padding: "0.5rem 1.2rem" }}>
            Dry-Run
          </button>
          <button
            className="secondary"
            type="button"
            disabled={submitting !== null}
            onClick={() => submit("block")}
            style={{ width: "auto", padding: "0.5rem 1.2rem" }}
          >
            Block
          </button>
          <button
            className="secondary"
            type="button"
            disabled={submitting !== null}
            onClick={() => submit("unblock")}
            style={{ width: "auto", padding: "0.5rem 1.2rem" }}
          >
            Unblock
          </button>
        </form>
        {formMessage && <div className="notice-banner" style={{ marginTop: "0.75rem" }}>{formMessage}</div>}
      </div>

      <div className="panel">
        <div className="section-title">Currently Blocked Sources ({currentlyBlocked.size})</div>
        {currentlyBlocked.size === 0 ? (
          <div className="empty-state">None -- no source is currently in a real blocked state.</div>
        ) : (
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            {[...currentlyBlocked].map((sourceIp) => (
              <span key={sourceIp} className="badge outline mono">
                {sourceIp}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="panel">
        <div className="section-title">Response Action Log</div>
        {loading ? (
          <div className="empty-state">Loading...</div>
        ) : actions.length === 0 ? (
          <div className="empty-state">No response actions recorded yet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>Requested</th>
                <th>Status</th>
                <th>Dry-Run</th>
                <th>Success</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((a) => (
                <tr key={a.id}>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td className="mono">{a.source_ip}</td>
                  <td>{a.risk_score !== null ? a.risk_score.toFixed(2) : "-"}</td>
                  <td>
                    <RiskBadge level={a.risk_level} />
                  </td>
                  <td>{a.requested_action}</td>
                  <td>
                    <ActionBadge action={a} />
                  </td>
                  <td>{a.dry_run ? "yes" : "no"}</td>
                  <td>{a.success ? "yes" : "no"}</td>
                  <td>{a.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
