import { useCallback, useEffect, useState } from "react";
import { StatusPill } from "../components/StatusPill";
import { api } from "../services/api";
import type { LiveDeviceIdentity } from "../types";

function agentId(device: LiveDeviceIdentity): string {
  return device.device_id.startsWith("victim:")
    ? device.device_id.slice("victim:".length)
    : device.device_id;
}

function hostname(device: LiveDeviceIdentity): string {
  const prefix = "Victim: ";
  const suffix = ` (${agentId(device)})`;
  if (!device.label.startsWith(prefix) || !device.label.endsWith(suffix)) {
    return "Hostname unavailable";
  }
  return device.label.slice(prefix.length, -suffix.length) || "Hostname unavailable";
}

function utcDateTime(value: string): string {
  return /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value) ? value : `${value}Z`;
}

function formatUtcTimestamp(value: string | null | undefined): string {
  if (!value) return "Unavailable";
  const date = new Date(utcDateTime(value));
  if (Number.isNaN(date.getTime())) return "Timestamp unavailable";
  return `${new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

function verificationLabel(status: LiveDeviceIdentity["ip_address_status"]): string {
  if (status === "verified") return "Verified";
  if (status === "unavailable") return "Unavailable";
  if (status === "ambiguous") return "Ambiguous";
  return "Unknown";
}

export function Victims() {
  const [devices, setDevices] = useState<LiveDeviceIdentity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getLiveNetworkDevices();
      setDevices(response.devices.filter((device) => device.role === "victim" && device.registered));
    } catch {
      setError("Could not load registered victim devices. Check the backend connection and retry.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const interval = setInterval(() => void load(), 5000);
    return () => clearInterval(interval);
  }, [load]);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Victim Devices</h1>
          <div className="page-subtitle">Registered Victim Agents and their latest authenticated heartbeat.</div>
        </div>
        <button className="secondary" onClick={() => void load()} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      <div className="notice-banner">
        Connectivity reflects the latest authenticated heartbeat. Lifecycle is a separate administrative setting.
        IP addresses are shown only when the backend reports a verified address.
      </div>

      {error && <div className="notice-banner" role="alert">{error}</div>}

      <section className="panel" aria-labelledby="victims-title">
        <h2 className="section-title" id="victims-title">Registered Victim Devices ({devices.length})</h2>
        {loading ? <div className="empty-state" role="status">Loading registered victim devices…</div> : error && devices.length === 0 ? (
          <div className="empty-state">Victim device records are unavailable until the backend responds.</div>
        ) : devices.length === 0 ? (
          <div className="empty-state">No registered Victim Agents are available.</div>
        ) : (
          <div className="reports-table-wrap" role="region" aria-label="Registered victim devices table" tabIndex={0}>
            <table>
              <thead>
                <tr>
                  <th>Device / Agent ID</th>
                  <th>Hostname</th>
                  <th>Verified IP address</th>
                  <th>IP observation (UTC) / source</th>
                  <th>IP verification</th>
                  <th>Connectivity</th>
                  <th>Lifecycle</th>
                  <th>Last seen (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => {
                  const seen = formatUtcTimestamp(device.last_seen);
                  const observedAt = formatUtcTimestamp(device.ip_address_observed_at);
                  const online = device.online === true;
                  const offline = device.online === false;
                  const active = device.status === "active";
                  const disabled = device.status === "disabled";
                  const verifiedIp = device.ip_address_status === "verified" ? device.ip_address : null;
                  return (
                    <tr key={device.device_id}>
                      <td className="mono">{agentId(device)}</td>
                      <td>{hostname(device)}</td>
                      <td className="mono">{verifiedIp ?? <span className="page-subtitle">IP unavailable</span>}</td>
                      <td>
                        {device.ip_address_observed_at
                          ? <time dateTime={utcDateTime(device.ip_address_observed_at)}>{observedAt}</time>
                          : observedAt}
                        <br />
                        <span className="page-subtitle">{device.ip_address_source ?? "Source unavailable"}</span>
                      </td>
                      <td>
                        {verificationLabel(device.ip_address_status)}
                        {device.ip_address_reason && <><br /><span className="page-subtitle">{device.ip_address_reason}</span></>}
                      </td>
                      <td>
                        <StatusPill
                          state={online ? "healthy" : "neutral"}
                          label={online ? "Online" : offline ? "Offline" : "Unknown"}
                        />
                      </td>
                      <td>
                        <StatusPill
                          state={disabled ? "warning" : "neutral"}
                          label={active ? "Active" : disabled ? "Disabled" : "Unknown"}
                        />
                      </td>
                      <td>
                        {device.last_seen
                          ? <time dateTime={utcDateTime(device.last_seen)}>{seen}</time>
                          : "Never reported"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
