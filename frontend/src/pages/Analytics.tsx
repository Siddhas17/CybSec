import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../services/api";
import type {
  AttacksByType,
  HistogramBucket,
  RiskDistributionBucket,
  TimelinePoint,
  TopNode,
} from "../types";

const CHART_COLOR = "#3b9eff";
const ATTACK_COLOR = "#d64550";

function ChartPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="panel">
      <div className="section-title">{title}</div>
      <div style={{ height: 260 }}>{children}</div>
    </div>
  );
}

export function Analytics() {
  const [attacksByType, setAttacksByType] = useState<AttacksByType[]>([]);
  const [riskDistribution, setRiskDistribution] = useState<RiskDistributionBucket[]>([]);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [topSources, setTopSources] = useState<TopNode[]>([]);
  const [topDestinations, setTopDestinations] = useState<TopNode[]>([]);
  const [anomalyDist, setAnomalyDist] = useState<HistogramBucket[]>([]);
  const [riskScoreDist, setRiskScoreDist] = useState<HistogramBucket[]>([]);

  useEffect(() => {
    api.analytics.attacksByType().then(setAttacksByType);
    api.analytics.riskDistribution().then(setRiskDistribution);
    api.analytics.timeline().then(setTimeline);
    api.analytics.topSources(10).then(setTopSources);
    api.analytics.topDestinations(10).then(setTopDestinations);
    api.analytics.anomalyScoreDistribution().then(setAnomalyDist);
    api.analytics.riskScoreDistribution().then(setRiskScoreDist);
  }, []);

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Analytics</h1>
          <div className="page-subtitle">Computed from persisted analytical results (never re-scans raw datasets per request).</div>
        </div>
      </div>

      <div className="grid grid-2">
        <ChartPanel title="Events Over Time">
          {timeline.length === 0 ? (
            <div className="empty-state">No data yet.</div>
          ) : (
            <ResponsiveContainer>
              <LineChart data={timeline}>
                <CartesianGrid stroke="#223044" />
                <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: "#8ea0b5" }} hide />
                <YAxis tick={{ fontSize: 10, fill: "#8ea0b5" }} />
                <Tooltip contentStyle={{ background: "#161f2c", border: "1px solid #223044" }} />
                <Line type="monotone" dataKey="event_count" stroke={CHART_COLOR} name="Events" dot={false} />
                <Line type="monotone" dataKey="attack_count" stroke={ATTACK_COLOR} name="Attacks" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </ChartPanel>

        <ChartPanel title="Attacks by Category">
          {attacksByType.length === 0 ? (
            <div className="empty-state">No attack events yet.</div>
          ) : (
            <ResponsiveContainer>
              <BarChart data={attacksByType} layout="vertical" margin={{ left: 40 }}>
                <CartesianGrid stroke="#223044" />
                <XAxis type="number" tick={{ fontSize: 10, fill: "#8ea0b5" }} />
                <YAxis type="category" dataKey="attack_type" tick={{ fontSize: 10, fill: "#8ea0b5" }} width={110} />
                <Tooltip contentStyle={{ background: "#161f2c", border: "1px solid #223044" }} />
                <Bar dataKey="count" fill={ATTACK_COLOR} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartPanel>

        <ChartPanel title="Anomaly Score Distribution">
          {anomalyDist.length === 0 ? (
            <div className="empty-state">No data yet.</div>
          ) : (
            <ResponsiveContainer>
              <BarChart data={anomalyDist.map((b) => ({ ...b, label: b.range_start.toFixed(2) }))}>
                <CartesianGrid stroke="#223044" />
                <XAxis dataKey="label" tick={{ fontSize: 9, fill: "#8ea0b5" }} />
                <YAxis tick={{ fontSize: 10, fill: "#8ea0b5" }} />
                <Tooltip contentStyle={{ background: "#161f2c", border: "1px solid #223044" }} />
                <Bar dataKey="count" fill={CHART_COLOR} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartPanel>

        <ChartPanel title="Risk Score Distribution">
          {riskScoreDist.length === 0 ? (
            <div className="empty-state">No data yet.</div>
          ) : (
            <ResponsiveContainer>
              <BarChart data={riskScoreDist.map((b) => ({ ...b, label: b.range_start.toFixed(1) }))}>
                <CartesianGrid stroke="#223044" />
                <XAxis dataKey="label" tick={{ fontSize: 9, fill: "#8ea0b5" }} />
                <YAxis tick={{ fontSize: 10, fill: "#8ea0b5" }} />
                <Tooltip contentStyle={{ background: "#161f2c", border: "1px solid #223044" }} />
                <Bar dataKey="count" fill={ATTACK_COLOR} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartPanel>

        <div className="panel">
          <div className="section-title">Top Source Nodes (by attack flow count)</div>
          {topSources.length === 0 ? (
            <div className="empty-state">No data yet.</div>
          ) : (
            <table>
              <thead>
                <tr><th>IP</th><th>Attack Flows</th><th>Total Flows</th></tr>
              </thead>
              <tbody>
                {topSources.map((n) => (
                  <tr key={n.ip}><td className="mono">{n.ip}</td><td>{n.attack_flow_count.toLocaleString()}</td><td>{n.total_flow_count.toLocaleString()}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="panel">
          <div className="section-title">Top Destination Nodes (by attack flow count)</div>
          {topDestinations.length === 0 ? (
            <div className="empty-state">No data yet.</div>
          ) : (
            <table>
              <thead>
                <tr><th>IP</th><th>Attack Flows</th><th>Total Flows</th></tr>
              </thead>
              <tbody>
                {topDestinations.map((n) => (
                  <tr key={n.ip}><td className="mono">{n.ip}</td><td>{n.attack_flow_count.toLocaleString()}</td><td>{n.total_flow_count.toLocaleString()}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {riskDistribution.length > 0 && (
        <div className="panel">
          <div className="section-title">Risk Level Distribution</div>
          <div style={{ display: "flex", gap: "1.5rem" }}>
            {riskDistribution.map((b) => (
              <div key={b.risk_level}>
                <div className="page-subtitle">{b.risk_level}</div>
                <div style={{ fontSize: "1.4rem", fontWeight: 600 }}>{b.count}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
