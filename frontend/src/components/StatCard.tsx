export function StatCard({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="stat-card">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="page-subtitle" style={{ marginTop: 4 }}>{hint}</div>}
    </div>
  );
}
