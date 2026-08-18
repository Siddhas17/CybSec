import type { RiskLevel } from "../types";

const CLASS_BY_LEVEL: Record<RiskLevel, string> = {
  "Very Low": "very-low",
  Low: "low",
  Moderate: "moderate",
  High: "high",
  Critical: "critical",
};

export function RiskBadge({ level }: { level: RiskLevel | null | undefined }) {
  if (!level) return <span className="badge outline">Unscored</span>;
  return <span className={`badge ${CLASS_BY_LEVEL[level]}`}>{level}</span>;
}
