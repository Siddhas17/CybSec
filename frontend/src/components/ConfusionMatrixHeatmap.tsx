import type { CSSProperties } from "react";
import type { ConfusionMatrix } from "../types";

interface Props {
  matrix: ConfusionMatrix;
  positiveLabel?: string;
  negativeLabel?: string;
}

function cellStyle(value: number, max: number, isDiagonal: boolean): CSSProperties {
  const intensity = max > 0 ? value / max : 0;
  const color = isDiagonal ? "var(--risk-very-low)" : "var(--risk-critical)";
  return {
    background: `color-mix(in srgb, ${color} ${Math.round(intensity * 70)}%, var(--bg-panel))`,
    textAlign: "center",
    verticalAlign: "middle",
    fontSize: "1.1rem",
    fontWeight: 600,
    padding: "1rem",
  };
}

export function ConfusionMatrixHeatmap({ matrix, positiveLabel = "ATTACK", negativeLabel = "BENIGN" }: Props) {
  const { tp, tn, fp, fn } = matrix;
  if (tp == null || tn == null || fp == null || fn == null) {
    return <div className="empty-state">Confusion matrix not available.</div>;
  }
  const max = Math.max(tp, tn, fp, fn);

  return (
    <table style={{ tableLayout: "fixed" }}>
      <thead>
        <tr>
          <th></th>
          <th style={{ textAlign: "center" }}>Actual {negativeLabel}</th>
          <th style={{ textAlign: "center" }}>Actual {positiveLabel}</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <th>Predicted {negativeLabel}</th>
          <td style={cellStyle(tn, max, true)}>
            {tn.toLocaleString()}
            <div className="page-subtitle">TN</div>
          </td>
          <td style={cellStyle(fn, max, false)}>
            {fn.toLocaleString()}
            <div className="page-subtitle">FN</div>
          </td>
        </tr>
        <tr>
          <th>Predicted {positiveLabel}</th>
          <td style={cellStyle(fp, max, false)}>
            {fp.toLocaleString()}
            <div className="page-subtitle">FP</div>
          </td>
          <td style={cellStyle(tp, max, true)}>
            {tp.toLocaleString()}
            <div className="page-subtitle">TP</div>
          </td>
        </tr>
      </tbody>
    </table>
  );
}
