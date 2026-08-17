"""Generic, dataset-agnostic CSV inspector.

Scans every CSV under a raw-data directory and reports structural facts
(rows, columns, dtypes, missing/duplicate/infinite values, constant columns,
a heuristically-detected label column and its class distribution) without
assuming anything about column names in advance. Intended to be run once
real dataset files are present, and reused programmatically by the actual
preprocessing pipeline so cleaning decisions are based on what's observed
here rather than assumptions.

CLI usage:
    python -m ml.preprocessing.inspect_dataset

Produces:
    docs/dataset_inspection.md         human-readable report
    ml/datasets/raw/_inspection.json   machine-readable report (gitignored,
                                        lives under raw/ since it's derived
                                        from raw files, not committed)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from ml.preprocessing.config import DOCS_DIR, RAW_DATA_DIR

LABEL_COLUMN_HINTS = ("label", "class", "attack")


@dataclass
class ColumnReport:
    name: str
    dtype: str
    has_stray_whitespace: bool
    missing_count: int
    missing_pct: float
    infinite_count: int
    is_constant: bool
    unique_count: int


@dataclass
class CsvReport:
    filename: str
    size_bytes: int
    num_rows: int
    num_columns: int
    duplicate_rows: int
    columns: list[ColumnReport] = field(default_factory=list)
    label_column: str | None = None
    label_distribution: dict[str, int] = field(default_factory=dict)
    non_numeric_columns: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    load_error: str | None = None


def _find_label_column(columns: list[str]) -> str | None:
    """Heuristic: prefer an exact 'Label' match, else any column whose
    (stripped, lowercased) name contains a label-like hint word."""
    stripped = {c: c.strip().lower() for c in columns}
    for original, norm in stripped.items():
        if norm == "label":
            return original
    for original, norm in stripped.items():
        if any(hint in norm for hint in LABEL_COLUMN_HINTS):
            return original
    return None


def _read_csv_robust(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path, low_memory=False, encoding="utf-8")
    except UnicodeDecodeError:
        return pd.read_csv(path, low_memory=False, encoding="latin1")


def inspect_csv(path: Path, raw_dir: Path) -> CsvReport:
    rel_name = str(path.relative_to(raw_dir))
    size_bytes = path.stat().st_size

    try:
        df = _read_csv_robust(path)
    except Exception as exc:  # genuinely unknown failure mode until we see real files
        return CsvReport(
            filename=rel_name,
            size_bytes=size_bytes,
            num_rows=0,
            num_columns=0,
            duplicate_rows=0,
            load_error=f"{type(exc).__name__}: {exc}",
        )

    num_rows, num_columns = df.shape
    duplicate_rows = int(df.duplicated().sum())

    columns: list[ColumnReport] = []
    non_numeric_columns: list[str] = []
    suspicious: list[str] = []

    for col in df.columns:
        series = df[col]
        stray_ws = col != col.strip()
        if stray_ws:
            suspicious.append(f"column name {col!r} has leading/trailing whitespace")

        missing_count = int(series.isna().sum())
        missing_pct = round(100 * missing_count / num_rows, 4) if num_rows else 0.0

        infinite_count = 0
        if pd.api.types.is_numeric_dtype(series):
            infinite_count = int(np.isinf(series.to_numpy(dtype="float64", na_value=0.0)).sum())
        else:
            non_numeric_columns.append(col)
            coerced = pd.to_numeric(series, errors="coerce")
            already_missing = series.isna().sum()
            newly_unparseable = int(coerced.isna().sum() - already_missing)
            if newly_unparseable > 0 and newly_unparseable < num_rows:
                suspicious.append(
                    f"column {col!r} is non-numeric but {newly_unparseable} of {num_rows} "
                    "values look like they were meant to be numeric (e.g. 'Infinity', 'NaN' "
                    "as literal strings) — inspect before assuming it's categorical"
                )

        unique_count = int(series.nunique(dropna=True))
        is_constant = unique_count <= 1

        columns.append(
            ColumnReport(
                name=col,
                dtype=str(series.dtype),
                has_stray_whitespace=stray_ws,
                missing_count=missing_count,
                missing_pct=missing_pct,
                infinite_count=infinite_count,
                is_constant=is_constant,
                unique_count=unique_count,
            )
        )
        if infinite_count > 0:
            suspicious.append(f"column {col!r} has {infinite_count} infinite value(s)")
        if is_constant:
            suspicious.append(f"column {col!r} is constant (only {unique_count} unique value)")

    label_column = _find_label_column(list(df.columns))
    label_distribution: dict[str, int] = {}
    if label_column is not None:
        label_distribution = {str(k): int(v) for k, v in df[label_column].value_counts(dropna=False).items()}

    if duplicate_rows > 0:
        suspicious.append(f"{duplicate_rows} fully duplicate row(s) out of {num_rows}")

    return CsvReport(
        filename=rel_name,
        size_bytes=size_bytes,
        num_rows=num_rows,
        num_columns=num_columns,
        duplicate_rows=duplicate_rows,
        columns=columns,
        label_column=label_column,
        label_distribution=label_distribution,
        non_numeric_columns=non_numeric_columns,
        suspicious=suspicious,
    )


def inspect_directory(raw_dir: Path) -> list[CsvReport]:
    csv_paths = sorted(raw_dir.rglob("*.csv"))
    return [inspect_csv(p, raw_dir) for p in csv_paths]


def render_markdown(reports: list[CsvReport]) -> str:
    lines = [
        "# Dataset Inspection Report",
        "",
        "Auto-generated by `ml/preprocessing/inspect_dataset.py`. Do not hand-edit —",
        "regenerate it instead if the raw files change.",
        "",
    ]
    if not reports:
        lines += [
            "No CSV files found under `ml/datasets/raw/`. Nothing has been inspected yet.",
            "",
        ]
        return "\n".join(lines)

    for r in reports:
        lines.append(f"## `{r.filename}`")
        lines.append("")
        if r.load_error:
            lines.append(f"**Failed to load:** {r.load_error}")
            lines.append("")
            continue
        lines.append(f"- Size: {r.size_bytes / (1024 * 1024):.1f} MB")
        lines.append(f"- Rows: {r.num_rows:,}")
        lines.append(f"- Columns: {r.num_columns}")
        lines.append(f"- Duplicate rows: {r.duplicate_rows:,}")
        lines.append(f"- Detected label column: {r.label_column!r}")
        lines.append("")

        if r.label_distribution:
            lines.append("### Label distribution")
            lines.append("")
            lines.append("| Label | Count |")
            lines.append("|---|---|")
            for label, count in sorted(r.label_distribution.items(), key=lambda kv: -kv[1]):
                lines.append(f"| {label} | {count:,} |")
            lines.append("")

        lines.append("### Columns")
        lines.append("")
        lines.append("| Column | Dtype | Missing | Missing % | Infinite | Unique | Constant |")
        lines.append("|---|---|---|---|---|---|---|")
        for c in r.columns:
            lines.append(
                f"| {c.name} | {c.dtype} | {c.missing_count:,} | {c.missing_pct}% | "
                f"{c.infinite_count:,} | {c.unique_count:,} | {'yes' if c.is_constant else 'no'} |"
            )
        lines.append("")

        if r.suspicious:
            lines.append("### Flags")
            lines.append("")
            for s in r.suspicious:
                lines.append(f"- {s}")
            lines.append("")

    return "\n".join(lines)


def main() -> None:
    reports = inspect_directory(RAW_DATA_DIR)

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DOCS_DIR / "dataset_inspection.md"
    report_path.write_text(render_markdown(reports), encoding="utf-8")

    json_path = RAW_DATA_DIR / "_inspection.json"
    json_path.write_text(
        json.dumps([asdict(r) for r in reports], indent=2),
        encoding="utf-8",
    )

    print(f"Inspected {len(reports)} CSV file(s).")
    print(f"Markdown report: {report_path}")
    print(f"JSON report:     {json_path}")


if __name__ == "__main__":
    main()
