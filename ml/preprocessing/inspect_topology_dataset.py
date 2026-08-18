"""Read-only inspector for the topology-bearing CICIDS2017 distribution
(GeneratedLabelledFlows / TrafficLabelling), used only to verify Phase 2's
data-availability stop condition before any attack_graph/ code is written.

Unlike ml/preprocessing/inspect_dataset.py (generic, dataset-agnostic,
reused by the Phase 1 cleaning pipeline), this module specifically checks
for the network-topology fields the attack graph needs (Flow ID, Source
IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp,
Label) and validates their contents (malformed IPs, invalid ports,
unexpected protocol values, unparseable timestamps). It does not clean,
transform, or persist anything — inspection only.

CLI usage:
    python -m ml.preprocessing.inspect_topology_dataset

Produces:
    docs/dataset_inspection_labelled_flows.md   human-readable report
    ml/datasets/raw_labelled_flows/_inspection.json   machine-readable
                                                       (gitignored)
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pandas as pd

from ml.preprocessing.config import DOCS_DIR, PROJECT_ROOT

TOPOLOGY_DATA_DIR = Path(
    os.environ.get(
        "TOPOLOGY_RAW_DIR", PROJECT_ROOT / "ml" / "datasets" / "raw_labelled_flows"
    )
)
PHASE1_RAW_DATA_DIR = Path(
    os.environ.get("DATASET_RAW_DIR", PROJECT_ROOT / "ml" / "datasets" / "raw")
)

REQUIRED_TOPOLOGY_FIELDS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Label",
]

# IANA-assigned protocol numbers actually plausible in captured IP traffic;
# anything else found in the data is flagged as "unexpected", not rejected.
PLAUSIBLE_PROTOCOL_NUMBERS = {0, 1, 2, 6, 17, 41, 47, 50, 51, 58, 132}


def _strip(name: str) -> str:
    return name.strip()


def _read_csv_robust(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path, low_memory=False, encoding="utf-8")
    except UnicodeDecodeError:
        return pd.read_csv(path, low_memory=False, encoding="latin1")


@dataclass
class FieldPresence:
    requested_name: str
    found_column: str | None
    present: bool


@dataclass
class ValidationIssue:
    check: str
    count: int
    pct: float
    example_values: list[str] = field(default_factory=list)


@dataclass
class TopologyCsvReport:
    filename: str
    size_bytes: int
    num_rows: int
    num_columns: int
    columns: list[str] = field(default_factory=list)
    dtypes: dict[str, str] = field(default_factory=dict)
    field_presence: list[FieldPresence] = field(default_factory=list)
    missing_values_by_column: dict[str, int] = field(default_factory=dict)
    duplicate_rows: int = 0
    validation_issues: list[ValidationIssue] = field(default_factory=list)
    load_error: str | None = None


def _find_field(columns: list[str], target: str) -> str | None:
    """Match a required field name allowing for leading/trailing whitespace,
    exactly like the Phase 1 header quirk (65 of 79 columns had a stray
    leading space). Does not fuzzy-match beyond stripping."""
    stripped = {c: _strip(c) for c in columns}
    for original, norm in stripped.items():
        if norm == target:
            return original
    return None


def _validate_ip_column(series: pd.Series) -> ValidationIssue | None:
    def is_valid(v: object) -> bool:
        if pd.isna(v):
            return False
        try:
            ipaddress.ip_address(str(v).strip())
            return True
        except ValueError:
            return False

    valid_mask = series.map(is_valid)
    invalid = series[~valid_mask]
    if len(invalid) == 0:
        return None
    examples = [str(v) for v in invalid.head(5).tolist()]
    return ValidationIssue(
        check="malformed IP address",
        count=int(len(invalid)),
        pct=round(100 * len(invalid) / len(series), 4) if len(series) else 0.0,
        example_values=examples,
    )


def _validate_port_column(series: pd.Series, label: str) -> ValidationIssue | None:
    numeric = pd.to_numeric(series, errors="coerce")
    invalid_mask = numeric.isna() | (numeric < 0) | (numeric > 65535) | (numeric != numeric.round())
    invalid = series[invalid_mask]
    if len(invalid) == 0:
        return None
    examples = [str(v) for v in invalid.head(5).tolist()]
    return ValidationIssue(
        check=f"invalid {label} (outside 0-65535 or non-integer)",
        count=int(len(invalid)),
        pct=round(100 * len(invalid) / len(series), 4) if len(series) else 0.0,
        example_values=examples,
    )


def _validate_protocol_column(series: pd.Series) -> ValidationIssue | None:
    numeric = pd.to_numeric(series, errors="coerce")
    unexpected_mask = numeric.isna() | ~numeric.isin(PLAUSIBLE_PROTOCOL_NUMBERS)
    unexpected = series[unexpected_mask]
    if len(unexpected) == 0:
        return None
    examples = sorted({str(v) for v in unexpected.head(20).tolist()})[:5]
    return ValidationIssue(
        check="unexpected protocol value (not in {0,1,2,6,17,41,47,50,51,58,132})",
        count=int(len(unexpected)),
        pct=round(100 * len(unexpected) / len(series), 4) if len(series) else 0.0,
        example_values=examples,
    )


def _validate_timestamp_column(series: pd.Series) -> ValidationIssue | None:
    parsed = pd.to_datetime(series, errors="coerce", format="mixed", dayfirst=False)
    unparseable = series[parsed.isna() & series.notna()]
    if len(unparseable) == 0:
        return None
    examples = [str(v) for v in unparseable.head(5).tolist()]
    return ValidationIssue(
        check="unparseable timestamp",
        count=int(len(unparseable)),
        pct=round(100 * len(unparseable) / len(series), 4) if len(series) else 0.0,
        example_values=examples,
    )


def inspect_topology_csv(path: Path, data_dir: Path) -> TopologyCsvReport:
    rel_name = str(path.relative_to(data_dir))
    size_bytes = path.stat().st_size

    try:
        df = _read_csv_robust(path)
    except Exception as exc:
        return TopologyCsvReport(
            filename=rel_name,
            size_bytes=size_bytes,
            num_rows=0,
            num_columns=0,
            load_error=f"{type(exc).__name__}: {exc}",
        )

    num_rows, num_columns = df.shape
    columns = list(df.columns)

    field_presence = [
        FieldPresence(
            requested_name=field_name,
            found_column=_find_field(columns, field_name),
            present=_find_field(columns, field_name) is not None,
        )
        for field_name in REQUIRED_TOPOLOGY_FIELDS
    ]

    missing_values_by_column = {
        col: int(df[col].isna().sum()) for col in columns if df[col].isna().sum() > 0
    }
    duplicate_rows = int(df.duplicated().sum())

    validation_issues: list[ValidationIssue] = []
    by_requested = {fp.requested_name: fp.found_column for fp in field_presence}

    if by_requested["Source IP"]:
        issue = _validate_ip_column(df[by_requested["Source IP"]])
        if issue:
            validation_issues.append(ValidationIssue(f"Source IP: {issue.check}", issue.count, issue.pct, issue.example_values))
    if by_requested["Destination IP"]:
        issue = _validate_ip_column(df[by_requested["Destination IP"]])
        if issue:
            validation_issues.append(ValidationIssue(f"Destination IP: {issue.check}", issue.count, issue.pct, issue.example_values))
    if by_requested["Source Port"]:
        issue = _validate_port_column(df[by_requested["Source Port"]], "Source Port")
        if issue:
            validation_issues.append(issue)
    if by_requested["Destination Port"]:
        issue = _validate_port_column(df[by_requested["Destination Port"]], "Destination Port")
        if issue:
            validation_issues.append(issue)
    if by_requested["Protocol"]:
        issue = _validate_protocol_column(df[by_requested["Protocol"]])
        if issue:
            validation_issues.append(issue)
    if by_requested["Timestamp"]:
        issue = _validate_timestamp_column(df[by_requested["Timestamp"]])
        if issue:
            validation_issues.append(issue)

    if duplicate_rows > 0:
        validation_issues.append(
            ValidationIssue(
                check="fully duplicate rows",
                count=duplicate_rows,
                pct=round(100 * duplicate_rows / num_rows, 4) if num_rows else 0.0,
            )
        )

    return TopologyCsvReport(
        filename=rel_name,
        size_bytes=size_bytes,
        num_rows=num_rows,
        num_columns=num_columns,
        columns=columns,
        dtypes={col: str(df[col].dtype) for col in columns},
        field_presence=field_presence,
        missing_values_by_column=missing_values_by_column,
        duplicate_rows=duplicate_rows,
        validation_issues=validation_issues,
    )


def inspect_topology_directory(data_dir: Path) -> list[TopologyCsvReport]:
    csv_paths = sorted(data_dir.rglob("*.csv"))
    return [inspect_topology_csv(p, data_dir) for p in csv_paths]


def check_schema_consistency(reports: list[TopologyCsvReport]) -> tuple[bool, str]:
    loaded = [r for r in reports if r.load_error is None]
    if not loaded:
        return False, "No files loaded successfully."
    reference = tuple(loaded[0].columns)
    mismatches = [r.filename for r in loaded[1:] if tuple(r.columns) != reference]
    if not mismatches:
        return True, f"All {len(loaded)} files share an identical {len(reference)}-column schema."
    return False, f"Column mismatch in: {', '.join(mismatches)} (relative to {loaded[0].filename})"


def compare_with_phase1_schema(
    topology_reports: list[TopologyCsvReport], phase1_dir: Path
) -> str:
    if not phase1_dir.exists():
        return f"Phase 1 raw dir {phase1_dir} not found; skipped comparison."
    phase1_csvs = sorted(phase1_dir.glob("*.csv"))
    if not phase1_csvs:
        return f"No CSVs found in {phase1_dir}; skipped comparison."
    phase1_columns = {_strip(c) for c in pd.read_csv(phase1_csvs[0], nrows=0).columns}

    loaded = [r for r in topology_reports if r.load_error is None]
    if not loaded:
        return "No topology files loaded; skipped comparison."
    topology_columns = {_strip(c) for c in loaded[0].columns}

    only_in_topology = sorted(topology_columns - phase1_columns)
    only_in_phase1 = sorted(phase1_columns - topology_columns)
    shared = sorted(topology_columns & phase1_columns)

    lines = [
        f"Phase 1 (`{phase1_csvs[0].name}`): {len(phase1_columns)} stripped column names.",
        f"Topology (`{loaded[0].filename}`): {len(topology_columns)} stripped column names.",
        f"Shared (stripped-name match): {len(shared)}.",
        f"Only in topology dataset ({len(only_in_topology)}): {', '.join(only_in_topology)}",
        f"Only in Phase 1 dataset ({len(only_in_phase1)}): {', '.join(only_in_phase1) or '(none)'}",
    ]
    return "\n".join(lines)


def render_markdown(
    reports: list[TopologyCsvReport], schema_ok: bool, schema_msg: str, phase1_comparison: str
) -> str:
    lines = [
        "# Topology Dataset Inspection Report (GeneratedLabelledFlows)",
        "",
        "Auto-generated by `ml/preprocessing/inspect_topology_dataset.py`. Read-only",
        "inspection of `ml/datasets/raw_labelled_flows/` — Phase 2 stop-condition check.",
        "Do not hand-edit; regenerate instead if the raw files change.",
        "",
        "## Schema consistency across files",
        "",
        schema_msg,
        "",
        "## Comparison with Phase 1 MachineLearningCSV schema",
        "",
        phase1_comparison,
        "",
    ]

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
        lines.append("")

        lines.append("### Required topology field presence")
        lines.append("")
        lines.append("| Requested field | Found column | Present |")
        lines.append("|---|---|---|")
        for fp in r.field_presence:
            lines.append(
                f"| {fp.requested_name} | {fp.found_column or '(missing)'} | "
                f"{'YES' if fp.present else 'NO'} |"
            )
        lines.append("")

        lines.append("### All columns and dtypes")
        lines.append("")
        lines.append("| # | Column | Dtype |")
        lines.append("|---|---|---|")
        for i, col in enumerate(r.columns, start=1):
            lines.append(f"| {i} | {col} | {r.dtypes[col]} |")
        lines.append("")

        if r.missing_values_by_column:
            lines.append("### Missing values by column")
            lines.append("")
            lines.append("| Column | Missing count |")
            lines.append("|---|---|")
            for col, cnt in r.missing_values_by_column.items():
                lines.append(f"| {col} | {cnt:,} |")
            lines.append("")
        else:
            lines.append("### Missing values by column")
            lines.append("")
            lines.append("None found.")
            lines.append("")

        lines.append("### Validation issues")
        lines.append("")
        if r.validation_issues:
            lines.append("| Check | Count | % of rows | Examples |")
            lines.append("|---|---|---|---|")
            for issue in r.validation_issues:
                examples = ", ".join(issue.example_values) if issue.example_values else "-"
                lines.append(f"| {issue.check} | {issue.count:,} | {issue.pct}% | {examples} |")
        else:
            lines.append("None found.")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    reports = inspect_topology_directory(TOPOLOGY_DATA_DIR)
    schema_ok, schema_msg = check_schema_consistency(reports)
    phase1_comparison = compare_with_phase1_schema(reports, PHASE1_RAW_DATA_DIR)

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DOCS_DIR / "dataset_inspection_labelled_flows.md"
    report_path.write_text(
        render_markdown(reports, schema_ok, schema_msg, phase1_comparison), encoding="utf-8"
    )

    json_path = TOPOLOGY_DATA_DIR / "_inspection.json"
    json_path.write_text(json.dumps([asdict(r) for r in reports], indent=2), encoding="utf-8")

    print(f"Inspected {len(reports)} CSV file(s). Schema consistent: {schema_ok}")
    print(f"Markdown report: {report_path}")
    print(f"JSON report:     {json_path}")


if __name__ == "__main__":
    main()
