"""Phase 1 cleaning / feature-selection pipeline for CICIDS2017.

Order of operations (see docs/cleaning_decision_report.md for the report
this run produces, and docs/dataset_inspection.md for the raw-data facts
this pipeline is built on):

  1. Load all raw CSVs, strip column-name whitespace, drop the confirmed
     exact-duplicate column (``Fwd Header Length.1``), tag every row with
     its source file.
  2. Preserve the raw label and add a normalized canonical label
     (ml/preprocessing/labels.py) — unrecognized label values raise rather
     than being silently mapped.
  3. Remove exact duplicate rows (all feature + label columns, ignoring the
     source-file tag so cross-file duplicates are caught too) globally,
     before any split, to avoid the same flow leaking across train/val/test.
  4. Convert +-Inf to NaN in the two columns known to contain them
     (division-by-zero on zero-duration flows), measure how concentrated
     the affected rows are by label and by source file, and drop those
     rows if the affected fraction is small.
  5. Redundant-feature detection on the full cleaned dataset (every row,
     not a split — see find_redundant_features docstring for why that
     matters), then drop the columns confirmed structurally redundant
     (CONFIRMED_REDUNDANT_FEATURES) while keeping exact-but-unexplained
     duplicates in the feature set (documented in the report).
  6. Stratified train/val/test split on the canonical label.
  7. Zero-variance feature detection computed on the training split only.
  8. Feature / metadata / label separation.
  9. StandardScaler fit on the training split only; val/test are only
     ever transformed, never refit, so no split leaks into another.
  10. Write processed splits + a human-readable cleaning-decision report.

Run as:
    python -m ml.preprocessing.clean
"""

from __future__ import annotations

import json
import pickle
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ml.preprocessing.config import (
    DOCS_DIR,
    PROCESSED_DATA_DIR,
    RANDOM_SEED,
    RAW_DATA_DIR,
    TEST_SPLIT,
    TRAIN_SPLIT,
    VAL_SPLIT,
)
from ml.preprocessing.labels import MOJIBAKE_TO_CANONICAL, normalize_labels

RAW_LABEL_COLUMN = "Label"
CANONICAL_LABEL_COLUMN = "canonical_label"
SOURCE_FILE_COLUMN = "source_file"

# Confirmed byte-identical duplicate of "Fwd Header Length" — see
# docs/dataset_inspection.md. The original CICFlowMeter header repeated the
# name; pandas auto-suffixed the second occurrence on read.
DUPLICATE_COLUMNS = ["Fwd Header Length.1"]

# The only two columns the inspector found missing/infinite values in,
# both caused by division-by-zero on zero-duration flows.
INF_PRONE_COLUMNS = ["Flow Bytes/s", "Flow Packets/s"]

# Above this fraction of affected rows, handle_inf_nan refuses to silently
# drop rows and asks for a decision instead (policy: "do not silently
# discard a large portion of the dataset").
INF_NAN_DROP_THRESHOLD = 0.01

# Decision (2026-08-18): keep as a numeric model feature, scaled like any
# other flow feature — it's directly available from live flow telemetry
# (unlike source/destination IP, which this dataset doesn't even have) and
# carries real service/attack-behavior signal. Treating a port number as a
# continuous scaled value is a simplification (no ordinal relationship
# between e.g. port 21 and port 22) accepted for Phase 1; revisit if a
# categorical/embedding encoding is wanted later. Also duplicated into
# metadata, unscaled, for the future attack-graph module.
LEAKAGE_PRONE_FEATURES = ["Destination Port"]
ATTACK_GRAPH_METADATA_FEATURES = ["Destination Port"]

# Decision (2026-08-18): dropped as structurally redundant with Total
# Fwd/Bwd Packets — CICFlowMeter reports exactly one subflow per record in
# this export, so Subflow == Total by definition here. Verified
# byte-for-byte equal across all 2,520,798 cleaned rows, all 8 files, and
# all 15 labels (not just the training split) before dropping. Two other
# exact-duplicate pairs found by the same analysis (Fwd PSH Flags ==
# SYN Flag Count, Fwd URG Flags == CWE Flag Count) were deliberately left
# in the feature set: their equality has no structural explanation and
# looks coincidental to this specific capture rather than a guaranteed
# identity, so dropping either felt like discarding a real, differently-
# named metric rather than removing a true duplicate. See
# docs/cleaning_decision_report.md for the full pairwise verification.
CONFIRMED_REDUNDANT_FEATURES = ["Subflow Fwd Packets", "Subflow Bwd Packets"]


@dataclass
class CleaningReport:
    files_loaded: list[str]
    rows_before_dedup: int
    exact_duplicate_rows: int
    rows_after_dedup: int
    inf_counts_before: dict[str, int]
    nan_rows_after_inf_conversion: int
    nan_row_pct: float
    nan_by_label: dict[str, int]
    nan_by_file: dict[str, int]
    inf_nan_rows_dropped: bool
    rows_after_inf_nan_handling: int
    label_distribution_before: dict[str, int]
    label_distribution_after: dict[str, int]
    mojibake_mappings: dict[str, str]
    split_sizes: dict[str, int]
    split_label_distribution: dict[str, dict[str, int]]
    zero_variance_columns: dict[str, float]
    exact_duplicate_feature_pairs: list[list[str]]
    redundant_features_dropped: list[str]
    redundant_features_kept: list[list[str]]
    near_duplicate_feature_pairs: list[dict]
    model_feature_columns: list[str]
    metadata_columns: list[str]
    questionable_fields: list[str] = field(default_factory=list)


def load_raw_dataset(raw_dir: Path) -> pd.DataFrame:
    csv_paths = sorted(raw_dir.glob("*.csv"))
    frames = []
    for path in csv_paths:
        df = pd.read_csv(path, low_memory=False, encoding="utf-8")
        df.columns = [c.strip() for c in df.columns]
        df[SOURCE_FILE_COLUMN] = path.name
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True, copy=False)
    combined = combined.drop(columns=DUPLICATE_COLUMNS)
    return combined


def add_canonical_label(df: pd.DataFrame) -> pd.DataFrame:
    df[CANONICAL_LABEL_COLUMN] = normalize_labels(df[RAW_LABEL_COLUMN])
    return df


def remove_exact_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop exact duplicate rows, ignoring the source-file tag so a flow
    that happens to be identical across two different day-captures is still
    caught (not just duplicates within a single file)."""
    subset = [c for c in df.columns if c != SOURCE_FILE_COLUMN]
    dup_mask = df.duplicated(subset=subset, keep="first")
    dup_count = int(dup_mask.sum())
    deduped = df.loc[~dup_mask].reset_index(drop=True)
    return deduped, dup_count


def handle_inf_nan(
    df: pd.DataFrame, columns: list[str] = INF_PRONE_COLUMNS
) -> tuple[pd.DataFrame, dict]:
    inf_counts_before = {
        col: int(np.isinf(df[col].to_numpy(dtype="float64")).sum()) for col in columns
    }

    df = df.copy()
    for col in columns:
        df[col] = df[col].replace([np.inf, -np.inf], np.nan)

    affected_mask = df[columns].isna().any(axis=1)
    affected_count = int(affected_mask.sum())
    total_rows = len(df)
    affected_pct = affected_count / total_rows if total_rows else 0.0

    nan_by_label = (
        df.loc[affected_mask, CANONICAL_LABEL_COLUMN].value_counts().to_dict()
    )
    nan_by_file = df.loc[affected_mask, SOURCE_FILE_COLUMN].value_counts().to_dict()

    stats = {
        "inf_counts_before": inf_counts_before,
        "nan_rows_after_inf_conversion": affected_count,
        "nan_row_pct": round(100 * affected_pct, 6),
        "nan_by_label": {str(k): int(v) for k, v in nan_by_label.items()},
        "nan_by_file": {str(k): int(v) for k, v in nan_by_file.items()},
        "rows_dropped": False,
    }

    if affected_pct <= INF_NAN_DROP_THRESHOLD:
        df = df.loc[~affected_mask].reset_index(drop=True)
        stats["rows_dropped"] = True
    # else: leave NaN in place; caller must stop and decide (policy: never
    # silently discard a large fraction of the dataset).

    return df, stats


def stratified_split(
    df: pd.DataFrame,
    label_col: str,
    train_frac: float = TRAIN_SPLIT,
    val_frac: float = VAL_SPLIT,
    test_frac: float = TEST_SPLIT,
    seed: int = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    assert abs(train_frac + val_frac + test_frac - 1.0) < 1e-9

    counts = df[label_col].value_counts()
    stratifiable = counts[counts >= 4].index
    unstratifiable = counts[counts < 4].index

    strat_df = df[df[label_col].isin(stratifiable)]
    rest_df = df[df[label_col].isin(unstratifiable)]

    train_df, temp_df = train_test_split(
        strat_df,
        test_size=(val_frac + test_frac),
        stratify=strat_df[label_col],
        random_state=seed,
    )
    val_df, test_df = train_test_split(
        temp_df,
        test_size=test_frac / (val_frac + test_frac),
        stratify=temp_df[label_col],
        random_state=seed,
    )

    # Classes too rare to stratify (fewer than 3 members) go entirely into
    # training — there aren't enough examples to guarantee representation
    # in val/test as well, and evaluation on a 0-2 sample class would be
    # meaningless anyway. Documented in the report as a limitation.
    train_df = pd.concat([train_df, rest_df], ignore_index=False)

    return (
        train_df.reset_index(drop=True),
        val_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
    )


def find_zero_variance_columns(df: pd.DataFrame, candidate_cols: list[str]) -> dict[str, float]:
    variances = df[candidate_cols].var(ddof=0)
    return {col: float(variances[col]) for col in candidate_cols if variances[col] == 0}


def find_redundant_features(
    df: pd.DataFrame, candidate_cols: list[str], sample_size: int = 200_000, seed: int = RANDOM_SEED
) -> tuple[list[list[str]], list[dict]]:
    """Return (exact_duplicate_pairs, near_duplicate_pairs) among candidate
    numeric feature columns.

    ``df`` must be the full cleaned dataset (post dedup/Inf-NaN handling,
    pre-split) rather than any single split. Candidate pairs are found via
    correlation on a sample for speed, but exactness is then verified with
    an equality check against every row of the full dataset — checking only
    a split (e.g. the training set) can misclassify a pair as "exact" when
    it actually differs in a handful of rows that split happens not to
    contain (this happened in practice: two pairs were exact on the 1.76M
    training rows but each had exactly one mismatching row elsewhere in the
    2.52M-row full dataset — see docs/cleaning_decision_report.md).
    """
    sample = df[candidate_cols]
    if len(sample) > sample_size:
        sample = sample.sample(n=sample_size, random_state=seed)

    corr = sample.corr()
    exact_pairs: list[list[str]] = []
    near_pairs: list[dict] = []
    cols = candidate_cols
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            c = corr.iloc[i, j]
            if pd.isna(c) or c < 0.999:
                continue
            a, b = cols[i], cols[j]
            if df[a].equals(df[b]):
                exact_pairs.append([a, b])
            else:
                mismatches = int((df[a] != df[b]).sum())
                near_pairs.append(
                    {
                        "columns": [a, b],
                        "correlation": round(float(c), 8),
                        "mismatch_count": mismatches,
                        "mismatch_pct": round(100 * mismatches / len(df), 6),
                    }
                )
    return exact_pairs, near_pairs


def separate_features_metadata(
    df: pd.DataFrame, zero_variance_cols: list[str]
) -> tuple[list[str], list[str]]:
    non_feature_cols = {RAW_LABEL_COLUMN, CANONICAL_LABEL_COLUMN, SOURCE_FILE_COLUMN}
    numeric_cols = [
        c for c in df.columns if c not in non_feature_cols and pd.api.types.is_numeric_dtype(df[c])
    ]
    model_features = [c for c in numeric_cols if c not in zero_variance_cols]
    # Destination Port is both a scaled model feature (see
    # ATTACK_GRAPH_METADATA_FEATURES / LEAKAGE_PRONE_FEATURES above) and,
    # unscaled, future attack-graph metadata — kept in both outputs.
    metadata_cols = [
        RAW_LABEL_COLUMN,
        CANONICAL_LABEL_COLUMN,
        SOURCE_FILE_COLUMN,
    ] + ATTACK_GRAPH_METADATA_FEATURES
    return model_features, metadata_cols


def assert_clean_matrix(X: np.ndarray, name: str) -> None:
    assert not np.isnan(X).any(), f"{name} contains NaN after cleaning"
    assert not np.isinf(X).any(), f"{name} contains +-Inf after cleaning"


def render_report(report: CleaningReport) -> str:
    lines = [
        "# Cleaning Decision Report",
        "",
        "Auto-generated by `ml/preprocessing/clean.py`. Do not hand-edit —",
        "regenerate it instead if the pipeline or raw files change.",
        "",
        "## 1. Deduplication",
        "",
        f"- Files loaded: {len(report.files_loaded)}",
        f"- Rows before dedup: {report.rows_before_dedup:,}",
        f"- Exact duplicate rows removed: {report.exact_duplicate_rows:,} "
        f"({100 * report.exact_duplicate_rows / report.rows_before_dedup:.2f}%)",
        f"- Rows after dedup: {report.rows_after_dedup:,}",
        "",
        "## 2. Zero-variance columns (measured on training split)",
        "",
    ]
    if report.zero_variance_columns:
        lines.append("| Column | Variance |")
        lines.append("|---|---|")
        for col, var in report.zero_variance_columns.items():
            lines.append(f"| {col} | {var} |")
    else:
        lines.append("None found.")
    lines += [
        "",
        "## 3. Infinite / missing values",
        "",
        f"- Inf counts before conversion: {report.inf_counts_before}",
        f"- Rows with NaN after Inf->NaN conversion: {report.nan_rows_after_inf_conversion:,} "
        f"({report.nan_row_pct}%)",
        f"- Affected rows by label: {report.nan_by_label}",
        f"- Affected rows by source file: {report.nan_by_file}",
        f"- Rows dropped: {report.inf_nan_rows_dropped} "
        f"(threshold: {INF_NAN_DROP_THRESHOLD * 100}%)",
        f"- Rows after Inf/NaN handling: {report.rows_after_inf_nan_handling:,}",
        "",
        "## 4. Mojibake label normalization",
        "",
        "| Raw (corrupted) | Canonical |",
        "|---|---|",
    ]
    for raw, canonical in report.mojibake_mappings.items():
        lines.append(f"| {raw} | {canonical} |")
    lines += [
        "",
        "### Label distribution before normalization",
        "",
        "| Label | Count |",
        "|---|---|",
    ]
    for label, count in sorted(report.label_distribution_before.items(), key=lambda kv: -kv[1]):
        lines.append(f"| {label} | {count:,} |")
    lines += [
        "",
        "### Label distribution after normalization (post dedup/Inf-NaN cleanup)",
        "",
        "| Canonical label | Count |",
        "|---|---|",
    ]
    for label, count in sorted(report.label_distribution_after.items(), key=lambda kv: -kv[1]):
        lines.append(f"| {label} | {count:,} |")
    lines += [
        "",
        "## 5. Train / validation / test split",
        "",
        f"- Sizes: {report.split_sizes}",
        "",
    ]
    for split_name, dist in report.split_label_distribution.items():
        lines.append(f"### {split_name}")
        lines.append("")
        lines.append("| Canonical label | Count |")
        lines.append("|---|---|")
        for label, count in sorted(dist.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {label} | {count:,} |")
        lines.append("")
    lines += [
        "## 6. Feature selection",
        "",
        f"- Model feature count: {len(report.model_feature_columns)}",
        f"- Model features: {report.model_feature_columns}",
        f"- Metadata columns (not fed to the model): {report.metadata_columns}",
        "",
        "### Redundant feature pairs",
        "",
        "Verified against every row of the full cleaned dataset (not just the",
        "training split) — see module docstring in clean.py for why that",
        "distinction matters.",
        "",
        f"- Exact duplicate pairs found (all rows/files/labels identical): {report.exact_duplicate_feature_pairs}",
        f"  - Dropped (structural redundancy, e.g. Subflow == Total by definition here): {report.redundant_features_dropped}",
        f"  - Kept (exact but no structural explanation, equality looks coincidental to this capture): {report.redundant_features_kept}",
        f"- Near-duplicate pairs (correlation >= 0.999 but NOT exact — checked and rejected as duplicates, values differ in at least one row): {report.near_duplicate_feature_pairs}",
        "",
        "### Questionable fields",
        "",
    ]
    for item in report.questionable_fields:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    csv_paths = sorted(RAW_DATA_DIR.glob("*.csv"))

    df = load_raw_dataset(RAW_DATA_DIR)
    df = add_canonical_label(df)

    rows_before_dedup = len(df)
    label_distribution_before = df[RAW_LABEL_COLUMN].value_counts().to_dict()

    df, dup_count = remove_exact_duplicates(df)
    rows_after_dedup = len(df)

    df, inf_nan_stats = handle_inf_nan(df)
    if inf_nan_stats["nan_row_pct"] / 100 > INF_NAN_DROP_THRESHOLD:
        raise RuntimeError(
            "Inf/NaN-affected fraction exceeds the drop threshold "
            f"({inf_nan_stats['nan_row_pct']}% > {INF_NAN_DROP_THRESHOLD * 100}%) — "
            "stopping for a decision instead of silently discarding data. "
            f"Stats: {inf_nan_stats}"
        )
    rows_after_inf_nan = len(df)

    # Redundant-feature detection runs on the full cleaned dataset (all
    # 2,520,798 rows at this point), not a split — see find_redundant_features
    # docstring for why a split-only check is not trustworthy here.
    numeric_candidate_cols = [
        c
        for c in df.columns
        if c not in {RAW_LABEL_COLUMN, CANONICAL_LABEL_COLUMN, SOURCE_FILE_COLUMN}
        and pd.api.types.is_numeric_dtype(df[c])
    ]
    exact_pairs, near_pairs = find_redundant_features(df, numeric_candidate_cols)

    redundant_dropped = [c for c in CONFIRMED_REDUNDANT_FEATURES if c in df.columns]
    redundant_kept = [pair for pair in exact_pairs if not set(pair) & set(redundant_dropped)]
    df = df.drop(columns=redundant_dropped)

    train_df, val_df, test_df = stratified_split(df, CANONICAL_LABEL_COLUMN)

    numeric_candidate_cols = [c for c in numeric_candidate_cols if c not in redundant_dropped]
    zero_var_cols = find_zero_variance_columns(train_df, numeric_candidate_cols)

    model_features, metadata_cols = separate_features_metadata(df, list(zero_var_cols))

    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_df[model_features].to_numpy(dtype="float64")).astype("float32")
    X_val = scaler.transform(val_df[model_features].to_numpy(dtype="float64")).astype("float32")
    X_test = scaler.transform(test_df[model_features].to_numpy(dtype="float64")).astype("float32")

    assert_clean_matrix(X_train, "X_train")
    assert_clean_matrix(X_val, "X_val")
    assert_clean_matrix(X_test, "X_test")

    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(PROCESSED_DATA_DIR / "train_features.npz", X=X_train)
    np.savez_compressed(PROCESSED_DATA_DIR / "val_features.npz", X=X_val)
    np.savez_compressed(PROCESSED_DATA_DIR / "test_features.npz", X=X_test)
    train_df[metadata_cols].to_csv(PROCESSED_DATA_DIR / "train_metadata.csv", index=False)
    val_df[metadata_cols].to_csv(PROCESSED_DATA_DIR / "val_metadata.csv", index=False)
    test_df[metadata_cols].to_csv(PROCESSED_DATA_DIR / "test_metadata.csv", index=False)
    (PROCESSED_DATA_DIR / "feature_names.json").write_text(
        json.dumps(model_features, indent=2), encoding="utf-8"
    )
    with open(PROCESSED_DATA_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    report = CleaningReport(
        files_loaded=[p.name for p in csv_paths],
        rows_before_dedup=rows_before_dedup,
        exact_duplicate_rows=dup_count,
        rows_after_dedup=rows_after_dedup,
        inf_counts_before=inf_nan_stats["inf_counts_before"],
        nan_rows_after_inf_conversion=inf_nan_stats["nan_rows_after_inf_conversion"],
        nan_row_pct=inf_nan_stats["nan_row_pct"],
        nan_by_label=inf_nan_stats["nan_by_label"],
        nan_by_file=inf_nan_stats["nan_by_file"],
        inf_nan_rows_dropped=inf_nan_stats["rows_dropped"],
        rows_after_inf_nan_handling=rows_after_inf_nan,
        label_distribution_before={str(k): int(v) for k, v in label_distribution_before.items()},
        label_distribution_after={
            str(k): int(v) for k, v in df[CANONICAL_LABEL_COLUMN].value_counts().to_dict().items()
        },
        mojibake_mappings=MOJIBAKE_TO_CANONICAL,
        split_sizes={"train": len(train_df), "val": len(val_df), "test": len(test_df)},
        split_label_distribution={
            "train": {str(k): int(v) for k, v in train_df[CANONICAL_LABEL_COLUMN].value_counts().to_dict().items()},
            "val": {str(k): int(v) for k, v in val_df[CANONICAL_LABEL_COLUMN].value_counts().to_dict().items()},
            "test": {str(k): int(v) for k, v in test_df[CANONICAL_LABEL_COLUMN].value_counts().to_dict().items()},
        },
        zero_variance_columns=zero_var_cols,
        exact_duplicate_feature_pairs=exact_pairs,
        redundant_features_dropped=redundant_dropped,
        redundant_features_kept=redundant_kept,
        near_duplicate_feature_pairs=near_pairs,
        model_feature_columns=model_features,
        metadata_columns=metadata_cols,
        questionable_fields=[
            f"{col!r} decision (2026-08-18): kept as a scaled numeric model feature "
            "(available from live flow telemetry, carries service/attack-behavior "
            "signal) and also duplicated, unscaled, into metadata for the future "
            "attack-graph module. Treating a port number as a continuous scaled "
            "value is a simplification with no ordinal meaning between adjacent "
            "port numbers — accepted for Phase 1. CICIDS2017 attacks in this "
            "capture often target one fixed port (e.g. FTP-Patator -> 21, "
            "SSH-Patator -> 22), so a model could shortcut-learn on port number "
            "instead of behavioral flow features; revisit if that turns out to "
            "matter during autoencoder evaluation."
            for col in LEAKAGE_PRONE_FEATURES
        ]
        + [
            "This CICIDS2017 MachineLearningCSV variant has no Source IP / "
            "Destination IP / Flow ID / Timestamp columns at all (already "
            "stripped upstream) — so no raw-identifier exclusion was needed for "
            "the autoencoder, but it also means the attack-graph module "
            "(docs/architecture.md) cannot build host-level topology from this "
            "dataset alone; it will need a different data source or the "
            "IP-bearing GeneratedLabelledFlows CICIDS2017 variant.",
        ],
    )

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DOCS_DIR / "cleaning_decision_report.md"
    report_path.write_text(render_report(report), encoding="utf-8")
    (PROCESSED_DATA_DIR / "_cleaning_report.json").write_text(
        json.dumps(asdict(report), indent=2), encoding="utf-8"
    )

    print(f"Report written to {report_path}")
    print(f"Processed splits written to {PROCESSED_DATA_DIR}")


if __name__ == "__main__":
    main()
