"""Per-chunk cleaning: blank-row removal, IP/port/timestamp validation, and
canonical label derivation. Every dropped row is counted in a CleaningStats
so the pipeline can report exactly what was removed and why -- nothing is
silently discarded, and no field is fabricated or repaired.

Cleaning order matters: blank rows are dropped first (their Label field is
NaN, which would otherwise make ml.preprocessing.labels.normalize_labels
raise on an "unrecognized" NaN label).
"""

from __future__ import annotations

import ipaddress

import pandas as pd

from ml.preprocessing.labels import CLEAN_LABELS, MOJIBAKE_TO_CANONICAL

from attack_graph.schemas import REQUIRED_RAW_COLUMNS, CleaningStats, traffic_class

MIN_PORT = 0
MAX_PORT = 65535

# This distribution (GeneratedLabelledFlows) encodes the "Web Attack" label
# separator as a raw 0x96 byte, decoded as U+0096 when the file falls back
# to latin1 (attack_graph.generation.loader._detect_encoding) -- verified
# byte-for-byte in Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
# (2,180 occurrences, all confined to the Label column; see
# docs/attack_graph.md). This is a *different* corruption than the UTF-8
# U+FFFD sequence ml/preprocessing/labels.py's MOJIBAKE_TO_CANONICAL maps
# for Phase 1's MachineLearningCSV variant of the same three labels -- that
# module is Phase 1's already-committed, tested artifact and is
# deliberately left unmodified. Reused here (CLEAN_LABELS,
# MOJIBAKE_TO_CANONICAL) rather than duplicated, merged with this
# distribution's own corrupted variant so both are recognized and mapped
# to the identical canonical spelling.
TOPOLOGY_MOJIBAKE_TO_CANONICAL: dict[str, str] = {
    "Web Attack \x96 Brute Force": "Web Attack - Brute Force",
    "Web Attack \x96 Sql Injection": "Web Attack - Sql Injection",
    "Web Attack \x96 XSS": "Web Attack - XSS",
}
_ALL_MOJIBAKE_TO_CANONICAL: dict[str, str] = {**MOJIBAKE_TO_CANONICAL, **TOPOLOGY_MOJIBAKE_TO_CANONICAL}
_KNOWN_RAW_LABELS: set[str] = CLEAN_LABELS | set(_ALL_MOJIBAKE_TO_CANONICAL)


def normalize_topology_labels(raw: pd.Series) -> pd.Series:
    """Like ml.preprocessing.labels.normalize_labels, but recognizing both
    Phase 1's U+FFFD mojibake variant and this distribution's own 0x96
    variant. Raises on anything outside both known sets -- never guesses at
    an unfamiliar label."""
    unknown = set(raw.unique()) - _KNOWN_RAW_LABELS
    if unknown:
        raise ValueError(f"Unrecognized label value(s), refusing to normalize: {sorted(unknown)}")
    return raw.replace(_ALL_MOJIBAKE_TO_CANONICAL)


def _require_columns(chunk: pd.DataFrame) -> None:
    missing = [c for c in REQUIRED_RAW_COLUMNS if c not in chunk.columns]
    if missing:
        raise ValueError(f"Missing required topology column(s): {missing}")


def _is_valid_ip(value: object) -> bool:
    if pd.isna(value):
        return False
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _valid_port_mask(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    return numeric.notna() & (numeric >= MIN_PORT) & (numeric <= MAX_PORT) & (numeric == numeric.round())


def drop_blank_rows(chunk: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop rows where every column is empty (the verified
    Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv trailing-blank-row
    artifact) -- never treated as traffic."""
    blank_mask = chunk.isna().all(axis=1)
    return chunk.loc[~blank_mask].copy(), int(blank_mask.sum())


def clean_chunk(chunk: pd.DataFrame) -> tuple[pd.DataFrame, CleaningStats]:
    _require_columns(chunk)
    stats = CleaningStats(raw_rows=len(chunk))

    chunk, blank_rows = drop_blank_rows(chunk)
    stats.blank_rows = blank_rows

    valid_ip = chunk["Source IP"].map(_is_valid_ip) & chunk["Destination IP"].map(_is_valid_ip)
    stats.invalid_ip_rows = int((~valid_ip).sum())
    chunk = chunk.loc[valid_ip].copy()

    valid_port = _valid_port_mask(chunk["Source Port"]) & _valid_port_mask(chunk["Destination Port"])
    stats.invalid_port_rows = int((~valid_port).sum())
    chunk = chunk.loc[valid_port].copy()

    parsed_timestamp = pd.to_datetime(chunk["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    valid_timestamp = parsed_timestamp.notna()
    stats.invalid_timestamp_rows = int((~valid_timestamp).sum())
    chunk = chunk.loc[valid_timestamp].copy()
    chunk["Timestamp"] = parsed_timestamp.loc[valid_timestamp]

    chunk["Source Port"] = pd.to_numeric(chunk["Source Port"], errors="raise").astype("int64")
    chunk["Destination Port"] = pd.to_numeric(chunk["Destination Port"], errors="raise").astype("int64")
    chunk["Protocol"] = pd.to_numeric(chunk["Protocol"], errors="raise").astype("int64")
    chunk["Total Length of Fwd Packets"] = pd.to_numeric(
        chunk["Total Length of Fwd Packets"], errors="coerce"
    ).fillna(0)
    chunk["Total Length of Bwd Packets"] = pd.to_numeric(
        chunk["Total Length of Bwd Packets"], errors="coerce"
    ).fillna(0)

    chunk["original_label"] = chunk["Label"]
    chunk["canonical_label"] = normalize_topology_labels(chunk["Label"])
    chunk["traffic_class"] = chunk["canonical_label"].map(traffic_class)
    chunk = chunk.drop(columns=["Label"])

    stats.valid_rows = len(chunk)
    return chunk, stats
