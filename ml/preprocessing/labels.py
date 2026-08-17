"""Canonical label normalization for the CICIDS2017 ``Label`` column.

The raw label column contains three "Web Attack" values with a literal
U+FFFD replacement character baked into the source CSV bytes (confirmed at
the byte level in Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv —
not an artifact of how this project reads the file; see
docs/dataset_inspection.md). This module maps only those three confirmed
corrupted strings to a canonical spelling. Every other label must already
be a known-clean value — anything outside both sets raises instead of being
silently passed through or guessed at.
"""

from __future__ import annotations

import pandas as pd

# Corrupted-byte-sequence label -> canonical label. The separator between
# "Web Attack" and the subtype decodes as U+FFFD (raw file bytes
# b'\xef\xbf\xbd') in all three variants — almost certainly an en dash
# mangled during the dataset's original export. Mapped by exact string
# match only; no broad encoding re-conversion is applied.
MOJIBAKE_TO_CANONICAL: dict[str, str] = {
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack � XSS": "Web Attack - XSS",
    "Web Attack � Sql Injection": "Web Attack - Sql Injection",
}

# Labels observed in the raw files that are already clean (no mojibake).
CLEAN_LABELS: set[str] = {
    "BENIGN",
    "DDoS",
    "PortScan",
    "Bot",
    "Infiltration",
    "FTP-Patator",
    "SSH-Patator",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "Heartbleed",
}

KNOWN_RAW_LABELS: set[str] = CLEAN_LABELS | set(MOJIBAKE_TO_CANONICAL)


def normalize_labels(raw: pd.Series) -> pd.Series:
    """Map raw label strings to their canonical form.

    Raises ValueError listing any value that is neither a known-clean label
    nor a confirmed mojibake variant — normalization never guesses at an
    unfamiliar string.
    """
    unknown = set(raw.unique()) - KNOWN_RAW_LABELS
    if unknown:
        raise ValueError(f"Unrecognized label value(s), refusing to normalize: {sorted(unknown)}")
    return raw.replace(MOJIBAKE_TO_CANONICAL)
