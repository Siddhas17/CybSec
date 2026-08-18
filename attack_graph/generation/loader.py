"""Chunked, column-limited CSV reading for the topology dataset.

Reads only the 10 columns attack_graph.schemas.REQUIRED_RAW_COLUMNS needs
(out of 85 in the raw files) and yields fixed-size chunks, so peak memory
stays bounded regardless of file size -- the full Wednesday file is 272MB
with ~693K rows, but only ~10 numeric/short-string columns of it are ever
materialized here.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pandas as pd

from attack_graph.schemas import REQUIRED_RAW_COLUMNS

_REQUIRED_STRIPPED = set(REQUIRED_RAW_COLUMNS)


def discover_csv_files(raw_dir: Path) -> list[Path]:
    return sorted(raw_dir.glob("*.csv"))


def _select_column(name: str) -> bool:
    return name.strip() in _REQUIRED_STRIPPED


def _detect_encoding(csv_path: Path) -> str:
    """utf-8 if the whole file decodes cleanly, else latin1 (same
    utf-8-then-latin1 fallback used by ml/preprocessing/inspect_dataset.py
    and ml/preprocessing/inspect_topology_dataset.py).

    Verified 2026-08-18: Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
    in this distribution encodes its "Web Attack" label separator as a raw
    0x96 byte -- confirmed confined to the Label column (2,180 occurrences,
    all inside "Web Attack" text) -- which is invalid UTF-8. This is a
    *different* byte-level corruption than the U+FFFD sequence
    ml/preprocessing/labels.py handles for the MachineLearningCSV variant;
    see attack_graph.generation.cleaner.TOPOLOGY_MOJIBAKE_TO_CANONICAL.
    Read as whole-file bytes once (not per-chunk) since the chunked reader
    needs one fixed encoding decided upfront.
    """
    try:
        csv_path.read_bytes().decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "latin1"


def iter_topology_chunks(csv_path: Path, chunk_size: int) -> Iterator[pd.DataFrame]:
    """Yield DataFrame chunks with stripped, canonical column names.

    Column dtypes are intentionally left to pandas' inference (they vary
    file-to-file, e.g. int64 vs float64 for the same column -- see
    docs/dataset_inspection_labelled_flows.md); attack_graph.generation.cleaner
    coerces everything it needs with pd.to_numeric rather than relying on
    the inferred dtype.
    """
    encoding = _detect_encoding(csv_path)
    reader = pd.read_csv(
        csv_path,
        usecols=_select_column,
        chunksize=chunk_size,
        low_memory=False,
        encoding=encoding,
    )
    for chunk in reader:
        chunk.columns = [c.strip() for c in chunk.columns]
        yield chunk
