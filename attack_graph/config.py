"""Shared paths and constants for the attack graph module.

Mirrors the env-var-overridable pattern in ml/preprocessing/config.py so
both modules can be pointed at alternate directories (e.g. in tests) the
same way.
"""

from __future__ import annotations

import os
from pathlib import Path

from ml.preprocessing.config import DOCS_DIR, PROJECT_ROOT

TOPOLOGY_RAW_DIR = Path(
    os.environ.get(
        "TOPOLOGY_RAW_DIR", PROJECT_ROOT / "ml" / "datasets" / "raw_labelled_flows"
    )
)
GRAPH_OUTPUT_DIR = Path(
    os.environ.get("GRAPH_OUTPUT_DIR", PROJECT_ROOT / "attack_graph" / "output")
)

DEFAULT_CHUNK_SIZE = int(os.environ.get("GRAPH_CHUNK_SIZE", 100_000))

__all__ = ["TOPOLOGY_RAW_DIR", "GRAPH_OUTPUT_DIR", "DEFAULT_CHUNK_SIZE", "DOCS_DIR", "PROJECT_ROOT"]
