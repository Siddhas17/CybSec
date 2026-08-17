"""Shared paths and constants for the preprocessing pipeline.

Kept minimal and dependency-free (no dataset-specific assumptions) so it can
be imported by inspection, cleaning, and future live-inference code alike.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DATA_DIR = Path(os.environ.get("DATASET_RAW_DIR", PROJECT_ROOT / "ml" / "datasets" / "raw"))
PROCESSED_DATA_DIR = Path(
    os.environ.get("DATASET_PROCESSED_DIR", PROJECT_ROOT / "ml" / "datasets" / "processed")
)
MODEL_DIR = Path(os.environ.get("MODEL_DIR", PROJECT_ROOT / "ml" / "models"))
DOCS_DIR = PROJECT_ROOT / "docs"

RANDOM_SEED = int(os.environ.get("RANDOM_SEED", 42))
TRAIN_SPLIT = float(os.environ.get("TRAIN_SPLIT", 0.7))
VAL_SPLIT = float(os.environ.get("VAL_SPLIT", 0.15))
TEST_SPLIT = float(os.environ.get("TEST_SPLIT", 0.15))
