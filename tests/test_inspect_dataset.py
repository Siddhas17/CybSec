"""Validates the generic CSV inspector against a small synthetic fixture with
known properties (missing values, an infinite value, a duplicate row, a
constant column, and a label column) — not the real CICIDS2017 dataset,
which isn't acquired yet. This only proves the inspector's logic is correct
so it can be trusted once real files land in ml/datasets/raw/.
"""

import numpy as np
import pandas as pd
import pytest

from ml.preprocessing.inspect_dataset import inspect_csv, render_markdown, _find_label_column


@pytest.fixture
def synthetic_csv(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    df = pd.DataFrame(
        {
            " Destination Port": [80, 443, 80, 22, 80],
            "Flow Duration": [100, 200, 100, np.nan, 300],
            "Flow Bytes/s": [1.5, np.inf, 1.5, 4.0, 5.0],
            "Constant Col": [1, 1, 1, 1, 1],
            " Label": ["BENIGN", "DDoS", "BENIGN", "PortScan", "BENIGN"],
        }
    )
    path = raw_dir / "sample.csv"
    df.to_csv(path, index=False)
    return raw_dir, path


def test_find_label_column_variants():
    assert _find_label_column(["a", "Label"]) == "Label"
    assert _find_label_column(["a", " Label "]) == " Label "
    assert _find_label_column(["a", "Attack_Type"]) == "Attack_Type"
    assert _find_label_column(["a", "b"]) is None


def test_inspect_csv_detects_known_properties(synthetic_csv):
    raw_dir, path = synthetic_csv
    report = inspect_csv(path, raw_dir)

    assert report.load_error is None
    assert report.num_rows == 5
    assert report.num_columns == 5
    assert report.duplicate_rows == 1  # rows 0 and 2 are identical

    assert report.label_column == " Label"
    assert report.label_distribution == {"BENIGN": 3, "DDoS": 1, "PortScan": 1}

    by_name = {c.name: c for c in report.columns}
    assert by_name["Flow Duration"].missing_count == 1
    assert by_name["Flow Bytes/s"].infinite_count == 1
    assert by_name["Constant Col"].is_constant is True
    assert by_name[" Destination Port"].has_stray_whitespace is True
    assert by_name["Flow Duration"].has_stray_whitespace is False


def test_render_markdown_handles_empty_and_nonempty(synthetic_csv):
    raw_dir, path = synthetic_csv
    report = inspect_csv(path, raw_dir)

    empty_md = render_markdown([])
    assert "No CSV files found" in empty_md

    md = render_markdown([report])
    assert "sample.csv" in md
    assert "BENIGN" in md
    assert "Constant Col" in md
