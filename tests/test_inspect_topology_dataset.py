"""Validates the topology inspector against small synthetic fixtures with
known properties (a valid row, a malformed IP, an invalid port, an
unexpected protocol, an unparseable timestamp, and a schema mismatch) —
not the real GeneratedLabelledFlows dataset. Proves the inspector's logic
is trustworthy for the Phase 2 stop-condition report.
"""

import pandas as pd
import pytest

from ml.preprocessing.inspect_topology_dataset import (
    REQUIRED_TOPOLOGY_FIELDS,
    check_schema_consistency,
    inspect_topology_csv,
)


def _write_csv(tmp_path, name, df):
    data_dir = tmp_path / "raw_labelled_flows"
    data_dir.mkdir(exist_ok=True)
    path = data_dir / name
    df.to_csv(path, index=False)
    return data_dir, path


def test_reports_all_required_fields_present(tmp_path):
    df = pd.DataFrame(
        {
            "Flow ID": ["a-b-1-2-6"],
            " Source IP": ["192.168.10.5"],
            " Source Port": [443],
            " Destination IP": ["104.16.28.216"],
            " Destination Port": [80],
            " Protocol": [6],
            " Timestamp": ["3/7/2017 08:55:58"],
            " Label": ["BENIGN"],
        }
    )
    data_dir, path = _write_csv(tmp_path, "sample.csv", df)
    report = inspect_topology_csv(path, data_dir)

    assert report.load_error is None
    assert {fp.requested_name for fp in report.field_presence if fp.present} == set(
        REQUIRED_TOPOLOGY_FIELDS
    )
    assert report.validation_issues == []


def test_detects_missing_required_field(tmp_path):
    df = pd.DataFrame({" Source IP": ["192.168.10.5"], " Label": ["BENIGN"]})
    data_dir, path = _write_csv(tmp_path, "sample.csv", df)
    report = inspect_topology_csv(path, data_dir)

    by_name = {fp.requested_name: fp for fp in report.field_presence}
    assert by_name["Source IP"].present is True
    assert by_name["Destination IP"].present is False
    assert by_name["Flow ID"].present is False


def test_detects_malformed_ip_and_invalid_port(tmp_path):
    df = pd.DataFrame(
        {
            "Flow ID": ["a", "b"],
            " Source IP": ["192.168.10.5", "not-an-ip"],
            " Source Port": [443, 70000],
            " Destination IP": ["104.16.28.216", "104.16.28.216"],
            " Destination Port": [80, 80],
            " Protocol": [6, 6],
            " Timestamp": ["3/7/2017 08:55:58", "3/7/2017 08:56:01"],
            " Label": ["BENIGN", "BENIGN"],
        }
    )
    data_dir, path = _write_csv(tmp_path, "sample.csv", df)
    report = inspect_topology_csv(path, data_dir)

    checks = {issue.check: issue for issue in report.validation_issues}
    assert any("Source IP" in c and "malformed" in c for c in checks)
    assert any("Source Port" in c for c in checks)


def test_detects_unexpected_protocol_and_bad_timestamp(tmp_path):
    df = pd.DataFrame(
        {
            "Flow ID": ["a"],
            " Source IP": ["192.168.10.5"],
            " Source Port": [443],
            " Destination IP": ["104.16.28.216"],
            " Destination Port": [80],
            " Protocol": [9999],
            " Timestamp": ["not-a-timestamp"],
            " Label": ["BENIGN"],
        }
    )
    data_dir, path = _write_csv(tmp_path, "sample.csv", df)
    report = inspect_topology_csv(path, data_dir)

    checks = [issue.check for issue in report.validation_issues]
    assert any("unexpected protocol" in c for c in checks)
    assert any("unparseable timestamp" in c for c in checks)


def test_schema_consistency_detects_mismatch(tmp_path):
    df_a = pd.DataFrame({"Flow ID": ["a"], " Label": ["BENIGN"]})
    df_b = pd.DataFrame({"Flow ID": ["b"], " Source IP": ["1.2.3.4"], " Label": ["BENIGN"]})
    data_dir, _ = _write_csv(tmp_path, "a.csv", df_a)
    _write_csv(tmp_path, "b.csv", df_b)

    report_a = inspect_topology_csv(data_dir / "a.csv", data_dir)
    report_b = inspect_topology_csv(data_dir / "b.csv", data_dir)

    ok, msg = check_schema_consistency([report_a, report_b])
    assert ok is False
    assert "b.csv" in msg


def test_schema_consistency_passes_for_matching_files(tmp_path):
    df = pd.DataFrame({"Flow ID": ["a"], " Label": ["BENIGN"]})
    data_dir, _ = _write_csv(tmp_path, "a.csv", df)
    _write_csv(tmp_path, "b.csv", df)

    report_a = inspect_topology_csv(data_dir / "a.csv", data_dir)
    report_b = inspect_topology_csv(data_dir / "b.csv", data_dir)

    ok, msg = check_schema_consistency([report_a, report_b])
    assert ok is True
    assert "identical" in msg
