"""Unit tests for attack_graph.generation.cleaner: blank-row removal,
day-first timestamp parsing, IP/port validation, and label/traffic_class
derivation -- each using small synthetic fixtures with known properties."""

import pandas as pd
import pytest

from attack_graph.generation.cleaner import clean_chunk, drop_blank_rows


def _base_rows(n=1):
    return {
        "Flow ID": [f"flow-{i}" for i in range(n)],
        "Source IP": ["192.168.10.5"] * n,
        "Source Port": [443] * n,
        "Destination IP": ["104.16.28.216"] * n,
        "Destination Port": [80] * n,
        "Protocol": [6] * n,
        "Timestamp": ["3/7/2017 08:55"] * n,
        "Total Length of Fwd Packets": [100] * n,
        "Total Length of Bwd Packets": [50] * n,
        "Label": ["BENIGN"] * n,
    }


def test_drop_blank_rows_removes_fully_empty_rows_only():
    df = pd.DataFrame(_base_rows(2))
    blank = pd.DataFrame([{c: pd.NA for c in df.columns}])
    combined = pd.concat([df, blank], ignore_index=True)

    cleaned, blank_count = drop_blank_rows(combined)
    assert blank_count == 1
    assert len(cleaned) == 2


def test_clean_chunk_reports_zero_drops_for_fully_valid_data():
    df = pd.DataFrame(_base_rows(3))
    cleaned, stats = clean_chunk(df)

    assert stats.raw_rows == 3
    assert stats.blank_rows == 0
    assert stats.invalid_ip_rows == 0
    assert stats.invalid_port_rows == 0
    assert stats.invalid_timestamp_rows == 0
    assert stats.valid_rows == 3
    assert len(cleaned) == 3


def test_clean_chunk_parses_day_first_timestamps():
    rows = _base_rows(1)
    rows["Timestamp"] = ["03/07/2017 08:55:58"]  # day-first: 3 July 2017
    df = pd.DataFrame(rows)
    cleaned, _ = clean_chunk(df)

    ts = cleaned.iloc[0]["Timestamp"]
    assert ts.month == 7
    assert ts.day == 3
    assert ts.year == 2017


def test_clean_chunk_drops_malformed_ip():
    rows = _base_rows(2)
    rows["Source IP"] = ["192.168.10.5", "not-an-ip"]
    df = pd.DataFrame(rows)
    cleaned, stats = clean_chunk(df)

    assert stats.invalid_ip_rows == 1
    assert len(cleaned) == 1


def test_clean_chunk_drops_invalid_port():
    rows = _base_rows(2)
    rows["Destination Port"] = [80, 70000]
    df = pd.DataFrame(rows)
    cleaned, stats = clean_chunk(df)

    assert stats.invalid_port_rows == 1
    assert len(cleaned) == 1


def test_clean_chunk_preserves_numeric_protocol_values():
    rows = _base_rows(3)
    rows["Protocol"] = [6, 17, 0]
    df = pd.DataFrame(rows)
    cleaned, _ = clean_chunk(df)

    assert list(cleaned["Protocol"]) == [6, 17, 0]


def test_clean_chunk_derives_traffic_class_and_keeps_canonical_label():
    rows = _base_rows(2)
    rows["Label"] = ["BENIGN", "DDoS"]
    df = pd.DataFrame(rows)
    cleaned, _ = clean_chunk(df)

    assert list(cleaned["canonical_label"]) == ["BENIGN", "DDoS"]
    assert list(cleaned["traffic_class"]) == ["BENIGN", "ATTACK"]


def test_clean_chunk_normalizes_web_attack_mojibake():
    rows = _base_rows(1)
    rows["Label"] = ["Web Attack � Brute Force"]
    df = pd.DataFrame(rows)
    cleaned, _ = clean_chunk(df)

    assert cleaned.iloc[0]["canonical_label"] == "Web Attack - Brute Force"
    assert cleaned.iloc[0]["traffic_class"] == "ATTACK"


def test_clean_chunk_normalizes_topology_specific_0x96_mojibake():
    # This distribution's own corruption: a raw 0x96 byte (decoded as
    # U+0096 under the latin1 fallback), distinct from the U+FFFD variant
    # above -- verified in Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.
    rows = _base_rows(1)
    rows["Label"] = ["Web Attack \x96 Sql Injection"]
    df = pd.DataFrame(rows)
    cleaned, _ = clean_chunk(df)

    assert cleaned.iloc[0]["canonical_label"] == "Web Attack - Sql Injection"
    assert cleaned.iloc[0]["traffic_class"] == "ATTACK"


def test_clean_chunk_preserves_original_label_alongside_canonical():
    rows = _base_rows(1)
    rows["Label"] = ["Web Attack \x96 XSS"]
    df = pd.DataFrame(rows)
    cleaned, _ = clean_chunk(df)

    assert cleaned.iloc[0]["original_label"] == "Web Attack \x96 XSS"
    assert cleaned.iloc[0]["canonical_label"] == "Web Attack - XSS"


def test_clean_chunk_raises_on_unrecognized_label():
    rows = _base_rows(1)
    rows["Label"] = ["TotallyMadeUpAttack"]
    df = pd.DataFrame(rows)
    with pytest.raises(ValueError):
        clean_chunk(df)


def test_clean_chunk_raises_clear_error_on_missing_required_column():
    rows = _base_rows(1)
    del rows["Source IP"]
    df = pd.DataFrame(rows)
    with pytest.raises(ValueError, match="Source IP"):
        clean_chunk(df)
