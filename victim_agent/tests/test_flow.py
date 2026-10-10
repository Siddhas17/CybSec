from __future__ import annotations

import dataclasses
import json
import math
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP

from victim_agent import capture, flow

T0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)


def _pkt(source_ip, source_port, destination_ip, destination_port, protocol, length=100, timestamp=T0):
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "length": length,
    }


def _tcp_pkt(source_ip, source_port, destination_ip, destination_port, length, timestamp, flags, window, header_len=20, payload_len=0):
    d = _pkt(source_ip, source_port, destination_ip, destination_port, "TCP", length=length, timestamp=timestamp)
    d.update(tcp_flags=flags, tcp_window=window, transport_header_length=header_len, tcp_payload_length=payload_len)
    return d


# The exact 67 CICIDS2017 feature names/order this project's trained
# autoencoder/KNN require (ml/models/artifacts/autoencoder/feature_names.json),
# copied independently here (not imported from flow.py) so this test can
# actually catch flow.CICIDS_FEATURE_NAMES drifting out of sync.
EXPECTED_CICIDS_FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Subflow Fwd Bytes", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def _assert_no_nan_or_inf(features: dict[str, float]) -> None:
    for name, value in features.items():
        assert not math.isnan(value), f"{name} is NaN"
        assert not math.isinf(value), f"{name} is infinite"


# --- make_flow_key -------------------------------------------------------


def test_make_flow_key_is_symmetric_for_forward_and_reverse():
    forward = flow.make_flow_key("192.168.1.6", 53386, "20.184.175.13", 443, "TCP")
    reverse = flow.make_flow_key("20.184.175.13", 443, "192.168.1.6", 53386, "TCP")

    assert forward == reverse


def test_make_flow_key_differs_by_protocol():
    tcp_key = flow.make_flow_key("192.168.1.6", 53386, "20.184.175.13", 443, "TCP")
    udp_key = flow.make_flow_key("192.168.1.6", 53386, "20.184.175.13", 443, "UDP")

    assert tcp_key != udp_key


# --- forward/reverse grouping ---------------------------------------------


def test_forward_and_reverse_packets_join_same_flow():
    packets = [
        _pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP"),
        _pkt("20.184.175.13", 443, "192.168.1.6", 53386, "TCP"),
    ]

    flows = flow.reconstruct_flows(packets)

    assert len(flows) == 1
    assert flows[0].total_packets == 2
    assert flows[0].forward_packets == 1
    assert flows[0].backward_packets == 1


def test_multiple_independent_flows_stay_separate():
    packets = [
        _pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP"),
        _pkt("192.168.1.6", 60000, "8.8.8.8", 53, "UDP"),
        _pkt("192.168.1.6", 53400, "1.1.1.1", 443, "TCP"),
    ]

    flows = flow.reconstruct_flows(packets)

    assert len(flows) == 3


# --- packet/byte counts and duration ---------------------------------------


def test_packet_and_byte_counts_accumulate_per_direction():
    packets = [
        _pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP", length=100),
        _pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP", length=200),
        _pkt("20.184.175.13", 443, "192.168.1.6", 53386, "TCP", length=1400),
    ]

    [flow_record] = flow.reconstruct_flows(packets)

    assert flow_record.total_packets == 3
    assert flow_record.forward_packets == 2
    assert flow_record.backward_packets == 1
    assert flow_record.total_bytes == 1700
    assert flow_record.forward_bytes == 300
    assert flow_record.backward_bytes == 1400


def test_duration_spans_min_and_max_timestamp_regardless_of_arrival_order():
    t_mid = T0 + timedelta(seconds=2)
    t_late = T0 + timedelta(seconds=5)
    packets = [
        _pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP", timestamp=t_mid),
        _pkt("20.184.175.13", 443, "192.168.1.6", 53386, "TCP", timestamp=T0),
        _pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP", timestamp=t_late),
    ]

    [flow_record] = flow.reconstruct_flows(packets)

    assert flow_record.start_timestamp == T0
    assert flow_record.end_timestamp == t_late
    assert flow_record.duration_seconds == 5.0


def test_single_packet_flow_has_zero_duration():
    [flow_record] = flow.reconstruct_flows([_pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP")])

    assert flow_record.duration_seconds == 0.0


# --- protocol handling -------------------------------------------------------


def test_udp_flow_tracks_like_tcp():
    packets = [
        _pkt("192.168.1.6", 60000, "8.8.8.8", 53, "UDP", length=64),
        _pkt("8.8.8.8", 53, "192.168.1.6", 60000, "UDP", length=512),
    ]

    [flow_record] = flow.reconstruct_flows(packets)

    assert flow_record.protocol == "UDP"
    assert flow_record.forward_bytes == 64
    assert flow_record.backward_bytes == 512


def test_icmp_flow_has_no_ports_but_still_groups_bidirectionally():
    packets = [
        _pkt("192.168.1.6", None, "1.1.1.1", None, "ICMP", length=64),
        _pkt("1.1.1.1", None, "192.168.1.6", None, "ICMP", length=64),
    ]

    flows = flow.reconstruct_flows(packets)

    assert len(flows) == 1
    assert flows[0].source_port is None
    assert flows[0].destination_port is None
    assert flows[0].total_packets == 2


# --- malformed / incomplete input -------------------------------------------


@pytest.mark.parametrize(
    "bad_packet",
    [
        {},
        {"source_ip": "192.168.1.6"},  # missing destination_ip/protocol/timestamp
        {"source_ip": "", "destination_ip": "1.1.1.1", "protocol": "TCP", "timestamp": T0},
        {"source_ip": "192.168.1.6", "destination_ip": "1.1.1.1", "protocol": "TCP", "timestamp": None},
        None,
        "not a packet",
        123,
    ],
)
def test_malformed_or_incomplete_metadata_is_skipped_without_raising(bad_packet):
    tracker = flow.FlowTracker()

    result = tracker.add(bad_packet)

    assert result is None
    assert tracker.flows() == []


def test_malformed_packet_does_not_disturb_earlier_valid_flows():
    tracker = flow.FlowTracker()
    tracker.add(_pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP"))

    tracker.add({"garbage": True})

    assert len(tracker.flows()) == 1
    assert tracker.flows()[0].total_packets == 1


def test_empty_input_produces_no_flows():
    assert flow.reconstruct_flows([]) == []


# --- interop with capture.extract_packet_metadata() -------------------------


def test_consumes_dict_produced_from_capture_extract_packet_metadata():
    scapy_packet = IP(src="192.168.1.6", dst="20.184.175.13") / TCP(sport=53386, dport=443)
    metadata = capture.extract_packet_metadata(scapy_packet)
    assert metadata is not None

    tracker = flow.FlowTracker()
    result = tracker.add(dataclasses.asdict(metadata))

    assert result is not None
    assert result.protocol == "TCP"
    assert result.total_packets == 1


def test_consumes_icmp_metadata_from_capture_module():
    scapy_packet = IP(src="192.168.1.6", dst="1.1.1.1") / ICMP()
    metadata = capture.extract_packet_metadata(scapy_packet)
    assert metadata is not None
    assert metadata.source_port is None

    tracker = flow.FlowTracker()
    result = tracker.add(dataclasses.asdict(metadata))

    assert result is not None
    assert result.protocol == "ICMP"
    assert result.source_port is None


# --- to_cicids_features() ----------------------------------------------------
#
# Fixture: a 4-packet TCP flow with 2s gaps between every consecutive
# packet (T0, T0+2s, T0+4s, T0+6s), alternating fwd/bwd/fwd/bwd, with
# lengths chosen so every statistic is an exact, hand-checkable number
# (population std of [100, 300] is exactly 100.0, etc.) rather than a
# repeating decimal that would need pytest.approx for every assertion.


def _tcp_flow_fixture() -> flow.Flow:
    packets = [
        _tcp_pkt("192.168.1.6", 53386, "20.184.175.13", 443, length=100, timestamp=T0, flags="S", window=64240, header_len=20, payload_len=0),
        _tcp_pkt("20.184.175.13", 443, "192.168.1.6", 53386, length=100, timestamp=T0 + timedelta(seconds=2), flags="SA", window=65535, header_len=20, payload_len=0),
        _tcp_pkt("192.168.1.6", 53386, "20.184.175.13", 443, length=300, timestamp=T0 + timedelta(seconds=4), flags="PA", window=64240, header_len=20, payload_len=260),
        _tcp_pkt("20.184.175.13", 443, "192.168.1.6", 53386, length=300, timestamp=T0 + timedelta(seconds=6), flags="A", window=65535, header_len=20, payload_len=260),
    ]
    [flow_record] = flow.reconstruct_flows(packets)
    return flow_record


def test_cicids_features_exact_names_and_count():
    features = _tcp_flow_fixture().to_cicids_features()

    assert len(features) == 67
    assert set(features.keys()) == set(EXPECTED_CICIDS_FEATURE_NAMES)


def test_cicids_features_exact_order():
    features = _tcp_flow_fixture().to_cicids_features()

    assert list(features.keys()) == EXPECTED_CICIDS_FEATURE_NAMES
    assert list(flow.CICIDS_FEATURE_NAMES) == EXPECTED_CICIDS_FEATURE_NAMES


def test_cicids_feature_names_match_autoencoder_artifact_order():
    artifact_path = (
        Path(__file__).resolve().parents[2]
        / "ml"
        / "models"
        / "artifacts"
        / "autoencoder"
        / "feature_names.json"
    )
    artifact_feature_names = json.loads(artifact_path.read_text(encoding="utf-8"))

    assert list(flow.CICIDS_FEATURE_NAMES) == artifact_feature_names


def test_cicids_features_forward_and_backward_packet_counts():
    features = _tcp_flow_fixture().to_cicids_features()

    assert features["Total Fwd Packets"] == 2.0
    assert features["Total Backward Packets"] == 2.0
    assert features["Total Length of Fwd Packets"] == 400.0
    assert features["Total Length of Bwd Packets"] == 400.0


def test_cicids_features_packet_length_statistics():
    features = _tcp_flow_fixture().to_cicids_features()

    assert features["Fwd Packet Length Max"] == 300.0
    assert features["Fwd Packet Length Min"] == 100.0
    assert features["Fwd Packet Length Mean"] == 200.0
    assert features["Fwd Packet Length Std"] == 100.0
    assert features["Bwd Packet Length Max"] == 300.0
    assert features["Bwd Packet Length Min"] == 100.0
    assert features["Bwd Packet Length Mean"] == 200.0
    assert features["Bwd Packet Length Std"] == 100.0
    assert features["Min Packet Length"] == 100.0
    assert features["Max Packet Length"] == 300.0
    assert features["Packet Length Mean"] == 200.0
    assert features["Packet Length Std"] == 100.0
    assert features["Packet Length Variance"] == 10000.0


def test_cicids_features_flow_duration_in_microseconds():
    features = _tcp_flow_fixture().to_cicids_features()

    assert features["Flow Duration"] == 6_000_000.0  # T0 -> T0+6s


def test_cicids_features_flow_iat_statistics():
    features = _tcp_flow_fixture().to_cicids_features()

    # 3 consecutive 2s gaps -> every diff is identical: mean=2e6us, std=0.
    assert features["Flow IAT Mean"] == 2_000_000.0
    assert features["Flow IAT Std"] == 0.0
    assert features["Flow IAT Max"] == 2_000_000.0
    assert features["Flow IAT Min"] == 2_000_000.0


def test_cicids_features_forward_iat_statistics():
    features = _tcp_flow_fixture().to_cicids_features()

    # Forward packets are 4s apart (T0 and T0+4s) -- a single interval.
    assert features["Fwd IAT Total"] == 4_000_000.0
    assert features["Fwd IAT Mean"] == 4_000_000.0
    assert features["Fwd IAT Std"] == 0.0
    assert features["Fwd IAT Max"] == 4_000_000.0
    assert features["Fwd IAT Min"] == 4_000_000.0


def test_cicids_features_backward_iat_statistics():
    features = _tcp_flow_fixture().to_cicids_features()

    # Backward packets are 4s apart (T0+2s and T0+6s) -- a single interval.
    assert features["Bwd IAT Total"] == 4_000_000.0
    assert features["Bwd IAT Mean"] == 4_000_000.0
    assert features["Bwd IAT Std"] == 0.0
    assert features["Bwd IAT Max"] == 4_000_000.0
    assert features["Bwd IAT Min"] == 4_000_000.0


def test_cicids_features_packet_rates():
    features = _tcp_flow_fixture().to_cicids_features()

    assert features["Flow Bytes/s"] == pytest.approx(800.0 / 6.0)
    assert features["Flow Packets/s"] == pytest.approx(4.0 / 6.0)
    assert features["Fwd Packets/s"] == pytest.approx(2.0 / 6.0)
    assert features["Bwd Packets/s"] == pytest.approx(2.0 / 6.0)


def test_cicids_features_tcp_flag_counts():
    features = _tcp_flow_fixture().to_cicids_features()

    # Flags observed: S, SA, PA, A -- SYN set on S+SA (2), ACK set on SA+PA+A (3), PSH set on PA (1).
    assert features["SYN Flag Count"] == 2.0
    assert features["ACK Flag Count"] == 3.0
    assert features["PSH Flag Count"] == 1.0
    assert features["FIN Flag Count"] == 0.0
    assert features["RST Flag Count"] == 0.0
    assert features["URG Flag Count"] == 0.0
    assert features["CWE Flag Count"] == 0.0
    assert features["ECE Flag Count"] == 0.0
    assert features["Fwd PSH Flags"] == 1.0  # only the forward PA packet
    assert features["Fwd URG Flags"] == 0.0


def test_cicids_features_tcp_header_lengths():
    features = _tcp_flow_fixture().to_cicids_features()

    assert features["Fwd Header Length"] == 40.0  # 20 + 20
    assert features["Bwd Header Length"] == 40.0
    assert features["min_seg_size_forward"] == 20.0


def test_cicids_features_tcp_window_values():
    features = _tcp_flow_fixture().to_cicids_features()

    # Init window = the *first* packet's window in that direction (T0 fwd, T0+2s bwd).
    assert features["Init_Win_bytes_forward"] == 64240.0
    assert features["Init_Win_bytes_backward"] == 65535.0


def test_cicids_features_payload_data_packet_count():
    features = _tcp_flow_fixture().to_cicids_features()

    # Only the second forward packet (PA, payload_len=260) carries data.
    assert features["act_data_pkt_fwd"] == 1.0


def test_cicids_features_single_packet_flow_is_safe():
    [flow_record] = flow.reconstruct_flows([_tcp_pkt("192.168.1.6", 53386, "20.184.175.13", 443, length=100, timestamp=T0, flags="S", window=64240)])

    features = flow_record.to_cicids_features()

    assert features["Total Fwd Packets"] == 1.0
    assert features["Total Backward Packets"] == 0.0
    assert features["Flow Duration"] == 0.0
    assert features["Flow IAT Mean"] == 0.0
    assert features["Fwd Packet Length Std"] == 0.0
    assert features["Down/Up Ratio"] == 0.0
    assert features["Init_Win_bytes_backward"] == -1.0  # no backward packet at all
    _assert_no_nan_or_inf(features)


def test_cicids_features_empty_flow_is_safe():
    bare_flow = flow.Flow(
        source_ip="192.168.1.6",
        destination_ip="20.184.175.13",
        source_port=53386,
        destination_port=443,
        protocol="TCP",
        start_timestamp=T0,
        end_timestamp=T0,
    )

    features = bare_flow.to_cicids_features()

    assert features["Total Fwd Packets"] == 0.0
    assert features["Total Backward Packets"] == 0.0
    assert features["Average Packet Size"] == 0.0
    assert features["Down/Up Ratio"] == 0.0
    assert features["Init_Win_bytes_forward"] == -1.0
    assert features["Init_Win_bytes_backward"] == -1.0
    _assert_no_nan_or_inf(features)


def test_cicids_features_incomplete_metadata_falls_back_safely():
    # Plain packets with none of the TCP-extended fields at all (as
    # produced by an older/minimal capture.py caller) -- must not crash,
    # and every TCP-specific feature must reflect "not observed", not a
    # fabricated value.
    packets = [
        _pkt("192.168.1.6", 53386, "20.184.175.13", 443, "TCP", length=100, timestamp=T0),
        _pkt("20.184.175.13", 443, "192.168.1.6", 53386, "TCP", length=100, timestamp=T0 + timedelta(seconds=1)),
    ]
    [flow_record] = flow.reconstruct_flows(packets)

    features = flow_record.to_cicids_features()

    assert features["SYN Flag Count"] == 0.0
    assert features["Fwd Header Length"] == 0.0
    assert features["Init_Win_bytes_forward"] == -1.0
    assert features["min_seg_size_forward"] == 0.0
    _assert_no_nan_or_inf(features)


def test_cicids_features_udp_flow():
    packets = [
        _pkt("192.168.1.6", 60000, "8.8.8.8", 53, "UDP", length=64, timestamp=T0) | {"transport_header_length": 8, "tcp_payload_length": 56},
        _pkt("8.8.8.8", 53, "192.168.1.6", 60000, "UDP", length=512, timestamp=T0 + timedelta(seconds=1)) | {"transport_header_length": 8, "tcp_payload_length": 504},
    ]
    [flow_record] = flow.reconstruct_flows(packets)

    features = flow_record.to_cicids_features()

    assert features["Total Fwd Packets"] == 1.0
    assert features["Total Backward Packets"] == 1.0
    assert features["Fwd Header Length"] == 8.0
    assert features["Bwd Header Length"] == 8.0
    assert features["act_data_pkt_fwd"] == 1.0  # forward packet's payload_len=56 > 0
    # UDP has no TCP flags/window -- these must be the documented sentinels, not fabricated.
    assert features["SYN Flag Count"] == 0.0
    assert features["Init_Win_bytes_forward"] == -1.0
    assert features["Init_Win_bytes_backward"] == -1.0
    _assert_no_nan_or_inf(features)


def test_cicids_features_icmp_flow():
    packets = [
        _pkt("192.168.1.6", None, "1.1.1.1", None, "ICMP", length=64, timestamp=T0),
        _pkt("1.1.1.1", None, "192.168.1.6", None, "ICMP", length=64, timestamp=T0 + timedelta(seconds=1)),
    ]
    [flow_record] = flow.reconstruct_flows(packets)

    features = flow_record.to_cicids_features()

    assert features["Destination Port"] == -1.0  # ICMP has no ports
    assert features["Total Fwd Packets"] == 1.0
    assert features["Total Backward Packets"] == 1.0
    assert features["Init_Win_bytes_forward"] == -1.0
    assert features["Init_Win_bytes_backward"] == -1.0
    assert features["SYN Flag Count"] == 0.0
    assert features["Fwd Header Length"] == 0.0  # never observed for ICMP -- not fabricated
    assert features["min_seg_size_forward"] == 0.0  # documented divergence -- see flow.py module docstring
    _assert_no_nan_or_inf(features)


def test_cicids_features_never_nan_or_infinite_across_flow_types():
    _assert_no_nan_or_inf(_tcp_flow_fixture().to_cicids_features())

    single = flow.reconstruct_flows([_tcp_pkt("192.168.1.6", 1, "1.1.1.1", 2, length=100, timestamp=T0, flags="S", window=1000)])[0]
    _assert_no_nan_or_inf(single.to_cicids_features())

    udp = flow.reconstruct_flows([_pkt("192.168.1.6", 1, "1.1.1.1", 2, "UDP", length=64, timestamp=T0)])[0]
    _assert_no_nan_or_inf(udp.to_cicids_features())

    icmp = flow.reconstruct_flows([_pkt("192.168.1.6", None, "1.1.1.1", None, "ICMP", length=64, timestamp=T0)])[0]
    _assert_no_nan_or_inf(icmp.to_cicids_features())
