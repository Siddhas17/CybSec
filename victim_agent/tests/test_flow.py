from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, UTC

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
