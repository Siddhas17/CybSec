"""Section 16 unit tests: flow reconstruction and graph TTL/cleanup use
hand-built RawPacketEvent fixtures only -- never real network traffic
(section 16 explicitly forbids that in unit tests)."""

from __future__ import annotations

from sensor.collectors.base import RawPacketEvent, TcpFlags
from sensor.normalization.flow_reconstruction import FlowAccumulator

SRC, DST = "10.0.0.1", "10.0.0.2"
SPORT, DPORT = 54321, 443


def _pkt(ts, is_forward=True, protocol=6, flags=None, length=100, payload=60):
    src, dst, sport, dport = (SRC, DST, SPORT, DPORT) if is_forward else (DST, SRC, DPORT, SPORT)
    return RawPacketEvent(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=protocol,
        total_length=length,
        ip_header_length=20,
        transport_header_length=20 if protocol == 6 else 8,
        payload_length=payload,
        tcp_flags=flags if protocol == 6 else None,
        tcp_window=8192 if protocol == 6 else None,
    )


def test_bidirectional_packets_group_into_one_flow_until_both_sides_fin():
    acc = FlowAccumulator(idle_timeout_seconds=30, max_duration_seconds=300)
    assert acc.ingest(_pkt(0.0, True, flags=TcpFlags(syn=True))) == []
    assert acc.ingest(_pkt(0.1, False, flags=TcpFlags(syn=True, ack=True))) == []
    assert acc.ingest(_pkt(0.2, True, flags=TcpFlags(ack=True))) == []
    assert acc.ingest(_pkt(0.3, False, flags=TcpFlags(ack=True))) == []
    assert acc.ingest(_pkt(0.4, True, flags=TcpFlags(fin=True, ack=True))) == []

    completed = acc.ingest(_pkt(0.5, False, flags=TcpFlags(fin=True, ack=True)))
    assert len(completed) == 1
    flow = completed[0]
    assert flow.end_reason == "fin"
    assert len(flow.fwd_packets) == 3
    assert len(flow.bwd_packets) == 3
    assert flow.forward_ip == SRC and flow.backward_ip == DST
    assert acc.active_flow_count == 0


def test_rst_ends_flow_immediately_even_with_no_backward_packets():
    acc = FlowAccumulator()
    assert acc.ingest(_pkt(0.0, True, flags=TcpFlags(syn=True))) == []
    completed = acc.ingest(_pkt(0.05, True, flags=TcpFlags(rst=True)))
    assert len(completed) == 1
    assert completed[0].end_reason == "rst"
    assert len(completed[0].bwd_packets) == 0
    assert acc.active_flow_count == 0


def test_idle_timeout_splits_traffic_on_the_same_5_tuple_into_two_flows():
    acc = FlowAccumulator(idle_timeout_seconds=5.0, max_duration_seconds=1e9)
    assert acc.ingest(_pkt(0.0, True, protocol=17)) == []
    assert acc.ingest(_pkt(1.0, False, protocol=17)) == []

    # 100s later on the identical 5-tuple: the old flow must be closed out,
    # not silently merged into a single 100-second flow.
    completed = acc.ingest(_pkt(101.0, True, protocol=17))
    assert len(completed) == 1
    old_flow = completed[0]
    assert old_flow.end_reason == "idle_timeout"
    assert len(old_flow.fwd_packets) == 1
    assert len(old_flow.bwd_packets) == 1
    assert acc.active_flow_count == 1  # the new packet started a fresh flow epoch


def test_max_duration_forces_completion_of_a_long_lived_flow():
    acc = FlowAccumulator(idle_timeout_seconds=1e9, max_duration_seconds=10.0)
    assert acc.ingest(_pkt(0.0, True, protocol=17)) == []
    completed = acc.ingest(_pkt(15.0, True, protocol=17))
    assert len(completed) == 1
    assert completed[0].end_reason == "max_duration"
    assert len(completed[0].fwd_packets) == 2


def test_max_packets_caps_memory_on_a_pathological_flood():
    acc = FlowAccumulator(idle_timeout_seconds=1e9, max_duration_seconds=1e9, max_packets=3)
    assert acc.ingest(_pkt(0.0, True, protocol=17)) == []
    assert acc.ingest(_pkt(0.1, True, protocol=17)) == []
    completed = acc.ingest(_pkt(0.2, True, protocol=17))
    assert len(completed) == 1
    assert completed[0].end_reason == "max_packets"


def test_flush_idle_recovers_flows_that_never_receive_another_packet():
    acc = FlowAccumulator(idle_timeout_seconds=1.0)
    acc.ingest(_pkt(0.0, True, protocol=17))
    assert acc.active_flow_count == 1

    flushed = acc.flush_idle(now_ts=10.0)
    assert len(flushed) == 1
    assert flushed[0].end_reason == "idle_timeout"
    assert acc.active_flow_count == 0


def test_flush_all_force_completes_in_progress_flows_on_shutdown():
    acc = FlowAccumulator()
    acc.ingest(_pkt(0.0, True, protocol=17))
    acc.ingest(_pkt(0.0, "9.9.9.9" and True, protocol=6))  # a second, distinct flow (different port/proto)

    flushed = acc.flush_all()
    assert {f.end_reason for f in flushed} == {"flush"}
    assert acc.active_flow_count == 0
