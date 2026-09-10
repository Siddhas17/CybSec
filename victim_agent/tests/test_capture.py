from __future__ import annotations

from types import SimpleNamespace

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from victim_agent import capture


def _iface(name: str, description: str, ip: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, description=description, ip=ip)


# --- extract_packet_metadata -------------------------------------------------


def test_extract_metadata_from_tcp_packet():
    packet = IP(src="192.168.1.6", dst="93.184.216.34") / TCP(sport=51820, dport=443)

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert meta.protocol == "TCP"
    assert meta.source_ip == "192.168.1.6"
    assert meta.destination_ip == "93.184.216.34"
    assert meta.source_port == 51820
    assert meta.destination_port == 443
    assert meta.length == len(packet)
    assert meta.timestamp is not None


def test_extract_metadata_from_udp_packet():
    packet = IP(src="192.168.1.6", dst="8.8.8.8") / UDP(sport=53000, dport=53)

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert meta.protocol == "UDP"
    assert meta.source_port == 53000
    assert meta.destination_port == 53


def test_extract_metadata_from_other_ip_packet_has_no_ports():
    packet = IP(src="192.168.1.6", dst="1.1.1.1") / ICMP()

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert meta.protocol == "ICMP"
    assert meta.source_port is None
    assert meta.destination_port is None


def test_extract_metadata_unknown_ip_protocol_number_is_labelled():
    packet = IP(src="192.168.1.6", dst="1.1.1.1", proto=253)  # reserved for experimentation -- not in our name table

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert meta.protocol == "IP-PROTO-253"


def test_extract_metadata_returns_none_for_non_ip_packet():
    packet = Ether() / ARP()

    assert capture.extract_packet_metadata(packet) is None


def test_extract_metadata_never_stores_payload_bytes():
    packet = IP(src="192.168.1.6", dst="93.184.216.34") / TCP(sport=51820, dport=443) / b"secret-payload"

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert not hasattr(meta, "payload")
    assert not hasattr(meta, "load")
    assert "secret-payload" not in repr(meta)


def test_extract_metadata_never_raises_on_malformed_packet():
    class _Explodes:
        def haslayer(self, _layer):
            raise RuntimeError("boom")

    assert capture.extract_packet_metadata(_Explodes()) is None


# --- find_wifi_interface ------------------------------------------------------


def test_find_wifi_interface_matches_description_and_requires_valid_ip():
    interfaces = [
        _iface("Ethernet", "Intel(R) Ethernet Connection", "169.254.114.117"),
        _iface("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", "192.168.1.6"),
    ]

    iface = capture.find_wifi_interface(interfaces)

    assert iface.name == "Wi-Fi"


def test_find_wifi_interface_rejects_link_local_wifi_direct_adapters():
    interfaces = [
        _iface("Local Area Connection* 2", "Microsoft Wi-Fi Direct Virtual Adapter #2", "169.254.183.67"),
        _iface("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", "192.168.1.6"),
    ]

    iface = capture.find_wifi_interface(interfaces)

    assert iface.ip == "192.168.1.6"


def test_find_wifi_interface_raises_when_none_qualify():
    interfaces = [
        _iface("Ethernet", "Intel(R) Ethernet Connection", "192.168.56.1"),
        _iface("Loopback", "Software Loopback Interface 1", "127.0.0.1"),
    ]

    with pytest.raises(capture.CaptureError):
        capture.find_wifi_interface(interfaces)


def test_find_wifi_interface_raises_when_no_interfaces_at_all():
    with pytest.raises(capture.CaptureError):
        capture.find_wifi_interface([])


# --- capture_packets bounds ---------------------------------------------------


def test_capture_packets_rejects_non_positive_duration():
    with pytest.raises(ValueError):
        capture.capture_packets(duration_seconds=0)


# --- extended header metadata (CICIDS2017 feature prep) ----------------------


def test_tcp_packet_includes_full_header_and_flag_metadata():
    packet = IP(src="192.168.1.6", dst="93.184.216.34") / TCP(sport=51820, dport=443, flags="PA", window=64240) / b"hello"

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert meta.ip_header_length == 20  # no IP options
    assert meta.transport_header_length == 20  # no TCP options
    assert meta.tcp_flags == "PA"
    assert meta.tcp_window == 64240
    assert meta.tcp_payload_length == len(b"hello")


def test_tcp_flags_reflect_multiple_set_flags():
    packet = IP(src="192.168.1.6", dst="93.184.216.34") / TCP(sport=51820, dport=443, flags="SA")

    meta = capture.extract_packet_metadata(packet)

    assert meta.tcp_flags == "SA"


def test_tcp_flags_empty_string_when_no_flags_set():
    packet = IP(src="192.168.1.6", dst="93.184.216.34") / TCP(sport=51820, dport=443, flags=0)

    meta = capture.extract_packet_metadata(packet)

    assert meta.tcp_flags == ""


def test_tcp_packet_with_no_payload_has_zero_payload_length():
    packet = IP(src="192.168.1.6", dst="93.184.216.34") / TCP(sport=51820, dport=443, flags="S")

    meta = capture.extract_packet_metadata(packet)

    assert meta.tcp_payload_length == 0


def test_udp_packet_reports_fixed_header_length_and_payload_length():
    packet = IP(src="192.168.1.6", dst="8.8.8.8") / UDP(sport=53000, dport=53) / b"udp-data"

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert meta.ip_header_length == 20
    assert meta.transport_header_length == 8  # UDP header is always 8 bytes
    assert meta.tcp_payload_length == len(b"udp-data")


def test_udp_packet_has_no_tcp_specific_fields():
    packet = IP(src="192.168.1.6", dst="8.8.8.8") / UDP(sport=53000, dport=53)

    meta = capture.extract_packet_metadata(packet)

    assert meta.tcp_flags is None
    assert meta.tcp_window is None


def test_icmp_packet_has_ip_header_length_but_no_transport_or_tcp_fields():
    packet = IP(src="192.168.1.6", dst="1.1.1.1") / ICMP()

    meta = capture.extract_packet_metadata(packet)

    assert meta is not None
    assert meta.ip_header_length == 20
    assert meta.transport_header_length is None
    assert meta.tcp_flags is None
    assert meta.tcp_window is None
    assert meta.tcp_payload_length is None
    assert meta.source_port is None
    assert meta.destination_port is None


def test_extract_metadata_handles_broken_layer_access_without_raising():
    class _BrokenIndexing:
        def haslayer(self, layer):
            return layer is IP

        def __getitem__(self, layer):
            raise RuntimeError("boom")

    assert capture.extract_packet_metadata(_BrokenIndexing()) is None


def test_extract_metadata_still_works_for_non_ip_packet_with_new_fields_absent():
    packet = Ether() / ARP()

    assert capture.extract_packet_metadata(packet) is None
