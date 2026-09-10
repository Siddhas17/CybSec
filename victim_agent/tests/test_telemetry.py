from __future__ import annotations

import socket
from types import SimpleNamespace

import psutil
import pytest

from victim_agent import telemetry


def _addr(ip: str, port: int) -> SimpleNamespace:
    return SimpleNamespace(ip=ip, port=port)


def _conn(type_, laddr, raddr, status) -> SimpleNamespace:
    return SimpleNamespace(type=type_, laddr=laddr, raddr=raddr, status=status)


def test_get_connections_maps_tcp_and_udp(monkeypatch):
    fake = [
        _conn(socket.SOCK_STREAM, _addr("192.168.56.101", 51820), _addr("192.168.56.1", 443), "ESTABLISHED"),
        _conn(socket.SOCK_STREAM, _addr("192.168.56.101", 3389), (), "LISTEN"),
        _conn(socket.SOCK_DGRAM, _addr("192.168.56.101", 68), (), "NONE"),
    ]
    monkeypatch.setattr("victim_agent.telemetry.psutil.net_connections", lambda kind: fake)

    connections = telemetry.get_connections()

    assert len(connections) == 3
    established = next(c for c in connections if c["local_port"] == 51820)
    assert established == {"local_ip": "192.168.56.101", "local_port": 51820, "remote_ip": "192.168.56.1", "remote_port": 443, "protocol": "TCP", "status": "ESTABLISHED"}

    listen = next(c for c in connections if c["local_port"] == 3389)
    assert listen["remote_ip"] is None
    assert listen["remote_port"] is None

    udp = next(c for c in connections if c["local_port"] == 68)
    assert udp["protocol"] == "UDP"


def test_get_connections_skips_entries_without_local_address(monkeypatch):
    fake = [_conn(socket.SOCK_STREAM, (), (), "NONE")]
    monkeypatch.setattr("victim_agent.telemetry.psutil.net_connections", lambda kind: fake)
    assert telemetry.get_connections() == []


def test_get_connections_skips_non_tcp_udp_socket_types(monkeypatch):
    fake = [_conn(socket.SOCK_RAW, _addr("192.168.56.101", 0), (), "NONE")]
    monkeypatch.setattr("victim_agent.telemetry.psutil.net_connections", lambda kind: fake)
    assert telemetry.get_connections() == []


def test_get_connections_never_fabricates_on_access_denied(monkeypatch, caplog):
    def _raise(kind):
        raise psutil.AccessDenied()

    monkeypatch.setattr("victim_agent.telemetry.psutil.net_connections", _raise)
    assert telemetry.get_connections() == []


def test_get_local_ipv4s_excludes_loopback(monkeypatch):
    fake_addrs = {
        "eth0": [SimpleNamespace(family=socket.AF_INET, address="192.168.56.101")],
        "lo": [SimpleNamespace(family=socket.AF_INET, address="127.0.0.1")],
    }
    monkeypatch.setattr("victim_agent.telemetry.psutil.net_if_addrs", lambda: fake_addrs)
    assert telemetry.get_local_ipv4s() == ["192.168.56.101"]


def test_get_primary_local_ip_falls_back_to_loopback_when_no_addrs(monkeypatch):
    monkeypatch.setattr("victim_agent.telemetry.psutil.net_if_addrs", lambda: {})
    assert telemetry.get_primary_local_ip() == "127.0.0.1"
