"""Pure-logic tests for validated identifier handling (section 13's
scenarios 4-6: invalid IP, outside-lab IP, localhost). No DB, no network --
monkeypatches `settings` directly since ip_validation reads it live."""

from __future__ import annotations

import pytest

from backend.app.core.config import settings
from backend.app.services.prevention.ip_validation import InvalidTargetError, validate_lab_target


@pytest.fixture(autouse=True)
def lab_scope(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "lab_network_cidrs", "192.168.56.0/24")
    monkeypatch.setattr(settings, "lab_allow_loopback_target", False)


def test_valid_lab_ip_is_accepted() -> None:
    target = validate_lab_target("192.168.56.10")
    assert target.ip == "192.168.56.10"
    assert target.scope == "192.168.56.0/24"


def test_malformed_ip_is_rejected() -> None:
    with pytest.raises(InvalidTargetError, match="not a valid IP address"):
        validate_lab_target("not-an-ip")


def test_ip_outside_lab_scope_is_rejected() -> None:
    with pytest.raises(InvalidTargetError, match="outside the configured lab network scope"):
        validate_lab_target("8.8.8.8")


def test_localhost_is_rejected_by_default() -> None:
    with pytest.raises(InvalidTargetError, match="loopback address"):
        validate_lab_target("127.0.0.1")


def test_localhost_is_accepted_when_explicitly_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "lab_allow_loopback_target", True)
    target = validate_lab_target("127.0.0.1")
    assert target.ip == "127.0.0.1"
    assert "loopback" in target.scope


def test_multicast_address_is_rejected() -> None:
    with pytest.raises(InvalidTargetError, match="multicast"):
        validate_lab_target("224.0.0.1")


def test_broadcast_address_is_rejected() -> None:
    with pytest.raises(InvalidTargetError, match="broadcast"):
        validate_lab_target("255.255.255.255")


def test_multiple_configured_cidrs_are_all_honored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "lab_network_cidrs", "192.168.56.0/24, 10.10.0.0/16")
    assert validate_lab_target("10.10.5.5").scope == "10.10.0.0/16"


def test_empty_input_is_rejected() -> None:
    with pytest.raises(InvalidTargetError):
        validate_lab_target("")
