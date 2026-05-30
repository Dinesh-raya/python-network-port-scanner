"""Tests for the models module."""

import pytest

from port_scanner.models import (
    Port,
    PortState,
    Protocol,
    ScanConfig,
    ScanResult,
    ScanTarget,
)


class TestPort:
    """Tests for the Port dataclass."""

    def test_valid_port_creation(self) -> None:
        port = Port(number=80, protocol=Protocol.TCP)
        assert port.number == 80
        assert port.protocol == Protocol.TCP

    def test_port_number_too_low(self) -> None:
        with pytest.raises(ValueError, match="Port number must be 1-65535"):
            Port(number=0, protocol=Protocol.TCP)

    def test_port_number_too_high(self) -> None:
        with pytest.raises(ValueError, match="Port number must be 1-65535"):
            Port(number=65536, protocol=Protocol.TCP)

    def test_port_boundary_values(self) -> None:
        port1 = Port(number=1, protocol=Protocol.TCP)
        port2 = Port(number=65535, protocol=Protocol.TCP)
        assert port1.number == 1
        assert port2.number == 65535

    def test_port_equality(self) -> None:
        port1 = Port(number=80, protocol=Protocol.TCP)
        port2 = Port(number=80, protocol=Protocol.TCP)
        assert port1 == port2

    def test_port_hash(self) -> None:
        port1 = Port(number=80, protocol=Protocol.TCP)
        port2 = Port(number=80, protocol=Protocol.TCP)
        assert hash(port1) == hash(port2)

    def test_port_frozen(self) -> None:
        port = Port(number=80, protocol=Protocol.TCP)
        with pytest.raises(AttributeError):
            port.number = 443  # type: ignore[misc]

    def test_port_str(self) -> None:
        port = Port(number=80, protocol=Protocol.TCP)
        assert str(port) == "80/tcp"


class TestPortState:
    """Tests for the PortState enum."""

    def test_states_exist(self) -> None:
        assert PortState.OPEN.value == "open"
        assert PortState.CLOSED.value == "closed"
        assert PortState.FILTERED.value == "filtered"


class TestProtocol:
    """Tests for the Protocol enum."""

    def test_protocols_exist(self) -> None:
        assert Protocol.TCP.value == "tcp"
        assert Protocol.UDP.value == "udp"


class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_scan_result_creation(self) -> None:
        port = Port(number=80, protocol=Protocol.TCP)
        result = ScanResult(
            port=port,
            state=PortState.OPEN,
            service="http",
            banner="Apache/2.4",
            response_time_ms=15.5,
        )
        assert result.port == port
        assert result.state == PortState.OPEN
        assert result.service == "http"
        assert result.banner == "Apache/2.4"
        assert result.response_time_ms == 15.5

    def test_scan_result_optional_fields(self) -> None:
        port = Port(number=80, protocol=Protocol.TCP)
        result = ScanResult(
            port=port,
            state=PortState.CLOSED,
            service=None,
            banner=None,
            response_time_ms=0.0,
        )
        assert result.service is None
        assert result.banner is None

    def test_scan_result_frozen(self) -> None:
        port = Port(number=80, protocol=Protocol.TCP)
        result = ScanResult(
            port=port,
            state=PortState.OPEN,
            service=None,
            banner=None,
            response_time_ms=0.0,
        )
        with pytest.raises(AttributeError):
            result.state = PortState.CLOSED  # type: ignore[misc]


class TestScanTarget:
    """Tests for the ScanTarget dataclass."""

    def test_scan_target_creation(self) -> None:
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="example.com", ip="93.184.216.34", ports=ports)
        assert target.host == "example.com"
        assert target.ip == "93.184.216.34"
        assert len(target.ports) == 1

    def test_scan_target_ports_frozen_to_tuple(self) -> None:
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="example.com", ip="93.184.216.34", ports=ports)
        assert isinstance(target.ports, tuple)


class TestScanConfig:
    """Tests for the ScanConfig dataclass."""

    def test_scan_config_creation(self) -> None:
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="example.com", ip="93.184.216.34", ports=ports)
        config = ScanConfig(
            target=target,
            timeout_ms=1000,
            max_concurrency=100,
            detect_services=True,
            grab_banners=True,
        )
        assert config.timeout_ms == 1000
        assert config.max_concurrency == 100
        assert config.detect_services is True
        assert config.grab_banners is True

    def test_scan_config_frozen(self) -> None:
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="example.com", ip="93.184.216.34", ports=ports)
        config = ScanConfig(
            target=target,
            timeout_ms=1000,
            max_concurrency=100,
            detect_services=True,
            grab_banners=True,
        )
        with pytest.raises(AttributeError):
            config.timeout_ms = 2000  # type: ignore[misc]

    def test_scan_config_invalid_timeout(self) -> None:
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="example.com", ip="93.184.216.34", ports=ports)
        with pytest.raises(ValueError, match="timeout_ms must be positive"):
            ScanConfig(target=target, timeout_ms=0)

    def test_scan_config_invalid_concurrency(self) -> None:
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="example.com", ip="93.184.216.34", ports=ports)
        with pytest.raises(ValueError, match="max_concurrency must be positive"):
            ScanConfig(target=target, max_concurrency=-1)
