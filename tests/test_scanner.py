"""Tests for the scanner module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from port_scanner.models import (
    Port,
    PortState,
    Protocol,
    ScanConfig,
    ScanTarget,
)
from port_scanner.scanner import PortScanner, _UDPProtocol


@pytest.fixture
def scan_config() -> ScanConfig:
    """Create a test scan configuration."""
    ports = [
        Port(number=80, protocol=Protocol.TCP),
        Port(number=443, protocol=Protocol.TCP),
    ]
    target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
    return ScanConfig(
        target=target,
        timeout_ms=1000,
        max_concurrency=10,
        detect_services=True,
        grab_banners=False,
    )


@pytest.fixture
def scanner(scan_config: ScanConfig) -> PortScanner:
    """Create a test scanner instance."""
    return PortScanner(scan_config)


@pytest.fixture
def udp_scan_config() -> ScanConfig:
    """Create a test scan configuration for UDP ports."""
    ports = [
        Port(number=53, protocol=Protocol.UDP),
        Port(number=161, protocol=Protocol.UDP),
    ]
    target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
    return ScanConfig(
        target=target,
        timeout_ms=1000,
        max_concurrency=10,
        detect_services=True,
        grab_banners=False,
    )


@pytest.fixture
def udp_scanner(udp_scan_config: ScanConfig) -> PortScanner:
    """Create a test scanner for UDP."""
    return PortScanner(udp_scan_config)


class TestPortScanner:
    """Tests for the PortScanner class."""

    def test_scanner_initialization(self, scanner: PortScanner) -> None:
        assert scanner is not None

    @pytest.mark.asyncio
    async def test_scan_port_open(self, scanner: PortScanner) -> None:
        """Test scanning an open port."""
        mock_writer = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            port = Port(number=80, protocol=Protocol.TCP)
            result = await scanner.scan_port(port)

            assert result.port == port
            assert result.state == PortState.OPEN
            mock_writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_port_closed(self, scanner: PortScanner) -> None:
        """Test scanning a closed port."""
        with patch(
            "asyncio.open_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            port = Port(number=80, protocol=Protocol.TCP)
            result = await scanner.scan_port(port)

            assert result.port == port
            assert result.state == PortState.CLOSED

    @pytest.mark.asyncio
    async def test_scan_port_filtered(self, scanner: PortScanner) -> None:
        """Test scanning a filtered port (timeout)."""
        with patch(
            "asyncio.open_connection",
            side_effect=asyncio.TimeoutError("Connection timed out"),
        ):
            port = Port(number=80, protocol=Protocol.TCP)
            result = await scanner.scan_port(port)

            assert result.port == port
            assert result.state == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_scan_port_with_os_error(self, scanner: PortScanner) -> None:
        """Test scanning a port that raises an OS error."""
        with patch(
            "asyncio.open_connection",
            side_effect=OSError("Network unreachable"),
        ):
            port = Port(number=80, protocol=Protocol.TCP)
            result = await scanner.scan_port(port)

            assert result.port == port
            assert result.state == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_scan_multiple_ports(self, scanner: PortScanner) -> None:
        """Test scanning multiple ports."""
        mock_writer = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            results = await scanner.scan()

            assert len(results) == 2
            assert all(r.state == PortState.OPEN for r in results)

    @pytest.mark.asyncio
    async def test_progress_callback(self, scan_config: ScanConfig) -> None:
        """Test that progress callback is called."""
        progress_calls: list[tuple[int, int]] = []

        def progress_callback(completed: int, total: int) -> None:
            progress_calls.append((completed, total))

        scanner = PortScanner(scan_config, progress_callback=progress_callback)

        mock_writer = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            await scanner.scan()

            assert len(progress_calls) > 0
            assert progress_calls[-1][0] == 2  # completed
            assert progress_calls[-1][1] == 2  # total

    @pytest.mark.asyncio
    async def test_scan_no_ports_raises(self) -> None:
        """Test that scanning with no ports raises ValueError."""
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=[])
        config = ScanConfig(target=target, timeout_ms=1000, max_concurrency=10)
        scanner = PortScanner(config)
        with pytest.raises(ValueError, match="No ports to scan"):
            await scanner.scan()

    @pytest.mark.asyncio
    async def test_os_error_errno_113_filtered(self, scanner: PortScanner) -> None:
        """Test that errno 113 (no route to host) results in FILTERED."""
        err = OSError("No route to host")
        err.errno = 113
        with patch("asyncio.open_connection", side_effect=err):
            port = Port(number=80, protocol=Protocol.TCP)
            result = await scanner.scan_port(port)
            assert result.state == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_os_error_errno_111_closed(self, scanner: PortScanner) -> None:
        """Test that errno 111 (connection refused on Linux) results in CLOSED."""
        err = OSError("Connection refused")
        err.errno = 111
        with patch("asyncio.open_connection", side_effect=err):
            port = Port(number=80, protocol=Protocol.TCP)
            result = await scanner.scan_port(port)
            assert result.state == PortState.CLOSED

    @pytest.mark.asyncio
    async def test_tcp_banner_grabbing(self) -> None:
        """Test banner grabbing on an open port."""
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=True, grab_banners=True,
        )
        scanner = PortScanner(config)

        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("127.0.0.1", 80)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"Apache/2.4.41")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await scanner.scan_port(Port(number=80, protocol=Protocol.TCP))
            assert result.state == PortState.OPEN
            assert result.banner == "Apache/2.4.41"

    @pytest.mark.asyncio
    async def test_tcp_banner_grab_timeout(self) -> None:
        """Test banner grabbing when read times out."""
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=True, grab_banners=True,
        )
        scanner = PortScanner(config)

        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("127.0.0.1", 80)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await scanner.scan_port(Port(number=80, protocol=Protocol.TCP))
            assert result.state == PortState.OPEN
            assert result.banner is None

    @pytest.mark.asyncio
    async def test_tcp_banner_grab_no_peer(self) -> None:
        """Test banner grabbing when get_extra_info returns None."""
        ports = [Port(number=22, protocol=Protocol.TCP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=True, grab_banners=True,
        )
        scanner = PortScanner(config)

        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = None
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.2")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await scanner.scan_port(Port(number=22, protocol=Protocol.TCP))
            assert result.state == PortState.OPEN
            assert result.banner == "SSH-2.0-OpenSSH_8.2"

    @pytest.mark.asyncio
    async def test_tcp_banner_with_null_bytes(self) -> None:
        """Test that banner cleanup strips null bytes."""
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=True, grab_banners=True,
        )
        scanner = PortScanner(config)

        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("127.0.0.1", 80)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"Apache\x00/2.4.41")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await scanner.scan_port(Port(number=80, protocol=Protocol.TCP))
            assert result.banner == "Apache/2.4.41"

    def test_get_service_name_with_db(self, scanner: PortScanner) -> None:
        """Test _get_service_name when service_db is available."""
        mock_db = MagicMock()
        mock_db.get_service_name.return_value = "http"
        scanner._service_db = mock_db

        port = Port(number=80, protocol=Protocol.TCP)
        name = scanner._get_service_name(port)
        assert name == "http"

    def test_get_service_name_unknown(self, scanner: PortScanner) -> None:
        """Test _get_service_name returns None for unknown ports."""
        mock_db = MagicMock()
        mock_db.get_service_name.return_value = "unknown"
        scanner._service_db = mock_db

        port = Port(number=9999, protocol=Protocol.TCP)
        name = scanner._get_service_name(port)
        assert name is None

    def test_get_service_name_no_db(self, scanner: PortScanner) -> None:
        """Test _get_service_name returns None when no service_db."""
        scanner._service_db = None
        port = Port(number=80, protocol=Protocol.TCP)
        name = scanner._get_service_name(port)
        assert name is None

    def test_get_tcp_probe_known_ports(self, scanner: PortScanner) -> None:
        """Test _get_tcp_probe returns probes for known ports."""
        assert scanner._get_tcp_probe(80) is not None
        assert scanner._get_tcp_probe(443) is not None
        assert scanner._get_tcp_probe(25) is not None
        assert scanner._get_tcp_probe(21) is not None
        assert scanner._get_tcp_probe(22) is not None
        assert scanner._get_tcp_probe(23) is not None

    def test_get_tcp_probe_unknown_port(self, scanner: PortScanner) -> None:
        """Test _get_tcp_probe returns None for unknown ports."""
        assert scanner._get_tcp_probe(9999) is None

    @pytest.mark.asyncio
    async def test_scanner_with_no_service_detection(self) -> None:
        """Test scanner with detect_services=False."""
        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=False, grab_banners=False,
        )
        scanner = PortScanner(config)

        mock_writer = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await scanner.scan_port(Port(number=80, protocol=Protocol.TCP))
            assert result.service is None

    @pytest.mark.asyncio
    async def test_scanner_custom_service_db(self) -> None:
        """Test scanner with a custom service_db provided."""
        mock_db = MagicMock()
        mock_db.get_service_name.return_value = "custom-service"

        ports = [Port(number=80, protocol=Protocol.TCP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=True, grab_banners=False,
        )
        scanner = PortScanner(config, service_db=mock_db)

        mock_writer = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await scanner.scan_port(Port(number=80, protocol=Protocol.TCP))
            assert result.service == "custom-service"

    @pytest.mark.asyncio
    async def test_scan_returns_sorted_results(self, scanner: PortScanner) -> None:
        """Test that scan results are sorted by port number."""
        mock_writer = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            results = await scanner.scan()
            port_numbers = [r.port.number for r in results]
            assert port_numbers == sorted(port_numbers)


class TestUDPScanner:
    """Tests for UDP scanning functionality."""

    @pytest.mark.asyncio
    async def test_udp_scan_open_port(self, udp_scanner: PortScanner) -> None:
        """Test scanning a UDP port that responds."""
        mock_transport = MagicMock()
        mock_protocol = AsyncMock()
        mock_protocol.wait_for_response = AsyncMock(return_value=b"response data")

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            port = Port(number=53, protocol=Protocol.UDP)
            result = await udp_scanner.scan_port(port)

            assert result.state == PortState.OPEN
            assert result.port == port

    @pytest.mark.asyncio
    async def test_udp_scan_open_with_banner(self) -> None:
        """Test that UDP scan captures banner when grab_banners is enabled."""
        ports = [Port(number=53, protocol=Protocol.UDP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=True, grab_banners=True,
        )
        scanner = PortScanner(config)

        mock_transport = MagicMock()
        mock_protocol = AsyncMock()
        mock_protocol.wait_for_response = AsyncMock(return_value=b"DNS response")

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            port = Port(number=53, protocol=Protocol.UDP)
            result = await scanner.scan_port(port)

            assert result.state == PortState.OPEN
            assert result.banner == "DNS response"

    @pytest.mark.asyncio
    async def test_udp_scan_filtered_timeout(self, udp_scanner: PortScanner) -> None:
        """Test that a UDP port with no response is FILTERED."""
        mock_transport = MagicMock()
        mock_protocol = AsyncMock()
        mock_protocol.wait_for_response = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            port = Port(number=53, protocol=Protocol.UDP)
            result = await udp_scanner.scan_port(port)

            assert result.state == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_udp_scan_closed_os_error_111(self, udp_scanner: PortScanner) -> None:
        """Test that errno 111 results in CLOSED for UDP."""
        err = OSError("Connection refused")
        err.errno = 111

        with patch("asyncio.get_event_loop", side_effect=err):
            port = Port(number=53, protocol=Protocol.UDP)
            result = await udp_scanner.scan_port(port)
            assert result.state == PortState.CLOSED

    @pytest.mark.asyncio
    async def test_udp_scan_filtered_os_error(self, udp_scanner: PortScanner) -> None:
        """Test that other OS errors result in FILTERED for UDP."""
        err = OSError("Network unreachable")
        err.errno = 101

        with patch("asyncio.get_event_loop", side_effect=err):
            port = Port(number=53, protocol=Protocol.UDP)
            result = await udp_scanner.scan_port(port)
            assert result.state == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_udp_scan_open_filtered_no_data(self, udp_scanner: PortScanner) -> None:
        """Test that protocol returning None means FILTERED."""
        mock_transport = MagicMock()
        mock_protocol = AsyncMock()
        mock_protocol.wait_for_response = AsyncMock(return_value=None)

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            port = Port(number=53, protocol=Protocol.UDP)
            result = await udp_scanner.scan_port(port)

            assert result.state == PortState.FILTERED
            assert result.banner is None

    @pytest.mark.asyncio
    async def test_udp_scan_uses_correct_probe(self, udp_scanner: PortScanner) -> None:
        """Test that the correct UDP probe is sent for known ports."""
        mock_transport = MagicMock()
        mock_protocol = AsyncMock()
        mock_protocol.wait_for_response = AsyncMock(return_value=b"response")

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            port = Port(number=53, protocol=Protocol.UDP)
            await udp_scanner.scan_port(port)

            # Verify sendto was called (probe was sent)
            mock_transport.sendto.assert_called_once()

    @pytest.mark.asyncio
    async def test_udp_scan_with_service_detection(self, udp_scanner: PortScanner) -> None:
        """Test that service detection works for UDP ports."""
        mock_transport = MagicMock()
        mock_protocol = AsyncMock()
        mock_protocol.wait_for_response = AsyncMock(return_value=b"response")

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            port = Port(number=53, protocol=Protocol.UDP)
            result = await udp_scanner.scan_port(port)

            # Port 53 UDP is "dns" in commonPorts.json
            assert result.service is not None

    @pytest.mark.asyncio
    async def test_udp_scan_no_service_detection(self) -> None:
        """Test UDP scan with service detection disabled."""
        ports = [Port(number=53, protocol=Protocol.UDP)]
        target = ScanTarget(host="localhost", ip="127.0.0.1", ports=ports)
        config = ScanConfig(
            target=target, timeout_ms=1000, max_concurrency=10,
            detect_services=False, grab_banners=False,
        )
        scanner = PortScanner(config)

        mock_transport = MagicMock()
        mock_protocol = AsyncMock()
        mock_protocol.wait_for_response = AsyncMock(return_value=b"response")

        with patch("asyncio.get_event_loop") as mock_get_loop:
            mock_loop = AsyncMock()
            mock_loop.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            mock_get_loop.return_value = mock_loop

            port = Port(number=53, protocol=Protocol.UDP)
            result = await scanner.scan_port(port)
            assert result.service is None


class TestUDPProtocol:
    """Tests for the _UDPProtocol class."""

    @pytest.mark.asyncio
    async def test_datagram_received(self) -> None:
        """Test that datagram_received resolves the future."""
        protocol = _UDPProtocol()
        protocol.datagram_received(b"hello", ("127.0.0.1", 53))
        result = await protocol.wait_for_response()
        assert result == b"hello"

    @pytest.mark.asyncio
    async def test_error_received(self) -> None:
        """Test that error_received sets result to None."""
        protocol = _UDPProtocol()
        protocol.error_received(Exception("test error"))
        result = await protocol.wait_for_response()
        assert result is None

    @pytest.mark.asyncio
    async def test_connection_lost(self) -> None:
        """Test that connection_lost sets result to None."""
        protocol = _UDPProtocol()
        protocol.connection_lost(None)
        result = await protocol.wait_for_response()
        assert result is None

    @pytest.mark.asyncio
    async def test_connection_made(self) -> None:
        """Test that connection_made does not raise."""
        protocol = _UDPProtocol()
        protocol.connection_made(MagicMock())  # Should not raise

    @pytest.mark.asyncio
    async def test_datagram_received_only_first(self) -> None:
        """Test that only the first datagram is captured."""
        protocol = _UDPProtocol()
        protocol.datagram_received(b"first", ("127.0.0.1", 53))
        protocol.datagram_received(b"second", ("127.0.0.1", 53))
        result = await protocol.wait_for_response()
        assert result == b"first"
