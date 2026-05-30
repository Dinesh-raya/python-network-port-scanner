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
from port_scanner.scanner import PortScanner


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
