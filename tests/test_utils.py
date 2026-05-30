"""Tests for the utils module."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from port_scanner.utils import (
    HostResolutionError,
    PortParseError,
    TargetValidationError,
    parse_port_range,
    resolve_host,
    validate_target,
)


class TestParsePortRange:
    """Tests for the parse_port_range function."""

    def test_single_port(self) -> None:
        ports = parse_port_range("80")
        assert ports == [80]

    def test_port_range(self) -> None:
        ports = parse_port_range("80-83")
        assert ports == [80, 81, 82, 83]

    def test_comma_separated_ports(self) -> None:
        ports = parse_port_range("80,443,8080")
        assert ports == [80, 443, 8080]

    def test_mixed_format(self) -> None:
        ports = parse_port_range("80,443,8000-8005")
        assert 80 in ports
        assert 443 in ports
        assert 8000 in ports
        assert 8005 in ports
        assert len(ports) == 8  # 80, 443, 8000-8005

    def test_invalid_port_number(self) -> None:
        with pytest.raises(PortParseError, match="Invalid port number"):
            parse_port_range("abc")

    def test_invalid_range(self) -> None:
        with pytest.raises(PortParseError, match="Invalid port range"):
            parse_port_range("80-")

    def test_port_out_of_range(self) -> None:
        with pytest.raises(PortParseError, match="Port number must be 1-65535"):
            parse_port_range("0")

    def test_port_too_high(self) -> None:
        with pytest.raises(PortParseError, match="Port number must be 1-65535"):
            parse_port_range("65536")

    def test_empty_string(self) -> None:
        with pytest.raises(PortParseError, match="cannot be empty"):
            parse_port_range("")

    def test_whitespace_handling(self) -> None:
        ports = parse_port_range(" 80 , 443 ")
        assert ports == [80, 443]

    def test_duplicate_removal(self) -> None:
        ports = parse_port_range("80,80,80")
        assert ports == [80]

    def test_sorted_output(self) -> None:
        ports = parse_port_range("443,80,8080")
        assert ports == [80, 443, 8080]

    def test_range_start_greater_than_end(self) -> None:
        """Test that range with start > end raises PortParseError."""
        with pytest.raises(PortParseError, match="Invalid range"):
            parse_port_range("100-80")

    def test_invalid_range_end(self) -> None:
        """Test that range with non-numeric end raises PortParseError."""
        with pytest.raises(PortParseError, match="Invalid port range"):
            parse_port_range("80-abc")

    def test_range_out_of_bounds(self) -> None:
        """Test that port range with out-of-bounds values raises error."""
        with pytest.raises(PortParseError, match="1-65535"):
            parse_port_range("0-100")

    def test_no_valid_ports(self) -> None:
        """Test that empty parts result in no valid ports."""
        with pytest.raises(PortParseError, match="No valid ports"):
            parse_port_range(",")

    def test_whitespace_only(self) -> None:
        """Test that whitespace-only string raises PortParseError."""
        with pytest.raises(PortParseError, match="cannot be empty"):
            parse_port_range("   ")

    def test_range_with_spaces(self) -> None:
        """Test that range parsing handles spaces around dash."""
        ports = parse_port_range("80 - 83")
        assert ports == [80, 81, 82, 83]

    def test_boundary_port_1(self) -> None:
        """Test that port 1 is valid."""
        ports = parse_port_range("1")
        assert ports == [1]

    def test_boundary_port_65535(self) -> None:
        """Test that port 65535 is valid."""
        ports = parse_port_range("65535")
        assert ports == [65535]


class TestResolveHost:
    """Tests for the resolve_host function."""

    @pytest.mark.asyncio
    async def test_resolve_localhost(self) -> None:
        ip = await resolve_host("localhost")
        assert ip in ("127.0.0.1", "::1")

    @pytest.mark.asyncio
    async def test_resolve_ip_address(self) -> None:
        ip = await resolve_host("127.0.0.1")
        assert ip == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_resolve_invalid_host(self) -> None:
        with pytest.raises(HostResolutionError):
            await resolve_host("this-host-does-not-exist-12345.invalid")

    @pytest.mark.asyncio
    async def test_resolve_gaierror(self) -> None:
        """Test that socket.gaierror is converted to HostResolutionError."""
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_loop.getaddrinfo = AsyncMock(
                side_effect=socket.gaierror("Name or service not known")
            )
            mock_get_loop.return_value = mock_loop
            with pytest.raises(HostResolutionError, match="Cannot resolve"):
                await resolve_host("invalid.host")

    @pytest.mark.asyncio
    async def test_resolve_empty_result(self) -> None:
        """Test that empty getaddrinfo result raises HostResolutionError."""
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_loop.getaddrinfo = AsyncMock(return_value=[])
            mock_get_loop.return_value = mock_loop
            with pytest.raises(HostResolutionError, match="No addresses"):
                await resolve_host("empty.host")


class TestValidateTarget:
    """Tests for the validate_target function."""

    @pytest.mark.asyncio
    async def test_validate_ip_address(self) -> None:
        """Test validating a simple IP address."""
        host, ip = await validate_target("127.0.0.1")
        assert host == "127.0.0.1"
        assert ip == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_validate_hostname(self) -> None:
        """Test validating a hostname."""
        host, ip = await validate_target("localhost")
        assert host == "localhost"
        assert ip in ("127.0.0.1", "::1")

    @pytest.mark.asyncio
    async def test_validate_empty_string(self) -> None:
        """Test that empty string raises TargetValidationError."""
        with pytest.raises(TargetValidationError, match="cannot be empty"):
            await validate_target("")

    @pytest.mark.asyncio
    async def test_validate_whitespace_only(self) -> None:
        """Test that whitespace-only string raises TargetValidationError."""
        with pytest.raises(TargetValidationError, match="cannot be empty"):
            await validate_target("   ")

    @pytest.mark.asyncio
    async def test_validate_strips_whitespace(self) -> None:
        """Test that leading/trailing whitespace is stripped."""
        host, ip = await validate_target("  127.0.0.1  ")
        assert host == "127.0.0.1"
        assert ip == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_validate_strips_http_prefix(self) -> None:
        """Test that http:// prefix is stripped."""
        host, ip = await validate_target("http://localhost")
        assert host == "localhost"
        assert ip in ("127.0.0.1", "::1")

    @pytest.mark.asyncio
    async def test_validate_strips_https_prefix(self) -> None:
        """Test that https:// prefix is stripped."""
        host, ip = await validate_target("https://localhost")
        assert host == "localhost"
        assert ip in ("127.0.0.1", "::1")

    @pytest.mark.asyncio
    async def test_validate_strips_ftp_prefix(self) -> None:
        """Test that ftp:// prefix is stripped."""
        host, ip = await validate_target("ftp://localhost")
        assert host == "localhost"
        assert ip in ("127.0.0.1", "::1")

    @pytest.mark.asyncio
    async def test_validate_strips_path_after_prefix(self) -> None:
        """Test that path after host is stripped with protocol prefix."""
        host, ip = await validate_target("http://localhost/some/path")
        assert host == "localhost"
        assert ip in ("127.0.0.1", "::1")

    @pytest.mark.asyncio
    async def test_validate_unresolvable_host(self) -> None:
        """Test that unresolvable host raises TargetValidationError."""
        with pytest.raises(TargetValidationError):
            await validate_target("this-host-does-not-exist-12345.invalid")

    @pytest.mark.asyncio
    async def test_validate_http_prefix_only(self) -> None:
        """Test that 'http://' alone raises TargetValidationError."""
        with pytest.raises(TargetValidationError, match="empty after stripping"):
            await validate_target("http://")

    @pytest.mark.asyncio
    async def test_validate_case_insensitive_prefix(self) -> None:
        """Test that HTTP:// prefix (uppercase) is stripped."""
        host, ip = await validate_target("HTTP://localhost")
        assert host == "localhost"
        assert ip in ("127.0.0.1", "::1")
