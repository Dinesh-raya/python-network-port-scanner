"""Tests for the utils module."""

import pytest

from port_scanner.utils import (
    HostResolutionError,
    PortParseError,
    parse_port_range,
    resolve_host,
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
