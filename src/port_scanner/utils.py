"""Utility functions for hostname resolution and port parsing."""

from __future__ import annotations

import asyncio
import socket


class ScannerError(Exception):
    """Base exception for scanner operations."""


class HostResolutionError(ScannerError):
    """Failed to resolve a hostname to an IP address."""


class PortParseError(ScannerError):
    """Failed to parse a port specification string."""


class TargetValidationError(ScannerError):
    """Target string failed validation."""


async def resolve_host(hostname: str) -> str:
    """Resolve a hostname to an IP address.

    Args:
        hostname: A hostname or IP address string.

    Returns:
        The resolved IPv4 or IPv6 address.

    Raises:
        HostResolutionError: If resolution fails.
    """
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        if not infos:
            raise HostResolutionError(f"No addresses found for {hostname}")
        # Return the first resolved address
        return infos[0][4][0]
    except socket.gaierror as e:
        raise HostResolutionError(f"Cannot resolve hostname '{hostname}': {e}") from e


def parse_port_range(port_string: str) -> list[int]:
    """Parse a port specification string into a list of port numbers.

    Supports:
        - Single ports: "80"
        - Ranges: "80-100"
        - Comma-separated: "80,443,8080"
        - Mixed: "80,443,8000-8100"

    Args:
        port_string: The port specification to parse.

    Returns:
        A sorted, deduplicated list of port numbers.

    Raises:
        PortParseError: If the specification is invalid.
    """
    if not port_string or not port_string.strip():
        raise PortParseError("Port specification cannot be empty")

    ports: set[int] = set()

    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            # Range specification
            bounds = part.split("-", 1)
            if len(bounds) != 2 or not bounds[0].strip() or not bounds[1].strip():
                raise PortParseError(f"Invalid port range: '{part}'")
            try:
                start = int(bounds[0].strip())
                end = int(bounds[1].strip())
            except ValueError as e:
                raise PortParseError(f"Invalid port range: '{part}'") from e
            if start > end:
                raise PortParseError(
                    f"Invalid range (start > end): '{part}'"
                )
            if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                raise PortParseError(f"Port numbers must be 1-65535: '{part}'")
            ports.update(range(start, end + 1))
        else:
            # Single port
            try:
                port = int(part)
            except ValueError as e:
                raise PortParseError(f"Invalid port number: '{part}'") from e
            if not 1 <= port <= 65535:
                raise PortParseError(f"Port number must be 1-65535, got {port}")
            ports.add(port)

    if not ports:
        raise PortParseError("No valid ports in specification")

    return sorted(ports)


async def validate_target(target_string: str) -> tuple[str, str]:
    """Validate and resolve a scan target.

    Args:
        target_string: A hostname or IP address.

    Returns:
        A tuple of (original_host, resolved_ip).

    Raises:
        TargetValidationError: If the target is invalid or unresolvable.
    """
    if not target_string or not target_string.strip():
        raise TargetValidationError("Target cannot be empty")

    host = target_string.strip()

    # Strip protocol prefix if present
    for prefix in ("http://", "https://", "ftp://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
            # Remove any trailing path
            host = host.split("/", 1)[0]
            break

    if not host:
        raise TargetValidationError("Target cannot be empty after stripping prefix")

    try:
        ip = await resolve_host(host)
    except HostResolutionError as e:
        raise TargetValidationError(str(e)) from e

    return host, ip
