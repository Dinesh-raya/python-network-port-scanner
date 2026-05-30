"""Core data models for the port scanner."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PortState(Enum):
    """State of a scanned port."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Protocol(Enum):
    """Network protocol."""

    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True)
class Port:
    """A network port with protocol.

    Args:
        number: Port number (1-65535).
        protocol: Network protocol (TCP or UDP).

    Raises:
        ValueError: If port number is outside valid range.
    """

    number: int
    protocol: Protocol

    def __post_init__(self) -> None:
        if not 1 <= self.number <= 65535:
            raise ValueError(f"Port number must be 1-65535, got {self.number}")

    def __str__(self) -> str:
        return f"{self.number}/{self.protocol.value}"


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning a single port.

    Args:
        port: The port that was scanned.
        state: The detected state of the port.
        service: Service name if detected, else None.
        banner: Service banner if grabbed, else None.
        response_time_ms: Round-trip time in milliseconds.
    """

    port: Port
    state: PortState
    service: str | None
    banner: str | None
    response_time_ms: float


@dataclass(frozen=True)
class ScanTarget:
    """A scan target with resolved IP and port list.

    Args:
        host: Original hostname or IP string.
        ip: Resolved IP address.
        ports: List of ports to scan.
    """

    host: str
    ip: str
    ports: tuple[Port, ...]

    def __post_init__(self) -> None:
        # Freeze the ports list into a tuple for immutability
        if isinstance(self.ports, list):
            object.__setattr__(self, "ports", tuple(self.ports))


@dataclass(frozen=True)
class ScanConfig:
    """Configuration for a scan operation.

    Args:
        target: The scan target.
        timeout_ms: Connection timeout in milliseconds.
        max_concurrency: Maximum concurrent connections.
        detect_services: Whether to look up service names.
        grab_banners: Whether to grab service banners.

    Raises:
        ValueError: If timeout or concurrency is non-positive.
    """

    target: ScanTarget
    timeout_ms: int = 1000
    max_concurrency: int = 100
    detect_services: bool = True
    grab_banners: bool = False

    def __post_init__(self) -> None:
        if self.timeout_ms <= 0:
            raise ValueError(f"timeout_ms must be positive, got {self.timeout_ms}")
        if self.max_concurrency <= 0:
            raise ValueError(
                f"max_concurrency must be positive, got {self.max_concurrency}"
            )
