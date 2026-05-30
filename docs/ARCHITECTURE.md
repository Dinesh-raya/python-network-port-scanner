# Architecture Specification

## Project Overview
Port Scanner Pro is a professional-grade async network port scanner built with Python.

## Module Structure

```
src/port_scanner/
├── __init__.py          # Public API exports
├── __main__.py          # python -m port_scanner entry
├── cli.py               # Click CLI with Rich output
├── models.py            # Data models (dataclasses)
├── scanner.py           # Async scanning engine
├── output.py            # Output formatters
├── services.py          # Service name database
└── utils.py             # Helpers (hostname resolution, etc.)
```

## Core Models (models.py)

```python
from dataclasses import dataclass
from enum import Enum

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"

@dataclass(frozen=True)
class Port:
    number: int
    protocol: Protocol

@dataclass(frozen=True)
class ScanResult:
    port: Port
    state: PortState
    service: str | None
    banner: str | None
    response_time_ms: float

@dataclass(frozen=True)
class ScanTarget:
    host: str
    ip: str
    ports: list[Port]

@dataclass(frozen=True)
class ScanConfig:
    target: ScanTarget
    timeout_ms: int
    max_concurrency: int
    detect_services: bool
    grab_banners: bool
```

## Scanner Engine (scanner.py)

- Async TCP connect scanning using asyncio
- Async UDP scanning with ICMP detection
- Semaphore-based concurrency control
- Banner grabbing with timeout
- Service detection from commonPorts.json
- Progress callback for UI updates

## CLI Interface (cli.py)

- Click command group
- Rich console for formatted output
- Progress bars with live updates
- Argument validation
- Multiple output format support

## Output Formatters (output.py)

- JSON formatter (structured data)
- CSV formatter (spreadsheet-compatible)
- Table formatter (Rich tables)
- Plain text formatter

## Key Interfaces

```python
class ScannerProtocol(Protocol):
    async def scan_port(self, port: Port) -> ScanResult: ...
    async def scan_target(self, target: ScanTarget) -> list[ScanResult]: ...

class OutputFormatter(Protocol):
    def format(self, results: list[ScanResult]) -> str: ...
```
