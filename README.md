# Port Scanner Pro

A professional-grade, async network port scanner built with Python. Designed for security professionals and network administrators.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://docs.astral.sh/ruff/)

## Features

- **Async TCP/UDP Scanning** - High-performance concurrent port scanning using Python's asyncio
- **Service Detection** - Automatic identification of common services (HTTP, SSH, FTP, etc.)
- **Banner Grabbing** - Retrieve service banners for version identification
- **Multiple Output Formats** - JSON, CSV, table, and plain text output
- **Progress Tracking** - Real-time progress bars with Rich
- **Flexible Port Specification** - Single ports, ranges, or comma-separated lists
- **Concurrency Control** - Configurable maximum concurrent connections
- **Professional CLI** - Intuitive command-line interface with Click

## Installation

### From Source

```bash
git clone https://github.com/Dinesh-raya/python-network-port-scanner.git
cd python-network-port-scanner
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

### Basic Scan

```bash
# Scan common ports on a target
port-scanner scan example.com

# Scan specific ports
port-scanner scan example.com -p 80,443,8080

# Scan a port range
port-scanner scan example.com -p 1-1000
```

### Output Formats

```bash
# JSON output (great for scripting)
port-scanner scan example.com -f json

# CSV output (great for spreadsheets)
port-scanner scan example.com -f csv

# Save results to file
port-scanner scan example.com -f json -o results.json
```

### Advanced Options

```bash
# High-speed scan with more concurrency
port-scanner scan example.com -p 1-10000 -c 500

# Verbose output
port-scanner scan example.com -v

# Disable service detection for faster scans
port-scanner scan example.com --no-service-detection
```

## Usage as Library

```python
import asyncio
from port_scanner import PortScanner, ScanConfig, ScanTarget, Port, Protocol

async def main():
    # Define target
    ports = [
        Port(number=80, protocol=Protocol.TCP),
        Port(number=443, protocol=Protocol.TCP),
        Port(number=8080, protocol=Protocol.TCP),
    ]
    target = ScanTarget(host="example.com", ip="93.184.216.34", ports=ports)

    # Configure scan
    config = ScanConfig(
        target=target,
        timeout_ms=1000,
        max_concurrency=100,
        detect_services=True,
        grab_banners=True,
    )

    # Run scan
    scanner = PortScanner(config)
    results = await scanner.scan()

    # Process results
    for result in results:
        print(f"Port {result.port.number}: {result.state.value}")
        if result.service:
            print(f"  Service: {result.service}")
        if result.banner:
            print(f"  Banner: {result.banner}")

asyncio.run(main())
```

## Architecture

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

### Key Components

| Component | Purpose |
|-----------|---------|
| `models.py` | Immutable data models with validation |
| `scanner.py` | Async scanning engine with concurrency control |
| `output.py` | Pluggable output formatters |
| `cli.py` | Professional CLI with progress tracking |
| `services.py` | Service name database (47 common services) |

## Output Examples

### Table Output (Default)

```
┌───────┬──────────┬────────┬─────────────┬─────────────────┬───────────────┐
│  Port │ Protocol │ State  │   Service   │     Banner      │ Response Time │
├───────┼──────────┼────────┼─────────────┼─────────────────┼───────────────┤
│    80 │ tcp      │ open   │ http        │ Apache/2.4.41   │ 15.5ms        │
│   443 │ tcp      │ open   │ https       │                 │ 12.3ms        │
│  8080 │ tcp      │ closed │             │                 │ 0.0ms         │
└───────┴──────────┴────────┴─────────────┴─────────────────┴───────────────┘
```

### JSON Output

```json
{
  "scan_metadata": {
    "target": "example.com",
    "ip": "93.184.216.34",
    "timestamp": "2024-01-15T10:30:00Z",
    "total_ports_scanned": 3,
    "open_ports_count": 2
  },
  "results": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "banner": "Apache/2.4.41",
      "response_time_ms": 15.5
    }
  ]
}
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=port_scanner

# Run specific test file
pytest tests/test_scanner.py
```

### Code Quality

```bash
# Linting
ruff check src/ tests/

# Type checking
mypy src/

# Formatting
ruff format src/ tests/
```

## Use Cases

- **Network Administration** - Verify services are running on expected ports
- **Security Auditing** - Identify open ports and running services
- **Development** - Check if local services are accessible
- **DevOps** - Validate firewall rules and network configurations
- **Education** - Learn about networking and async programming in Python

## Technical Highlights

This project demonstrates:

- **Async Programming** - Efficient I/O-bound operations with asyncio
- **Type Safety** - Full type hints with mypy strict mode
- **Clean Architecture** - Separation of concerns with clear module boundaries
- **Immutable Data** - Frozen dataclasses for thread-safe state management
- **Professional CLI** - Intuitive interface with Click and Rich
- **Comprehensive Testing** - Unit tests with pytest and mocking
- **Modern Python** - Python 3.10+ features (match statements, union types)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Dinesh Raya** - [GitHub](https://github.com/Dinesh-raya)
