# Port Scanner - Professional Security Toolkit

**Date:** 2026-05-30
**Status:** Approved
**Scope:** Flagship portfolio project

---

## 1. Overview

A professional-grade async port scanner with service detection, designed to be a portfolio centerpiece demonstrating Python mastery, networking knowledge, and software engineering best practices.

### Goals
- **Learning showcase:** Demonstrate async/await, OOP, testing, CLI design
- **Practical utility:** Genuinely useful for network admins and security professionals
- **Interview talking point:** Show depth in networking, concurrency, and clean architecture

### Key Features
- Async TCP/UDP scanning with configurable concurrency
- Service detection and banner grabbing
- Rich CLI with progress bars and colored output
- Multiple output formats (table, JSON, CSV, grepable)
- Comprehensive test suite with 90%+ coverage
- Professional packaging for PyPI distribution

---

## 2. Architecture

### Layered Design

```
┌─────────────────────────────────────────────┐
│                   CLI Layer                  │  ← User interface, argument parsing
├─────────────────────────────────────────────┤
│                Scanner Engine                │  ← Orchestration, async execution
├─────────────────────────────────────────────┤
│              Protocol Handlers               │  ← TCP, UDP, service detection
├─────────────────────────────────────────────┤
│              Output Formatters               │  ← JSON, CSV, table, rich console
└─────────────────────────────────────────────┘
```

### Design Principles
- **Single Responsibility:** Each module does one thing well
- **Dependency Inversion:** High-level modules don't depend on low-level details
- **Open/Closed:** Easy to add new scanners or output formats without modifying core
- **Async-First:** All network operations are async for performance

### Package Structure

```
port_scanner/
├── src/
│   └── port_scanner/
│       ├── __init__.py
│       ├── cli.py              # CLI entry point
│       ├── scanner.py          # Core scanning engine
│       ├── protocols/          # Protocol-specific handlers
│       │   ├── tcp.py
│       │   ├── udp.py
│       │   └── service.py      # Service detection & banners
│       ├── output/             # Output formatters
│       │   ├── json.py
│       │   ├── csv.py
│       │   ├── table.py
│       │   └── console.py      # Rich console output
│       └── utils/              # Shared utilities
│           ├── ports.py        # Port database management
│           ├── network.py      # Network helpers
│           └── config.py       # Configuration handling
├── tests/
│   ├── unit/
│   │   ├── test_scanner.py
│   │   ├── test_protocols.py
│   │   ├── test_services.py
│   │   ├── test_output.py
│   │   └── test_utils.py
│   ├── integration/
│   │   ├── test_cli.py
│   │   └── test_scanning.py
│   └── conftest.py
├── pyproject.toml
├── README.md
├── LICENSE
└── commonPorts.json
```

---

## 3. Core Scanner Engine

### Data Models

```python
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv4Network

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"

@dataclass
class ScanTarget:
    host: str
    ip: IPv4Address

@dataclass
class PortSpec:
    ports: list[int]
    
    @classmethod
    def parse(cls, spec: str) -> "PortSpec":
        """Parse port specification.
        
        Supported formats:
        - Single ports: "22" → [22]
        - Comma-separated: "22,80,443" → [22, 80, 443]
        - Ranges: "1-1000" → [1, 2, ..., 1000]
        - Mixed: "22,80,100-200" → [22, 80, 100, 101, ..., 200]
        - Presets: "top100", "top1000", "common" → predefined port lists
        """

@dataclass
class ServiceInfo:
    name: str
    version: str | None
    confidence: float  # 0.0 to 1.0

@dataclass
class ScanResult:
    port: int
    protocol: str
    state: PortState
    service: ServiceInfo | None
    banner: str | None
    response_time: float

@dataclass
class ScanConfig:
    timeout: float = 1.0
    max_concurrent: int = 100
    rate_limit: int | None = None  # requests per second
    grab_banners: bool = True
    detect_services: bool = True

@dataclass
class ScanResults:
    target: ScanTarget
    results: list[ScanResult]
    scan_time: float
    ports_scanned: int
```

### Scanner Engine

```python
class ScannerEngine:
    """Main scanning orchestrator"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
    
    async def scan(self, target: ScanTarget, ports: PortSpec) -> ScanResults:
        """Execute scan with controlled concurrency"""
        
    async def _scan_port(self, target: ScanTarget, port: int) -> ScanResult:
        """Scan single port with semaphore control"""
        
    async def cancel(self):
        """Gracefully cancel ongoing scan"""
```

### Scan Flow
1. Parse target (IP/hostname/CIDR)
2. Parse port specification
3. Create async tasks for each port
4. Execute with semaphore-controlled concurrency
5. Collect results as they complete
6. Pass to output formatter

---

## 4. Protocol Handlers

### TCP Scanner
- Connect scan (TCP handshake)
- Configurable timeout per port
- Banner grabbing (read initial response bytes)
- Service fingerprinting based on banner patterns

### UDP Scanner
- UDP probe with ICMP unreachable detection
- Common UDP service probes (DNS query, SNMP Get, NTP request)
- Timeout handling (UDP is connectionless, default 3s timeout)
- State determination:
  - Response received → OPEN
  - ICMP port unreachable → CLOSED
  - No response after timeout → FILTERED (assumed open)

### Service Detection

```python
class ServiceDetector:
    """Identifies services from banners and port knowledge"""
    
    # Banner patterns for common services
    PATTERNS = {
        b"SSH-": ("ssh", None),
        b"HTTP/": ("http", None),
        b"220 ": ("ftp", None),
        b"+OK": ("pop3", None),
        b"* OK": ("imap", None),
        b"220-SMTP": ("smtp", None),
        b"\x00\x00\x00": ("smb", None),
        b"RFB ": ("vnc", None),
        b"REDIS": ("redis", None),
        b"\x03\x00\x00": ("rdp", None),
    }
    
    async def detect(port: int, banner: bytes | None) -> ServiceInfo:
        # 1. Check banner against known patterns
        # 2. Fall back to port-based lookup from commonPorts.json
        # 3. Return service name, version hint, confidence level
```

### Banner Database
- Extends `commonPorts.json` with banner patterns
- Port → service name mapping
- Banner patterns → version detection
- Extensible via external JSON files

---

## 5. CLI & User Interface

### CLI Design (argparse + rich)

```bash
# Basic usage
port-scanner 192.168.1.1

# Scan specific ports
port-scanner 192.168.1.1 -p 22,80,443

# Scan port range
port-scanner 192.168.1.1 -p 1-1000

# Scan with service detection
port-scanner 192.168.1.1 --services

# Output as JSON
port-scanner 192.168.1.1 -o json

# Scan network range
port-scanner 192.168.1.0/24 -p 22,80

# Verbose mode with progress
port-scanner 192.168.1.1 -v --progress
```

### Features
- **Intuitive argument parsing** with helpful error messages
- **Progress bars** using `rich.progress` for long scans
- **Colored output** for different port states (open=green, closed=red, filtered=yellow)
- **Multiple output formats:** table (default), JSON, CSV, grepable
- **Verbose/quiet modes** for different use cases
- **Help text** with examples for each option

### Rich Console Output Example

```
╭─────────────────────────────────────╮
│  Port Scanner v1.0.0               │
│  Target: 192.168.1.1               │
│  Ports: 1-1000                     │
╰─────────────────────────────────────╯

Scanning... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

PORT     STATE    SERVICE      VERSION
22/tcp   open     ssh          OpenSSH 8.9p1
80/tcp   open     http         nginx 1.24.0
443/tcp  open     https        
3306/tcp closed   mysql        

Scan complete: 3 open, 997 closed (2.34s)
```

---

## 6. Output Formatters

### Interface

```python
class OutputFormatter(ABC):
    @abstractmethod
    def format_header(self, target: ScanTarget, config: ScanConfig) -> str: ...
    
    @abstractmethod
    def format_result(self, result: ScanResult) -> str: ...
    
    @abstractmethod
    def format_footer(self, results: ScanResults) -> str: ...
    
    def format_all(self, results: ScanResults) -> str:
        """Complete formatted output"""
```

### Implementations
- **TableFormatter:** Rich table with colors (default)
- **JsonFormatter:** JSON output for scripting
- **CsvFormatter:** CSV for spreadsheets
- **GrepableFormatter:** Nmap-style grepable output

---

## 7. Testing Strategy

### Test Structure

```
tests/
├── unit/
│   ├── test_scanner.py      # Scanner engine logic
│   ├── test_protocols.py    # TCP/UDP handlers
│   ├── test_services.py     # Service detection
│   ├── test_output.py       # Output formatters
│   └── test_utils.py        # Utility functions
├── integration/
│   ├── test_cli.py          # CLI end-to-end
│   └── test_scanning.py     # Real network scans (localhost)
└── conftest.py              # Shared fixtures
```

### Testing Approach

1. **Unit Tests (mocked):**
   - Test scanner logic without real network calls
   - Mock socket connections for predictable results
   - Test edge cases: timeouts, connection refused, invalid targets

2. **Integration Tests:**
   - Test CLI argument parsing
   - Test output format generation
   - Test against localhost (real sockets, controlled environment)

3. **Test Coverage Target:** 90%+ for core modules

### Example Test

```python
@pytest.mark.asyncio
async def test_tcp_scan_open_port():
    scanner = TCPScanner(timeout=1.0)
    result = await scanner.scan("127.0.0.1", 22)
    assert result.state == PortState.OPEN
    assert result.port == 22
```

---

## 8. Packaging & Distribution

### pyproject.toml

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "port-scanner"
version = "1.0.0"
description = "A professional async port scanner with service detection"
readme = "README.md"
license = "MIT"
requires-python = ">=3.9"
dependencies = [
    "rich>=13.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "pytest-asyncio>=0.21",
]

[project.scripts]
port-scanner = "port_scanner.cli:main"
```

### Installation Methods

```bash
# From PyPI (after publishing)
pip install port-scanner

# From source (development)
pip install -e ".[dev]"

# Run directly
python -m port_scanner
```

---

## 9. Dependencies

### Runtime
- `rich>=13.0` - Beautiful terminal output, progress bars, tables

### Development
- `pytest>=7.0` - Testing framework
- `pytest-cov>=4.0` - Coverage reporting
- `pytest-asyncio>=0.21` - Async test support

### Standard Library Only
- `socket` - Low-level networking
- `asyncio` - Async I/O
- `argparse` - CLI parsing
- `json` - Configuration files
- `ipaddress` - IP/network parsing
- `dataclasses` - Data models
- `enum` - enumerations
- `abc` - Abstract base classes
- `pathlib` - File paths
- `typing` - Type hints

---

## 10. Success Criteria

### Portfolio Impact
- [ ] Clean, readable code with type hints throughout
- [ ] Comprehensive docstrings for all public APIs
- [ ] Professional README with usage examples
- [ ] 90%+ test coverage
- [ ] Async scanning 10x+ faster than synchronous
- [ ] Service detection for 50+ common services
- [ ] Multiple output formats working
- [ ] Published to PyPI (optional but impressive)

### Technical Quality
- [ ] All tests passing
- [ ] No linting errors
- [ ] Type checking passes (mypy)
- [ ] Graceful error handling
- [ ] Clean cancellation support

---

## 11. Implementation Order

1. **Phase 1: Foundation**
   - Project structure and packaging
   - Core data models
   - Basic TCP scanner

2. **Phase 2: Engine**
   - Async scanner engine
   - Concurrency control
   - Progress tracking

3. **Phase 3: Protocols**
   - UDP scanner
   - Service detection
   - Banner grabbing

4. **Phase 4: Interface**
   - CLI with argparse
   - Rich console output
   - Output formatters

5. **Phase 5: Quality**
   - Comprehensive tests
   - Documentation
   - README with examples

6. **Phase 6: Polish**
   - Error handling refinement
   - Performance optimization
   - PyPI preparation
