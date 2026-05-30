"""Async port scanning engine with concurrency control and service detection."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from port_scanner.models import Port, PortState, Protocol, ScanConfig, ScanResult

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Type alias for progress callback
ProgressCallback = Callable[[int, int], None] | None

# Common UDP probes per service
_UDP_PROBES: dict[int, bytes] = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    67: b"\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00",
    123: b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63",
    500: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    514: b"\x3c\x31\x34\x3e\x4a\x61\x6e\x20",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n",
}

# Default probe for unknown UDP ports
_DEFAULT_UDP_PROBE = b"\x00" * 16


class PortScanner:
    """Async port scanner with concurrency control, banner grabbing, and service detection.

    Supports both TCP connect scanning and UDP probing with configurable
    concurrency limits and progress callbacks for UI integration.

    Example::

        config = ScanConfig(
            target=target,
            timeout_ms=1000,
            max_concurrency=100,
            detect_services=True,
            grab_banners=True,
        )
        scanner = PortScanner(config)
        results = await scanner.scan()
    """

    def __init__(
        self,
        config: ScanConfig,
        service_db: object | None = None,
        progress_callback: ProgressCallback = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            config: Scan configuration including target, timeout, and concurrency settings.
            service_db: Optional ServiceDB instance for port-to-service name mapping.
            progress_callback: Optional callback ``(completed, total)`` invoked after each port scan.
        """
        self._config = config
        self._progress_callback = progress_callback

        # Create default ServiceDB if none provided
        if service_db is None and config.detect_services:
            from port_scanner.services import ServiceDB
            self._service_db = ServiceDB()
        else:
            self._service_db = service_db
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._completed = 0
        self._total = len(config.target.ports)
        self._lock = asyncio.Lock()

    async def scan(self) -> list[ScanResult]:
        """Scan all ports on the configured target.

        Returns:
            List of ScanResult objects sorted by port number.

        Raises:
            ValueError: If target has no ports to scan.
        """
        if not self._config.target.ports:
            raise ValueError("No ports to scan")

        self._completed = 0
        self._total = len(self._config.target.ports)

        logger.info(
            "Starting scan of %s (%s) - %d ports, concurrency=%d",
            self._config.target.host,
            self._config.target.ip,
            self._total,
            self._config.max_concurrency,
        )

        tasks = [self._scan_with_semaphore(port) for port in self._config.target.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        scan_results: list[ScanResult] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Scan task failed: %s", result)
            else:
                scan_results.append(result)

        scan_results.sort(key=lambda r: r.port.number)

        logger.info(
            "Scan complete: %d open, %d closed, %d filtered",
            sum(1 for r in scan_results if r.state == PortState.OPEN),
            sum(1 for r in scan_results if r.state == PortState.CLOSED),
            sum(1 for r in scan_results if r.state == PortState.FILTERED),
        )

        return scan_results

    async def scan_port(self, port: Port) -> ScanResult:
        """Scan a single port.

        Args:
            port: The port to scan.

        Returns:
            ScanResult for the port.
        """
        return await self._scan_port(port)

    async def _scan_with_semaphore(self, port: Port) -> ScanResult:
        """Scan a port with semaphore-based concurrency control."""
        async with self._semaphore:
            result = await self._scan_port(port)
            async with self._lock:
                self._completed += 1
                if self._progress_callback:
                    self._progress_callback(self._completed, self._total)
            return result

    async def _scan_port(self, port: Port) -> ScanResult:
        """Dispatch to the appropriate scanner based on protocol."""
        if port.protocol == Protocol.TCP:
            return await self._scan_tcp(port)
        else:
            return await self._scan_udp(port)

    async def _scan_tcp(self, port: Port) -> ScanResult:
        """Scan a TCP port using connect scan with optional banner grabbing.

        Args:
            port: TCP port to scan.

        Returns:
            ScanResult with state, service, and banner information.
        """
        timeout_s = self._config.timeout_ms / 1000.0
        start_time = time.monotonic()
        banner: str | None = None
        state = PortState.FILTERED

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._config.target.ip, port.number),
                timeout=timeout_s,
            )
            state = PortState.OPEN
            elapsed_ms = (time.monotonic() - start_time) * 1000

            if self._config.grab_banners:
                banner = await self._grab_banner_tcp(reader, writer, timeout_s)

            writer.close()
            await writer.wait_closed()

        except ConnectionRefusedError:
            state = PortState.CLOSED
            elapsed_ms = (time.monotonic() - start_time) * 1000

        except (TimeoutError, asyncio.TimeoutError):
            state = PortState.FILTERED
            elapsed_ms = (time.monotonic() - start_time) * 1000

        except OSError as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            if e.errno == 113:  # No route to host
                state = PortState.FILTERED
            elif e.errno == 111:  # Connection refused (Linux)
                state = PortState.CLOSED
            else:
                state = PortState.FILTERED
            logger.debug("TCP scan error on port %d: %s", port.number, e)

        service = self._get_service_name(port) if self._config.detect_services else None

        return ScanResult(
            port=port,
            state=state,
            service=service,
            banner=banner,
            response_time_ms=round(elapsed_ms, 2),
        )

    async def _grab_banner_tcp(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout_s: float,
    ) -> str | None:
        """Attempt to read a service banner from an open TCP connection.

        Args:
            reader: Stream reader for the connection.
            writer: Stream writer for the connection.
            timeout_s: Read timeout in seconds.

        Returns:
            Banner string if received, None otherwise.
        """
        try:
            # Some services need a prompt to send a banner
            peer = writer.get_extra_info("peername")
            if peer and len(peer) >= 2:
                probe = self._get_tcp_probe(peer[1])
                if probe:
                    writer.write(probe)
                    await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=min(timeout_s, 2.0))
            if data:
                # Clean up the banner: strip null bytes, newlines, limit length
                banner = data.decode("utf-8", errors="replace").strip()
                banner = banner.replace("\x00", "").strip()
                return banner[:256] if banner else None
        except (TimeoutError, asyncio.TimeoutError, OSError):
            pass
        return None

    def _get_tcp_probe(self, port: int) -> bytes | None:
        """Get a protocol-specific probe for banner grabbing.

        Args:
            port: Target port number.

        Returns:
            Probe bytes or None if no probe is needed.
        """
        probes = {
            80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            443: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            25: b"EHLO localhost\r\n",
            110: b"USER test\r\n",
            143: b"a001 CAPABILITY\r\n",
            21: b"USER anonymous\r\n",
            22: b"",  # SSH sends banner without prompt
            23: b"",  # Telnet sends banner without prompt
        }
        return probes.get(port)

    async def _scan_udp(self, port: Port) -> ScanResult:
        """Scan a UDP port by sending a probe and listening for responses.

        UDP scanning works by sending a probe packet and waiting for:
        - A response (port open)
        - ICMP port unreachable (port closed)
        - Timeout (port open|filtered)

        Args:
            port: UDP port to scan.

        Returns:
            ScanResult with state, service, and banner information.
        """
        timeout_s = self._config.timeout_ms / 1000.0
        start_time = time.monotonic()
        state = PortState.FILTERED
        banner: str | None = None

        try:
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(),
                remote_addr=(self._config.target.ip, port.number),
            )

            try:
                probe = _UDP_PROBES.get(port.number, _DEFAULT_UDP_PROBE)
                transport.sendto(probe)

                response = await asyncio.wait_for(
                    protocol.wait_for_response(),
                    timeout=timeout_s,
                )

                if response is not None:
                    state = PortState.OPEN
                    if self._config.grab_banners:
                        banner = response.decode("utf-8", errors="replace")[:256]
                else:
                    state = PortState.FILTERED

            finally:
                transport.close()

        except (TimeoutError, asyncio.TimeoutError):
            state = PortState.FILTERED

        except OSError as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            if e.errno == 111:  # Connection refused = ICMP unreachable
                state = PortState.CLOSED
            else:
                state = PortState.FILTERED
            logger.debug("UDP scan error on port %d: %s", port.number, e)

        elapsed_ms = (time.monotonic() - start_time) * 1000
        service = self._get_service_name(port) if self._config.detect_services else None

        return ScanResult(
            port=port,
            state=state,
            service=service,
            banner=banner,
            response_time_ms=round(elapsed_ms, 2),
        )

    def _get_service_name(self, port: Port) -> str | None:
        """Look up service name for a port.

        Args:
            port: Port to look up.

        Returns:
            Service name string or None if not found.
        """
        if self._service_db is not None:
            name = self._service_db.get_service_name(port.number, port.protocol.value)
            return name if name != "unknown" else None
        return None


class _UDPProtocol(asyncio.DatagramProtocol):
    """Protocol for UDP scanning that captures responses."""

    def __init__(self) -> None:
        self._response: bytes | None = None
        self._response_future: asyncio.Future[bytes | None] = asyncio.get_event_loop().create_future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Called when connection is established."""
        pass

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called when a datagram is received."""
        if not self._response_future.done():
            self._response = data
            self._response_future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        """Called when an error is received."""
        if not self._response_future.done():
            self._response_future.set_result(None)

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when the connection is lost."""
        if not self._response_future.done():
            self._response_future.set_result(None)

    async def wait_for_response(self) -> bytes | None:
        """Wait for a response or timeout.

        Returns:
            Response bytes or None if no response.
        """
        return await self._response_future
