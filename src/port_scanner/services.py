"""Service name database for well-known ports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

_DEFAULT_PORTS_FILE: Final = Path(__file__).parent.parent.parent / "commonPorts.json"


class ServiceDB:
    """Lookup service names by port number.

    Loads the well-known ports database once and caches it for fast lookups.
    Uses a singleton-like pattern via the class-level cache.

    Args:
        ports_file: Path to the JSON ports database. Defaults to commonPorts.json.
    """

    _cache: dict[tuple[int, str], str] | None = None
    _cache_file: Path | None = None

    def __init__(self, ports_file: Path | None = None) -> None:
        self._ports_file = ports_file or _DEFAULT_PORTS_FILE
        self._load_if_needed()

    def _load_if_needed(self) -> None:
        """Load the ports database if not already cached or if file changed."""
        if ServiceDB._cache is not None and ServiceDB._cache_file == self._ports_file:
            return

        ServiceDB._cache = {}
        ServiceDB._cache_file = self._ports_file

        if not self._ports_file.exists():
            return

        with open(self._ports_file, encoding="utf-8") as f:
            data = json.load(f)

        for entry in data.get("ports", []):
            port_num = entry["port"]
            service = entry["service"]
            protocol = entry.get("protocol", "tcp")

            # Store for each applicable protocol
            if "/" in protocol:
                for proto in protocol.split("/"):
                    ServiceDB._cache[(port_num, proto)] = service
            else:
                ServiceDB._cache[(port_num, protocol)] = service

    def get_service_name(self, port_number: int, protocol: str = "tcp") -> str:
        """Look up the service name for a port.

        Args:
            port_number: The port number to look up.
            protocol: The protocol ("tcp" or "udp").

        Returns:
            The service name, or "unknown" if not found.
        """
        if ServiceDB._cache is None:
            return "unknown"
        return ServiceDB._cache.get((port_number, protocol), "unknown")

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the cached database. Useful for testing."""
        cls._cache = None
        cls._cache_file = None
