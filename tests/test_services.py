"""Tests for the services module."""

import json
import tempfile
from pathlib import Path

import pytest

from port_scanner.services import ServiceDB


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the ServiceDB cache before and after each test."""
    ServiceDB.clear_cache()
    yield
    ServiceDB.clear_cache()


@pytest.fixture
def ports_json_file(tmp_path: Path) -> Path:
    """Create a temporary ports JSON file for testing."""
    data = {
        "ports": [
            {"port": 80, "protocol": "tcp", "service": "http"},
            {"port": 443, "protocol": "tcp", "service": "https"},
            {"port": 53, "protocol": "tcp/udp", "service": "dns"},
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 67, "protocol": "udp", "service": "dhcp-server"},
        ]
    }
    file_path = tmp_path / "ports.json"
    file_path.write_text(json.dumps(data), encoding="utf-8")
    return file_path


class TestServiceDB:
    """Tests for the ServiceDB class."""

    def test_load_from_json_file(self, ports_json_file: Path) -> None:
        """Test loading service database from a JSON file."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(80, "tcp") == "http"
        assert db.get_service_name(443, "tcp") == "https"
        assert db.get_service_name(22, "tcp") == "ssh"

    def test_get_service_name_known_port(self, ports_json_file: Path) -> None:
        """Test looking up a known port."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(80, "tcp") == "http"

    def test_get_service_name_unknown_port(self, ports_json_file: Path) -> None:
        """Test looking up an unknown port returns 'unknown'."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(9999, "tcp") == "unknown"

    def test_get_service_name_wrong_protocol(self, ports_json_file: Path) -> None:
        """Test looking up a port with wrong protocol returns 'unknown'."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(80, "udp") == "unknown"

    def test_protocol_splitting_tcp_udp(self, ports_json_file: Path) -> None:
        """Test that entries with 'tcp/udp' protocol are stored for both."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(53, "tcp") == "dns"
        assert db.get_service_name(53, "udp") == "dns"

    def test_udp_service_lookup(self, ports_json_file: Path) -> None:
        """Test looking up a UDP-only service."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(67, "udp") == "dhcp-server"

    def test_missing_file(self, tmp_path: Path) -> None:
        """Test loading from a non-existent file returns 'unknown' for all ports."""
        db = ServiceDB(ports_file=tmp_path / "nonexistent.json")
        assert db.get_service_name(80, "tcp") == "unknown"

    def test_clear_cache(self, ports_json_file: Path) -> None:
        """Test that clear_cache resets the cache."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(80, "tcp") == "http"

        ServiceDB.clear_cache()
        assert ServiceDB._cache is None
        assert ServiceDB._cache_file is None

    def test_cache_reuse(self, ports_json_file: Path) -> None:
        """Test that a second instance reuses the cached data."""
        db1 = ServiceDB(ports_file=ports_json_file)
        assert db1.get_service_name(80, "tcp") == "http"

        db2 = ServiceDB(ports_file=ports_json_file)
        assert db2.get_service_name(80, "tcp") == "http"
        assert ServiceDB._cache is not None

    def test_different_file_reloads_cache(self, tmp_path: Path) -> None:
        """Test that using a different file triggers a reload."""
        data1 = {"ports": [{"port": 80, "protocol": "tcp", "service": "http"}]}
        file1 = tmp_path / "ports1.json"
        file1.write_text(json.dumps(data1), encoding="utf-8")

        data2 = {"ports": [{"port": 8080, "protocol": "tcp", "service": "http-alt"}]}
        file2 = tmp_path / "ports2.json"
        file2.write_text(json.dumps(data2), encoding="utf-8")

        db1 = ServiceDB(ports_file=file1)
        assert db1.get_service_name(80, "tcp") == "http"

        db2 = ServiceDB(ports_file=file2)
        assert db2.get_service_name(8080, "tcp") == "http-alt"

    def test_default_protocol_is_tcp(self, ports_json_file: Path) -> None:
        """Test that default protocol parameter is 'tcp'."""
        db = ServiceDB(ports_file=ports_json_file)
        assert db.get_service_name(80) == "http"

    def test_empty_ports_list(self, tmp_path: Path) -> None:
        """Test loading a JSON with an empty ports list."""
        data = {"ports": []}
        file_path = tmp_path / "empty.json"
        file_path.write_text(json.dumps(data), encoding="utf-8")
        db = ServiceDB(ports_file=file_path)
        assert db.get_service_name(80, "tcp") == "unknown"

    def test_entry_without_protocol_field(self, tmp_path: Path) -> None:
        """Test that entries missing protocol field default to tcp."""
        data = {"ports": [{"port": 8080, "service": "http-alt"}]}
        file_path = tmp_path / "noproto.json"
        file_path.write_text(json.dumps(data), encoding="utf-8")
        db = ServiceDB(ports_file=file_path)
        assert db.get_service_name(8080, "tcp") == "http-alt"

    def test_load_from_real_file(self) -> None:
        """Test loading from the actual commonPorts.json file."""
        db = ServiceDB()
        assert db.get_service_name(80, "tcp") == "http"
        assert db.get_service_name(443, "tcp") == "https"
        assert db.get_service_name(22, "tcp") == "ssh"

    def test_cache_none_returns_unknown(self) -> None:
        """Test that get_service_name returns 'unknown' when cache is None."""
        ServiceDB._cache = None
        ServiceDB._cache_file = None
        db = ServiceDB.__new__(ServiceDB)
        # Manually set _ports_file to avoid loading
        db._ports_file = Path("/nonexistent")
        # The cache should remain None if the file doesn't exist
        ServiceDB._cache = None
        assert db.get_service_name(80, "tcp") == "unknown"
