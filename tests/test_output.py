"""Tests for the output module."""

import csv
import io
import json

import pytest

from port_scanner.models import (
    Port,
    PortState,
    Protocol,
    ScanResult,
    ScanTarget,
)
from port_scanner.output import (
    CSVFormatter,
    JSONFormatter,
    PlainTextFormatter,
    TableFormatter,
    get_formatter,
)


@pytest.fixture
def sample_results() -> list[ScanResult]:
    """Create sample scan results for testing."""
    return [
        ScanResult(
            port=Port(number=80, protocol=Protocol.TCP),
            state=PortState.OPEN,
            service="http",
            banner="Apache/2.4.41",
            response_time_ms=15.5,
        ),
        ScanResult(
            port=Port(number=443, protocol=Protocol.TCP),
            state=PortState.OPEN,
            service="https",
            banner=None,
            response_time_ms=12.3,
        ),
        ScanResult(
            port=Port(number=8080, protocol=Protocol.TCP),
            state=PortState.CLOSED,
            service=None,
            banner=None,
            response_time_ms=0.0,
        ),
    ]


@pytest.fixture
def sample_target() -> ScanTarget:
    """Create a sample scan target for testing."""
    return ScanTarget(
        host="example.com",
        ip="93.184.216.34",
        ports=[Port(number=80, protocol=Protocol.TCP)],
    )


class TestJSONFormatter:
    """Tests for the JSONFormatter."""

    def test_json_output_is_valid(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = JSONFormatter()
        output = formatter.format(sample_results, sample_target)
        data = json.loads(output)
        assert "scan_metadata" in data
        assert "results" in data

    def test_json_contains_all_results(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = JSONFormatter()
        output = formatter.format(sample_results, sample_target)
        data = json.loads(output)
        assert len(data["results"]) == 3

    def test_json_result_fields(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = JSONFormatter()
        output = formatter.format(sample_results, sample_target)
        data = json.loads(output)
        result = data["results"][0]
        assert "port" in result
        assert "state" in result
        assert "service" in result
        assert "response_time_ms" in result

    def test_json_metadata_fields(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = JSONFormatter()
        output = formatter.format(sample_results, sample_target)
        data = json.loads(output)
        metadata = data["scan_metadata"]
        assert metadata["target"] == "example.com"
        assert metadata["ip"] == "93.184.216.34"
        assert metadata["open_ports_count"] == 2
        assert metadata["total_ports_scanned"] == 3


class TestCSVFormatter:
    """Tests for the CSVFormatter."""

    def test_csv_has_header(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = CSVFormatter()
        output = formatter.format(sample_results, sample_target)
        lines = output.strip().split("\n")
        header = lines[0]
        assert "port" in header
        assert "state" in header

    def test_csv_row_count(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = CSVFormatter()
        output = formatter.format(sample_results, sample_target)
        lines = output.strip().split("\n")
        # Header + 3 data rows
        assert len(lines) == 4

    def test_csv_is_parseable(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = CSVFormatter()
        output = formatter.format(sample_results, sample_target)
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 3
        assert rows[0]["port"] == "80"
        assert rows[0]["state"] == "open"


class TestPlainTextFormatter:
    """Tests for the PlainTextFormatter."""

    def test_text_output_contains_open_ports(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = PlainTextFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "80/tcp" in output
        assert "443/tcp" in output

    def test_text_output_contains_services(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = PlainTextFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "http" in output

    def test_text_output_shows_open_count(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        formatter = PlainTextFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "Open ports: 2" in output

    def test_text_no_open_ports(self, sample_target: ScanTarget) -> None:
        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.CLOSED,
                service=None,
                banner=None,
                response_time_ms=0.0,
            )
        ]
        formatter = PlainTextFormatter()
        output = formatter.format(results, sample_target)
        assert "No open ports found" in output

    def test_text_with_banner(self, sample_target: ScanTarget) -> None:
        """Test that plain text output includes banner when present."""
        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner="Apache/2.4.41",
                response_time_ms=15.5,
            )
        ]
        formatter = PlainTextFormatter()
        output = formatter.format(results, sample_target)
        assert "Apache/2.4.41" in output

    def test_text_without_service(self, sample_target: ScanTarget) -> None:
        """Test plain text output when service is None."""
        results = [
            ScanResult(
                port=Port(number=9999, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service=None,
                banner=None,
                response_time_ms=5.0,
            )
        ]
        formatter = PlainTextFormatter()
        output = formatter.format(results, sample_target)
        assert "9999/tcp" in output


class TestTableFormatter:
    """Tests for the TableFormatter."""

    def test_table_output_not_empty(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        """Test that TableFormatter produces non-empty output."""
        formatter = TableFormatter()
        output = formatter.format(sample_results, sample_target)
        assert len(output) > 0

    def test_table_contains_target_info(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        """Test that the table contains target host and IP."""
        formatter = TableFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "example.com" in output
        assert "93.184.216.34" in output

    def test_table_contains_port_numbers(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        """Test that the table contains port numbers."""
        formatter = TableFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "80" in output
        assert "443" in output
        assert "8080" in output

    def test_table_contains_state_info(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        """Test that the table contains state information."""
        formatter = TableFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "open" in output
        assert "closed" in output

    def test_table_contains_service_info(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        """Test that the table contains service names."""
        formatter = TableFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "http" in output
        assert "https" in output

    def test_table_contains_summary_row(
        self, sample_results: list[ScanResult], sample_target: ScanTarget
    ) -> None:
        """Test that the table contains a summary row."""
        formatter = TableFormatter()
        output = formatter.format(sample_results, sample_target)
        assert "open" in output
        assert "closed" in output
        assert "filtered" in output

    def test_table_filtered_results(self, sample_target: ScanTarget) -> None:
        """Test table with filtered port results."""
        results = [
            ScanResult(
                port=Port(number=443, protocol=Protocol.TCP),
                state=PortState.FILTERED,
                service=None,
                banner=None,
                response_time_ms=0.0,
            )
        ]
        formatter = TableFormatter()
        output = formatter.format(results, sample_target)
        assert "filtered" in output

    def test_table_empty_results(self, sample_target: ScanTarget) -> None:
        """Test table with no results."""
        formatter = TableFormatter()
        output = formatter.format([], sample_target)
        assert "example.com" in output

    def test_table_banner_truncation(self, sample_target: ScanTarget) -> None:
        """Test that long banners are handled."""
        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner="A" * 256,
                response_time_ms=15.5,
            )
        ]
        formatter = TableFormatter()
        output = formatter.format(results, sample_target)
        assert len(output) > 0

    def test_table_dash_for_missing_service(
        self, sample_target: ScanTarget
    ) -> None:
        """Test that missing services show as '-' in table."""
        results = [
            ScanResult(
                port=Port(number=9999, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service=None,
                banner=None,
                response_time_ms=5.0,
            )
        ]
        formatter = TableFormatter()
        output = formatter.format(results, sample_target)
        assert "-" in output

    def test_state_colors_mapping(self) -> None:
        """Test that STATE_COLORS has all port states."""
        assert PortState.OPEN in TableFormatter.STATE_COLORS
        assert PortState.CLOSED in TableFormatter.STATE_COLORS
        assert PortState.FILTERED in TableFormatter.STATE_COLORS


class TestGetFormatter:
    """Tests for the get_formatter factory."""

    def test_get_json_formatter(self) -> None:
        formatter = get_formatter("json")
        assert isinstance(formatter, JSONFormatter)

    def test_get_csv_formatter(self) -> None:
        formatter = get_formatter("csv")
        assert isinstance(formatter, CSVFormatter)

    def test_get_text_formatter(self) -> None:
        formatter = get_formatter("text")
        assert isinstance(formatter, PlainTextFormatter)

    def test_get_table_formatter(self) -> None:
        formatter = get_formatter("table")
        assert isinstance(formatter, TableFormatter)

    def test_get_unknown_formatter(self) -> None:
        with pytest.raises(ValueError, match="Unknown format"):
            get_formatter("xml")

    def test_case_insensitive(self) -> None:
        formatter = get_formatter("JSON")
        assert isinstance(formatter, JSONFormatter)

    def test_case_insensitive_table(self) -> None:
        formatter = get_formatter("TABLE")
        assert isinstance(formatter, TableFormatter)
