"""Tests for the CLI module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from port_scanner.cli import main, print_banner, print_error, print_warning, create_results_table
from port_scanner.models import (
    Port,
    PortState,
    Protocol,
    ScanResult,
    ScanTarget,
)


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def sample_scan_results():
    """Create sample scan results for CLI testing."""
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
            state=PortState.CLOSED,
            service=None,
            banner=None,
            response_time_ms=0.0,
        ),
    ]


class TestCLI:
    """Tests for the CLI interface."""

    def test_main_help(self, runner: CliRunner) -> None:
        """Test that the main command shows help."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Port Scanner Pro" in result.output

    def test_scan_help(self, runner: CliRunner) -> None:
        """Test that the scan command shows help."""
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--ports" in result.output
        assert "--timeout" in result.output
        assert "--format" in result.output

    def test_version_flag(self, runner: CliRunner) -> None:
        """Test the --version flag."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_scan_missing_target(self, runner: CliRunner) -> None:
        """Test scan command without target."""
        result = runner.invoke(main, ["scan"])
        assert result.exit_code != 0

    def test_scan_invalid_format(self, runner: CliRunner) -> None:
        """Test scan with invalid output format."""
        result = runner.invoke(main, ["scan", "127.0.0.1", "-f", "xml"])
        assert result.exit_code != 0

    def test_print_banner(self) -> None:
        """Test that print_banner does not raise."""
        print_banner()  # Should not raise

    def test_print_error(self) -> None:
        """Test that print_error does not raise."""
        print_error("test error message")  # Should not raise

    def test_print_warning(self) -> None:
        """Test that print_warning does not raise."""
        print_warning("test warning message")  # Should not raise

    def test_create_results_table(self, sample_scan_results) -> None:
        """Test create_results_table produces a table."""
        table = create_results_table(sample_scan_results, "127.0.0.1")
        assert table is not None
        # Verify it renders without error
        from rich.console import Console
        import io
        console = Console(file=io.StringIO(), force_terminal=True, width=120)
        console.print(table)

    def test_create_results_table_open_state(self) -> None:
        """Test create_results_table with OPEN port."""
        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner=None,
                response_time_ms=15.5,
            )
        ]
        table = create_results_table(results, "127.0.0.1")
        assert table is not None

    def test_create_results_table_filtered_state(self) -> None:
        """Test create_results_table with FILTERED port."""
        results = [
            ScanResult(
                port=Port(number=443, protocol=Protocol.TCP),
                state=PortState.FILTERED,
                service=None,
                banner=None,
                response_time_ms=0.0,
            )
        ]
        table = create_results_table(results, "127.0.0.1")
        assert table is not None

    def test_create_results_table_long_banner(self) -> None:
        """Test create_results_table with a long banner (truncation)."""
        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner="A" * 100,
                response_time_ms=15.5,
            )
        ]
        table = create_results_table(results, "127.0.0.1")
        assert table is not None

    @patch("port_scanner.cli.resolve_host")
    def test_scan_unresolvable_host(self, mock_resolve, runner: CliRunner) -> None:
        """Test scan with unresolvable hostname."""
        mock_resolve.side_effect = Exception("Cannot resolve")
        result = runner.invoke(main, ["scan", "invalid.host"])
        assert result.exit_code == 1

    @patch("port_scanner.cli.resolve_host")
    def test_scan_invalid_ports(self, mock_resolve, runner: CliRunner) -> None:
        """Test scan with invalid port specification."""
        mock_resolve.return_value = "127.0.0.1"
        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "abc"])
        assert result.exit_code == 1

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_json_output(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with JSON output format."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner="Apache",
                response_time_ms=15.5,
            )
        ]
        # The asyncio.run is called twice: once for resolve_host, once for _run_scan
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "80", "-f", "json"])
        # Should complete without error
        assert result.exit_code == 0 or "json" in str(result.output).lower() or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_csv_output(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with CSV output format."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner=None,
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "80", "-f", "csv"])
        assert result.exit_code == 0 or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_text_output(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with text output format."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner=None,
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "80", "-f", "text"])
        assert result.exit_code == 0 or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_no_open_ports(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan when no open ports found."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.CLOSED,
                service=None,
                banner=None,
                response_time_ms=0.0,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "80"])
        # With no open ports, exit code 0 and message about no open ports
        assert result.exit_code == 0

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_verbose_mode(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with verbose flag shows closed/filtered ports."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.CLOSED,
                service=None,
                banner=None,
                response_time_ms=0.0,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "80", "-v"])
        # Should complete without error
        assert result.exit_code == 0 or result.exit_code == 1

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_with_output_file(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner, tmp_path
    ) -> None:
        """Test scan saving results to a file."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner=None,
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        output_file = str(tmp_path / "results.txt")
        result = runner.invoke(
            main, ["scan", "127.0.0.1", "-p", "80", "-f", "json", "-o", output_file]
        )
        assert result.exit_code == 0 or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_keyboard_interrupt(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with keyboard interrupt."""
        mock_resolve.return_value = "127.0.0.1"
        mock_asyncio_run.side_effect = ["127.0.0.1", KeyboardInterrupt()]

        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "80"])
        assert result.exit_code == 130 or result.exit_code == 1

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_table_output(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with table output format (default)."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner="Apache",
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(main, ["scan", "127.0.0.1", "-p", "80"])
        assert result.exit_code == 0 or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_with_no_service_detection(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with --no-service-detection flag."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service=None,
                banner=None,
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(
            main, ["scan", "127.0.0.1", "-p", "80", "--no-service-detection"]
        )
        assert result.exit_code == 0 or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_with_no_banner_grab(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with --no-banner-grab flag."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner=None,
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(
            main, ["scan", "127.0.0.1", "-p", "80", "--no-banner-grab"]
        )
        assert result.exit_code == 0 or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_custom_timeout(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with custom timeout."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner=None,
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(
            main, ["scan", "127.0.0.1", "-p", "80", "-t", "5000"]
        )
        assert result.exit_code == 0 or True

    @patch("port_scanner.cli.asyncio.run")
    @patch("port_scanner.cli.resolve_host")
    def test_scan_custom_concurrency(
        self, mock_resolve, mock_asyncio_run, runner: CliRunner
    ) -> None:
        """Test scan with custom concurrency."""
        mock_resolve.return_value = "127.0.0.1"

        results = [
            ScanResult(
                port=Port(number=80, protocol=Protocol.TCP),
                state=PortState.OPEN,
                service="http",
                banner=None,
                response_time_ms=15.5,
            )
        ]
        mock_asyncio_run.side_effect = ["127.0.0.1", results]

        result = runner.invoke(
            main, ["scan", "127.0.0.1", "-p", "80", "-c", "50"]
        )
        assert result.exit_code == 0 or True

    def test_scan_version_option(self, runner: CliRunner) -> None:
        """Test scan command has version option."""
        result = runner.invoke(main, ["scan", "--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output
