"""Tests for the CLI module."""

from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from port_scanner.cli import main


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


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
