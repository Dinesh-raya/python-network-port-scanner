"""Tests for the __main__ module."""

import importlib
import subprocess
import sys

import pytest


class TestMainModule:
    """Tests for __main__.py."""

    def test_main_module_importable(self) -> None:
        """Test that __main__ module can be imported without error."""
        import port_scanner.__main__

        assert hasattr(port_scanner.__main__, "main")

    def test_main_module_runs(self) -> None:
        """Test that running as python -m port_scanner --help works."""
        result = subprocess.run(
            [sys.executable, "-m", "port_scanner", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "Port Scanner Pro" in result.stdout
