"""Output formatters for scan results.

Provides JSON, CSV, Rich table, and plain text formatters for presenting
port scan results in various output formats.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from rich.table import Table

from port_scanner.models import PortState, ScanResult, ScanTarget


@runtime_checkable
class OutputFormatter(Protocol):
    """Protocol for output formatters."""

    def format(self, results: list[ScanResult], target: ScanTarget) -> str:
        """Format scan results into a string representation.

        Args:
            results: List of scan results to format.
            target: The scan target metadata.

        Returns:
            Formatted string representation of the results.
        """
        ...


class JSONFormatter:
    """Formats scan results as pretty-printed JSON.

    Produces structured JSON output including scan metadata, target information,
    and all scan results with their details.
    """

    def format(self, results: list[ScanResult], target: ScanTarget) -> str:
        """Format results as JSON.

        Args:
            results: List of scan results to format.
            target: The scan target metadata.

        Returns:
            Pretty-printed JSON string.
        """
        open_ports = [r for r in results if r.state == PortState.OPEN]
        output = {
            "scan_metadata": {
                "target": target.host,
                "ip": target.ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_ports_scanned": len(results),
                "open_ports_count": len(open_ports),
            },
            "results": [
                {
                    "port": r.port.number,
                    "protocol": r.port.protocol.value,
                    "state": r.state.value,
                    "service": r.service,
                    "banner": r.banner,
                    "response_time_ms": round(r.response_time_ms, 2),
                }
                for r in results
            ],
        }
        return json.dumps(output, indent=2)


class CSVFormatter:
    """Formats scan results as CSV.

    Produces RFC 4180 compliant CSV output with proper escaping of fields
    containing commas, quotes, or newlines.
    """

    def format(self, results: list[ScanResult], target: ScanTarget) -> str:
        """Format results as CSV.

        Args:
            results: List of scan results to format.
            target: The scan target metadata.

        Returns:
            CSV string with header row and result rows.
        """
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["port", "protocol", "state", "service", "banner", "response_time_ms"])
        for r in results:
            writer.writerow(
                [
                    r.port.number,
                    r.port.protocol.value,
                    r.state.value,
                    r.service or "",
                    r.banner or "",
                    round(r.response_time_ms, 2),
                ]
            )
        return output.getvalue()


class TableFormatter:
    """Formats scan results as a Rich table.

    Produces a styled table with color-coded port states and a summary footer.
    Designed for terminal display via the Rich library.
    """

    STATE_COLORS = {
        PortState.OPEN: "green",
        PortState.CLOSED: "red",
        PortState.FILTERED: "yellow",
    }

    def format(self, results: list[ScanResult], target: ScanTarget) -> str:
        """Format results as a Rich table string.

        Args:
            results: List of scan results to format.
            target: The scan target metadata.

        Returns:
            Rendered Rich table as a string.
        """
        table = Table(
            title=f"Port Scan Results: {target.host} ({target.ip})",
            show_lines=True,
            title_style="bold cyan",
        )
        table.add_column("Port", style="bold", justify="right", no_wrap=True)
        table.add_column("Protocol", style="cyan")
        table.add_column("State", justify="center")
        table.add_column("Service", style="magenta")
        table.add_column("Banner", max_width=40)
        table.add_column("Response (ms)", justify="right", no_wrap=True)

        open_count = 0
        closed_count = 0
        filtered_count = 0

        for r in results:
            color = self.STATE_COLORS.get(r.state, "white")
            state_text = f"[{color}]{r.state.value}[/{color}]"

            if r.state == PortState.OPEN:
                open_count += 1
            elif r.state == PortState.CLOSED:
                closed_count += 1
            else:
                filtered_count += 1

            table.add_row(
                str(r.port.number),
                r.port.protocol.value,
                state_text,
                r.service or "-",
                r.banner or "-",
                f"{r.response_time_ms:.2f}",
            )

        table.add_section()
        table.add_row(
            "",
            "",
            f"[green]{open_count} open[/green]",
            f"[red]{closed_count} closed[/red]",
            f"[yellow]{filtered_count} filtered[/yellow]",
            "",
        )

        console_file = io.StringIO()
        from rich.console import Console

        console = Console(file=console_file, force_terminal=True, width=120)
        console.print(table)
        return console_file.getvalue()


class PlainTextFormatter:
    """Formats scan results as plain text.

    Produces simple, machine-parseable output with one line per open port.
    Suitable for piping to other tools or scripts.
    """

    def format(self, results: list[ScanResult], target: ScanTarget) -> str:
        """Format results as plain text.

        Args:
            results: List of scan results to format.
            target: The scan target metadata.

        Returns:
            Plain text string with one line per open port.
        """
        lines = [f"# Scan results for {target.host} ({target.ip})", ""]
        open_results = [r for r in results if r.state == PortState.OPEN]

        if not open_results:
            lines.append("No open ports found.")
        else:
            lines.append(f"Open ports: {len(open_results)}")
            lines.append("")
            for r in open_results:
                service = f" ({r.service})" if r.service else ""
                banner = f" - {r.banner}" if r.banner else ""
                lines.append(f"{r.port.number}/{r.port.protocol.value}{service}{banner}")

        return "\n".join(lines)


_FORMATTERS: dict[str, type[OutputFormatter]] = {
    "json": JSONFormatter,
    "csv": CSVFormatter,
    "table": TableFormatter,
    "text": PlainTextFormatter,
}


def get_formatter(format_name: str) -> OutputFormatter:
    """Get an output formatter by name.

    Args:
        format_name: Name of the formatter (json, csv, table, text).

    Returns:
        An instance of the requested formatter.

    Raises:
        ValueError: If format_name is not recognized.
    """
    formatter_cls = _FORMATTERS.get(format_name.lower())
    if formatter_cls is None:
        valid = ", ".join(sorted(_FORMATTERS.keys()))
        raise ValueError(f"Unknown format '{format_name}'. Valid formats: {valid}")
    return formatter_cls()
