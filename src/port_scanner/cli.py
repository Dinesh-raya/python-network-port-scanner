"""CLI interface for Port Scanner Pro.

Provides a professional command-line interface using Click and Rich
for formatted output, progress tracking, and multiple output formats.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from port_scanner import __version__
from port_scanner.models import Port, PortState, Protocol, ScanConfig, ScanTarget
from port_scanner.output import get_formatter
from port_scanner.scanner import PortScanner
from port_scanner.utils import parse_port_range, resolve_host, validate_target

console = Console(stderr=True)
output_console = Console()


def print_banner() -> None:
    """Display the application banner."""
    banner = (
        "[bold cyan]Port Scanner Pro[/] v{version}\n"
        "[dim]Professional async network port scanner[/]"
    ).format(version=__version__)
    console.print(Panel(banner, border_style="cyan", expand=False))


def print_error(message: str) -> None:
    """Print a formatted error message."""
    console.print(f"[bold red]Error:[/] {message}")


def print_warning(message: str) -> None:
    """Print a formatted warning message."""
    console.print(f"[bold yellow]Warning:[/] {message}")


def create_results_table(results: list, target_ip: str) -> Table:
    """Create a Rich table for displaying scan results.

    Args:
        results: List of ScanResult objects.
        target_ip: The scanned IP address.

    Returns:
        A Rich Table object ready for display.
    """
    table = Table(
        title=f"Scan Results for {target_ip}",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        caption="Port Scanner Pro",
    )
    table.add_column("Port", style="bold", justify="right", width=8)
    table.add_column("State", justify="center", width=10)
    table.add_column("Protocol", justify="center", width=10)
    table.add_column("Service", width=20)
    table.add_column("Banner", width=40)
    table.add_column("Response (ms)", justify="right", width=14)

    state_styles = {
        PortState.OPEN: "[bold green]open[/]",
        PortState.CLOSED: "[dim]closed[/]",
        PortState.FILTERED: "[yellow]filtered[/]",
    }

    for result in results:
        state_str = state_styles.get(result.state, result.state.value)
        service_str = result.service or "-"
        banner_str = result.banner[:40] + "..." if result.banner and len(result.banner) > 40 else (result.banner or "-")
        table.add_row(
            str(result.port.number),
            state_str,
            result.port.protocol.value,
            service_str,
            banner_str,
            f"{result.response_time_ms:.1f}",
        )

    return table


@click.group()
@click.version_option(version=__version__, prog_name="port-scanner")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Port Scanner Pro - Professional async network port scanner.

    A high-performance port scanner with service detection, banner grabbing,
    and multiple output formats. Built for security professionals and
    network administrators.

    \b
    Examples:
        port-scanner scan 192.168.1.1
        port-scanner scan example.com -p 80,443,8080
        port-scanner scan 10.0.0.1 -p 1-1000 -f json -o results.json
        port-scanner scan 192.168.1.1 -c 200 --no-banner-grab
    """
    ctx.ensure_object(dict)


@main.command()
@click.argument("target")
@click.option(
    "-p",
    "--ports",
    default="1-1000",
    help="Port specification: single (80), range (1-1000), or list (80,443,8080).",
)
@click.option(
    "-t",
    "--timeout",
    default=1000,
    type=click.IntRange(100, 30000),
    help="Connection timeout in milliseconds (100-30000).",
)
@click.option(
    "-c",
    "--concurrency",
    default=100,
    type=click.IntRange(1, 10000),
    help="Maximum concurrent connections (1-10000).",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv", "text"], case_sensitive=False),
    default="table",
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    help="Save results to file.",
)
@click.option(
    "--no-service-detection",
    is_flag=True,
    default=False,
    help="Disable service name detection.",
)
@click.option(
    "--no-banner-grab",
    is_flag=True,
    default=False,
    help="Disable banner grabbing.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Show closed and filtered ports in output.",
)
@click.version_option(version=__version__, prog_name="port-scanner")
def scan(
    target: str,
    ports: str,
    timeout: int,
    concurrency: int,
    output_format: str,
    output: str | None,
    no_service_detection: bool,
    no_banner_grab: bool,
    verbose: bool,
) -> None:
    """Scan ports on a target host.

    TARGET can be an IP address (192.168.1.1) or hostname (example.com).

    \b
    Examples:
        port-scanner scan 192.168.1.1
        port-scanner scan example.com -p 80,443
        port-scanner scan 10.0.0.1 -p 1-100 -f json -o scan.json
    """
    print_banner()

    # Validate target
    if not validate_target(target):
        print_error(f"Invalid target: {target}")
        sys.exit(1)

    # Resolve hostname
    console.print(f"[dim]Resolving {target}...[/]")
    ip = resolve_host(target)
    if ip is None:
        print_error(f"Could not resolve hostname: {target}")
        sys.exit(1)

    console.print(f"[green]Resolved:[/] {target} -> {ip}")

    # Parse ports
    try:
        port_numbers = parse_port_range(ports)
    except ValueError as e:
        print_error(f"Invalid port specification: {e}")
        sys.exit(1)

    if not port_numbers:
        print_error("No ports to scan.")
        sys.exit(1)

    # Create scan target
    scan_ports = [Port(number=p, protocol=Protocol.TCP) for p in port_numbers]
    scan_target = ScanTarget(host=target, ip=ip, ports=scan_ports)

    # Create config
    config = ScanConfig(
        target=scan_target,
        timeout_ms=timeout,
        max_concurrency=concurrency,
        detect_services=not no_service_detection,
        grab_banners=not no_banner_grab,
    )

    # Run scan
    console.print(
        f"\n[bold]Scanning[/] {len(port_numbers)} ports on {target} "
        f"(concurrency: {concurrency}, timeout: {timeout}ms)\n"
    )

    try:
        results = asyncio.run(_run_scan(config))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        sys.exit(130)

    # Filter results if not verbose
    if not verbose:
        results = [r for r in results if r.state == PortState.OPEN]

    if not results:
        console.print("[yellow]No open ports found.[/]")
        sys.exit(0)

    # Sort by port number
    results.sort(key=lambda r: r.port.number)

    # Format and display results
    formatter = get_formatter(output_format)
    formatted = formatter.format(results)

    if output_format == "table":
        table = create_results_table(results, ip)
        output_console.print()
        output_console.print(table)
        output_console.print()

        # Summary
        open_count = sum(1 for r in results if r.state == PortState.OPEN)
        console.print(
            f"[bold green]Scan complete:[/] {open_count} open port(s) "
            f"found out of {len(port_numbers)} scanned."
        )
    else:
        output_console.print(formatted)

    # Save to file if requested
    if output:
        output_path = Path(output)
        try:
            output_path.write_text(formatted, encoding="utf-8")
            console.print(f"[green]Results saved to:[/] {output_path}")
        except OSError as e:
            print_error(f"Could not write to file: {e}")
            sys.exit(1)


async def _run_scan(config: ScanConfig) -> list:
    """Run the async scan with progress tracking.

    Args:
        config: The scan configuration.

    Returns:
        List of ScanResult objects.
    """
    scanner = PortScanner(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=len(config.target.ports))

        def on_progress(port: Port) -> None:
            progress.advance(task)
            progress.update(task, description=f"[cyan]Scanning port {port.number}...")

        results = await scanner.scan_target(on_progress=on_progress)

    return results


if __name__ == "__main__":
    main()
