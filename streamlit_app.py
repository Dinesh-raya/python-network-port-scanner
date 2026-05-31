"""Port Scanner Pro - Production-Grade Live Streamlit Demo.

Features:
    - TCP/UDP scanning with real-time progress
    - CIDR/subnet expansion (192.168.1.0/24)
    - Scan history with port-diff comparison
    - HTML report export with Plotly charts
    - External IP scanning (any resolvable host)
    - Dark/light theme toggle
    - Scan presets (Quick, Common, Web, Database, Custom)
    - JSON/CSV/HTML export

Deploy on Streamlit Cloud: https://share.streamlit.io
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

# Add src to path for imports
_SRC_DIR = Path(__file__).parent / "src"
if _SRC_DIR.is_dir():
    sys.path.insert(0, str(_SRC_DIR))
else:
    # Fallback: try current working directory
    _alt = Path.cwd() / "src"
    if _alt.is_dir():
        sys.path.insert(0, str(_alt))

try:
    import plotly.graph_objects as go
    from port_scanner.models import Port, PortState, Protocol, ScanConfig, ScanTarget
    from port_scanner.output import CSVFormatter, JSONFormatter
    from port_scanner.scanner import PortScanner
except ImportError as e:
    st.error(f"Import error: {e}")
    st.info("If deploying on Streamlit Cloud, ensure `requirements.txt` is in the repo root.")
    st.stop()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PORTS_WEB = 1000
MAX_HOSTS_CIDR = 256
SCAN_COOLDOWN_SEC = 3

PRESETS: dict[str, str] = {
    "Quick (Top 20)": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
    "Common (Top 100)": (
        "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,"
        "389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,"
        "1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2100,2103,2121,2199,"
        "2717,2869,2967,3000,3001,3128,3306,3389,3986,4000,4001,4899,5000,5001,5003,5009,5050,"
        "5051,5060,5101,5120,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7000,7070,7100,"
        "7443,7938,8000,8008,8009,8080,8081,8443,8888,9090,9100,9999,10000,27017"
    ),
    "Web Ports": "80,443,8080,8443,3000,5000,8000,8888,9090",
    "Database Ports": "1433,1521,3306,5432,6379,27017,9042,5984",
    "Mail Ports": "25,110,143,465,587,993,995",
    "Remote Access": "22,23,3389,5900,5901,5985,5986",
    "Custom": "",
}

# ---------------------------------------------------------------------------
# Theme helpers
# ---------------------------------------------------------------------------

THEME_DARK = {
    "bg": "#0e1117",
    "secondary": "#1a1f2e",
    "text": "#e0e0e0",
    "primary": "#00ff88",
    "chart_colors": {"open": "#00ff88", "closed": "#ff4444", "filtered": "#ffaa00"},
}

THEME_LIGHT = {
    "bg": "#ffffff",
    "secondary": "#f0f2f6",
    "text": "#1a1a1a",
    "primary": "#00875a",
    "chart_colors": {"open": "#00875a", "closed": "#d32f2f", "filtered": "#f57c00"},
}


def _get_theme() -> dict:
    """Return current theme dict based on session state."""
    if st.session_state.get("dark_mode", True):
        return THEME_DARK
    return THEME_LIGHT


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------


def _is_safe_target(host: str) -> bool:
    """Validate target is resolvable. Any resolvable host is allowed —
    user is responsible for authorization."""
    host = host.strip().lower()
    if not host:
        return False

    # CIDR notation — validate the network part
    if "/" in host:
        try:
            network = ipaddress.ip_network(host, strict=False)
            return network.num_addresses > 0
        except ValueError:
            return False

    # Direct IP (v4 or v6)
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Hostname resolution
    try:
        ip = socket.gethostbyname(host)
        return bool(ip)
    except socket.gaierror:
        return False


def _check_cooldown() -> bool:
    """Return True if cooldown has passed."""
    if "last_scan_time" not in st.session_state:
        return True
    elapsed = time.time() - st.session_state.last_scan_time
    return elapsed >= SCAN_COOLDOWN_SEC


# ---------------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------------


def _expand_targets(target_str: str) -> list[str]:
    """Expand target string to list of hosts.

    Supports:
        - Single host: "example.com"
        - CIDR: "192.168.1.0/24"
        - Comma-separated: "host1,host2,192.168.1.0/24"
    """
    targets: list[str] = []
    for part in target_str.split(","):
        part = part.strip()
        if not part:
            continue

        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                if network.num_addresses > MAX_HOSTS_CIDR:
                    # Too many hosts — take first MAX_HOSTS_CIDR
                    for i, host in enumerate(network.hosts()):
                        if i >= MAX_HOSTS_CIDR:
                            break
                        targets.append(str(host))
                else:
                    targets.extend(str(h) for h in network.hosts())
            except ValueError:
                # Not valid CIDR — treat as hostname
                targets.append(part)
        else:
            targets.append(part)

    return targets


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------


def _build_ports(port_spec: str, preset: str, protocol: Protocol) -> list[Port]:
    """Build port list from preset or custom spec with given protocol."""
    if preset != "Custom" and PRESETS.get(preset):
        port_spec = PRESETS[preset]

    if not port_spec or not port_spec.strip():
        return []

    ports: list[Port] = []
    seen: set[int] = set()

    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            for p in range(start, min(end + 1, 65536)):
                if p not in seen:
                    seen.add(p)
                    ports.append(Port(number=p, protocol=protocol))
        else:
            p = int(part)
            if p not in seen:
                seen.add(p)
                ports.append(Port(number=p, protocol=protocol))

    return ports[:MAX_PORTS_WEB]


async def _run_scan(
    target: str,
    ports: list[Port],
    timeout_ms: int,
    concurrency: int,
    detect_services: bool,
    grab_banners: bool,
    progress_bar: Any,
) -> tuple[list, str, str]:
    """Execute scan. Returns (results, host, ip)."""
    host, ip = await _validate_and_resolve(target)

    async def on_progress(done: int, tot: int) -> None:
        pct = done / tot if tot > 0 else 0
        try:
            progress_bar.progress(pct, text=f"Scanning {host}... {done}/{tot} ports")
        except Exception:
            pass

    scan_target = ScanTarget(host=host, ip=ip, ports=tuple(ports))
    config = ScanConfig(
        target=scan_target,
        timeout_ms=timeout_ms,
        max_concurrency=concurrency,
        detect_services=detect_services,
        grab_banners=grab_banners,
    )
    scanner = PortScanner(config, progress_callback=on_progress)
    results = await scanner.scan()

    return results, host, ip


async def _validate_and_resolve(target: str) -> tuple[str, str]:
    """Validate target and resolve IP."""
    from port_scanner.utils import validate_target

    return await validate_target(target)


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------


def _add_to_history(
    host: str,
    ip: str,
    results: list,
    scan_time: float,
    params: dict,
) -> None:
    """Add scan result to session history."""
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []

    open_ports = [r.port.number for r in results if r.state == PortState.OPEN]
    st.session_state.scan_history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "ip": ip,
        "total_ports": len(results),
        "open_count": len(open_ports),
        "closed_count": sum(1 for r in results if r.state == PortState.CLOSED),
        "filtered_count": sum(1 for r in results if r.state == PortState.FILTERED),
        "open_ports": open_ports,
        "scan_time": scan_time,
        "params": params,
    })


def _render_history() -> None:
    """Render scan history panel."""
    history = st.session_state.get("scan_history", [])
    if not history:
        st.info("No scans yet. Run a scan to see history here.")
        return

    st.markdown(f"### Scan History ({len(history)} scans)")

    for i, entry in enumerate(reversed(history)):
        idx = len(history) - 1 - i
        ts = entry["timestamp"][:19].replace("T", " ")
        with st.expander(
            f"#{idx + 1} — `{entry['host']}` ({entry['ip']}) — "
            f"{entry['open_count']} open — {ts} UTC"
        ):
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Open", entry["open_count"])
            col2.metric("Closed", entry["closed_count"])
            col3.metric("Filtered", entry["filtered_count"])
            col4.metric("Time", f"{entry['scan_time']:.1f}s")

            if entry["open_ports"]:
                st.markdown(f"**Open ports:** {', '.join(str(p) for p in entry['open_ports'])}")

    # Comparison mode
    if len(history) >= 2:
        st.markdown("### Compare Scans")
        col1, col2 = st.columns(2)
        with col1:
            idx_a = st.selectbox(
                "Scan A",
                options=list(range(len(history))),
                format_func=lambda i: f"#{i + 1} — {history[i]['host']}",
                index=len(history) - 2,
            )
        with col2:
            idx_b = st.selectbox(
                "Scan B",
                options=list(range(len(history))),
                format_func=lambda i: f"#{i + 1} — {history[i]['host']}",
                index=len(history) - 1,
            )

        if st.button("Compare"):
            a = history[idx_a]
            b = history[idx_b]
            set_a = set(a["open_ports"])
            set_b = set(b["open_ports"])

            new_ports = sorted(set_b - set_a)
            closed_ports = sorted(set_a - set_b)
            common_ports = sorted(set_a & set_b)

            col1, col2, col3 = st.columns(3)
            col1.metric("New Open", len(new_ports))
            col2.metric("Now Closed", len(closed_ports))
            col3.metric("Still Open", len(common_ports))

            if new_ports:
                st.success(f"**New open ports:** {', '.join(str(p) for p in new_ports)}")
            if closed_ports:
                st.error(f"**Now closed:** {', '.join(str(p) for p in closed_ports)}")
            if common_ports:
                st.info(f"**Still open:** {', '.join(str(p) for p in common_ports)}")


# ---------------------------------------------------------------------------
# HTML report with Plotly
# ---------------------------------------------------------------------------


def _generate_html_report(
    results: list,
    host: str,
    ip: str,
    scan_time: float,
    params: dict,
) -> str:
    """Generate styled HTML report with Plotly charts."""
    open_ports = [r for r in results if r.state == PortState.OPEN]
    closed_ports = [r for r in results if r.state == PortState.CLOSED]
    filtered_ports = [r for r in results if r.state == PortState.FILTERED]

    # Pie chart — port states
    fig_pie = go.Figure(
        data=[
            go.Pie(
                labels=["Open", "Closed", "Filtered"],
                values=[len(open_ports), len(closed_ports), len(filtered_ports)],
                marker={"colors": ["#00ff88", "#ff4444", "#ffaa00"]},
                hole=0.4,
            )
        ]
    )
    fig_pie.update_layout(
        title="Port States Distribution",
        template="plotly_dark",
        height=350,
        margin=dict(t=50, b=30, l=30, r=30),
    )

    # Bar chart — response times for open ports
    if open_ports:
        fig_bar = go.Figure(
            data=[
                go.Bar(
                    x=[f"{r.port.number}/{r.port.protocol.value}" for r in open_ports],
                    y=[r.response_time_ms for r in open_ports],
                    marker_color="#00ff88",
                    text=[f"{r.response_time_ms:.1f}ms" for r in open_ports],
                    textposition="auto",
                )
            ]
        )
        fig_bar.update_layout(
            title="Response Times — Open Ports",
            xaxis_title="Port",
            yaxis_title="Response Time (ms)",
            template="plotly_dark",
            height=350,
            margin=dict(t=50, b=50, l=50, r=30),
        )
        bar_html = fig_bar.to_html(full_html=False, include_plotlyjs=False)
    else:
        bar_html = "<p>No open ports to chart.</p>"

    pie_html = fig_pie.to_html(full_html=False, include_plotlyjs=False)

    # Open ports table rows
    open_rows = ""
    for r in open_ports:
        banner = (r.banner[:80] + "...") if r.banner and len(r.banner) > 80 else (r.banner or "-")
        open_rows += f"""
        <tr>
            <td>{r.port.number}</td>
            <td>{r.port.protocol.value}</td>
            <td>{r.service or '-'}</td>
            <td>{banner}</td>
            <td>{r.response_time_ms:.1f}</td>
        </tr>"""

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Port Scan Report — {host}</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0e1117; color: #e0e0e0; padding: 2rem; }}
        .header {{ text-align: center; margin-bottom: 2rem; }}
        .header h1 {{ font-size: 1.8rem; color: #00ff88; }}
        .header p {{ color: #888; margin-top: 0.5rem; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .metric {{ background: #1a1f2e; border-radius: 8px; padding: 1.2rem; text-align: center; }}
        .metric .value {{ font-size: 2rem; font-weight: bold; }}
        .metric .label {{ color: #888; font-size: 0.85rem; text-transform: uppercase; }}
        .metric.open .value {{ color: #00ff88; }}
        .metric.closed .value {{ color: #ff4444; }}
        .metric.filtered .value {{ color: #ffaa00; }}
        .metric.time .value {{ color: #4488ff; }}
        .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem; }}
        .chart {{ background: #1a1f2e; border-radius: 8px; padding: 1rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a1f2e; border-radius: 8px; overflow: hidden; }}
        th {{ background: #252b3b; padding: 0.8rem; text-align: left; font-size: 0.85rem; text-transform: uppercase; color: #888; }}
        td {{ padding: 0.7rem 0.8rem; border-bottom: 1px solid #252b3b; }}
        tr:hover td {{ background: #1f2535; }}
        .footer {{ text-align: center; margin-top: 2rem; color: #555; font-size: 0.8rem; }}
        @media (max-width: 768px) {{
            .metrics {{ grid-template-columns: repeat(2, 1fr); }}
            .charts {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Port Scan Report</h1>
        <p><strong>{host}</strong> ({ip}) — Scanned {timestamp}</p>
        <p>Ports scanned: {len(results)} | Protocol: {params.get('protocol', 'tcp')} | Timeout: {params.get('timeout_ms', 1000)}ms</p>
    </div>

    <div class="metrics">
        <div class="metric open"><div class="value">{len(open_ports)}</div><div class="label">Open</div></div>
        <div class="metric closed"><div class="value">{len(closed_ports)}</div><div class="label">Closed</div></div>
        <div class="metric filtered"><div class="value">{len(filtered_ports)}</div><div class="label">Filtered</div></div>
        <div class="metric time"><div class="value">{scan_time:.1f}s</div><div class="label">Scan Time</div></div>
    </div>

    <div class="charts">
        <div class="chart">{pie_html}</div>
        <div class="chart">{bar_html}</div>
    </div>

    <h2 style="margin-bottom: 1rem; color: #00ff88;">Open Ports</h2>
    {"<p style='color: #888;'>No open ports found.</p>" if not open_ports else f'''
    <table>
        <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Banner</th><th>Response</th></tr></thead>
        <tbody>{open_rows}</tbody>
    </table>'''}

    <div class="footer">
        <p>Generated by Port Scanner Pro — {timestamp}</p>
    </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# UI rendering
# ---------------------------------------------------------------------------


def _render_sidebar() -> dict:
    """Render sidebar config. Return scan params dict."""
    with st.sidebar:
        st.markdown("## Scan Configuration")

        # Theme toggle
        st.toggle("Dark Mode", value=True, key="dark_mode")

        st.markdown("---")

        target = st.text_input(
            "Target Host",
            value="scanme.nmap.org",
            help="Hostname, IP, or CIDR (e.g. 192.168.1.0/24). Comma-separated for multiple.",
        )

        # Protocol selector
        protocol_str = st.radio(
            "Protocol",
            options=["TCP", "UDP"],
            horizontal=True,
            help="TCP connect scan or UDP probe",
        )
        protocol = Protocol.TCP if protocol_str == "TCP" else Protocol.UDP

        st.markdown("### Scan Profile")
        preset = st.selectbox(
            "Preset",
            options=list(PRESETS.keys()),
            index=1,  # Default to Common (Top 100)
            help="Predefined port sets for common scan types",
        )

        if preset == "Custom":
            port_spec = st.text_input(
                "Port Range",
                value="80,443,8080",
                help="e.g. 80,443,8000-8100",
            )
        else:
            port_spec = PRESETS[preset]
            st.caption(f"Ports: {port_spec[:80]}{'...' if len(port_spec) > 80 else ''}")

        st.markdown("### Options")
        col1, col2 = st.columns(2)
        with col1:
            detect_services = st.checkbox("Service Detection", value=True)
        with col2:
            grab_banners = st.checkbox("Banner Grabbing", value=False)

        timeout_ms = st.slider(
            "Timeout (ms)",
            min_value=100,
            max_value=10000,
            value=1000,
            step=100,
        )

        concurrency = st.slider(
            "Concurrency",
            min_value=10,
            max_value=500,
            value=100,
            step=10,
        )

        st.markdown("---")
        st.warning(
            "Only scan targets you have **authorization** to test. "
            "Unauthorized port scanning is illegal in most jurisdictions."
        )

    return {
        "target": target,
        "preset": preset,
        "port_spec": port_spec,
        "protocol": protocol,
        "detect_services": detect_services,
        "grab_banners": grab_banners,
        "timeout_ms": timeout_ms,
        "concurrency": concurrency,
    }


def _render_results(results: list, host: str, ip: str, scan_time: float) -> None:
    """Render scan results with charts."""
    theme = _get_theme()
    open_ports = [r for r in results if r.state == PortState.OPEN]
    closed_ports = [r for r in results if r.state == PortState.CLOSED]
    filtered_ports = [r for r in results if r.state == PortState.FILTERED]

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Open", len(open_ports))
    col2.metric("Closed", len(closed_ports))
    col3.metric("Filtered", len(filtered_ports))
    col4.metric("Scan Time", f"{scan_time:.1f}s")

    if not results:
        st.warning("No results returned.")
        return

    # Plotly charts
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        fig_pie = go.Figure(
            data=[
                go.Pie(
                    labels=["Open", "Closed", "Filtered"],
                    values=[len(open_ports), len(closed_ports), len(filtered_ports)],
                    marker={"colors": [
                        theme["chart_colors"]["open"],
                        theme["chart_colors"]["closed"],
                        theme["chart_colors"]["filtered"],
                    ]},
                    hole=0.4,
                )
            ]
        )
        fig_pie.update_layout(
            title="Port States",
            template="plotly_dark" if st.session_state.get("dark_mode", True) else "plotly",
            height=300,
            margin=dict(t=50, b=30, l=30, r=30),
            showlegend=True,
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with chart_col2:
        if open_ports:
            fig_bar = go.Figure(
                data=[
                    go.Bar(
                        x=[f"{r.port.number}" for r in open_ports],
                        y=[r.response_time_ms for r in open_ports],
                        marker_color=theme["chart_colors"]["open"],
                        text=[f"{r.response_time_ms:.0f}ms" for r in open_ports],
                        textposition="auto",
                    )
                ]
            )
            fig_bar.update_layout(
                title="Response Times — Open Ports",
                xaxis_title="Port",
                yaxis_title="ms",
                template="plotly_dark" if st.session_state.get("dark_mode", True) else "plotly",
                height=300,
                margin=dict(t=50, b=50, l=50, r=30),
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No open ports to chart.")

    # Results table
    st.markdown(f"### Results for `{host}` ({ip})")

    if open_ports:
        rows = []
        for r in open_ports:
            banner = (r.banner[:60] + "...") if r.banner and len(r.banner) > 60 else (r.banner or "-")
            rows.append({
                "Port": r.port.number,
                "Protocol": r.port.protocol.value,
                "Service": r.service or "-",
                "Banner": banner,
                "Response (ms)": f"{r.response_time_ms:.1f}",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No open ports found.")

    # Collapsible closed/filtered
    if closed_ports or filtered_ports:
        with st.expander(f"Closed/Filtered Ports ({len(closed_ports) + len(filtered_ports)})"):
            rows = []
            for r in closed_ports + filtered_ports:
                rows.append({
                    "Port": r.port.number,
                    "Protocol": r.port.protocol.value,
                    "State": r.state.value,
                    "Service": r.service or "-",
                    "Response (ms)": f"{r.response_time_ms:.1f}",
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)


def _render_export(results: list, host: str, ip: str, scan_time: float, params: dict) -> None:
    """Render export buttons (JSON, CSV, HTML)."""
    st.markdown("### Export Results")

    ports_tuple = tuple(r.port for r in results)
    scan_target = ScanTarget(host=host, ip=ip, ports=ports_tuple)

    json_str = JSONFormatter().format(results, scan_target)
    csv_str = CSVFormatter().format(results, scan_target)
    html_str = _generate_html_report(results, host, ip, scan_time, params)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.download_button(
            "Download JSON",
            data=json_str,
            file_name=f"scan_{host}_{ts}.json",
            mime="application/json",
            use_container_width=True,
        )
    with col2:
        st.download_button(
            "Download CSV",
            data=csv_str,
            file_name=f"scan_{host}_{ts}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with col3:
        st.download_button(
            "Download HTML Report",
            data=html_str,
            file_name=f"scan_{host}_{ts}.html",
            mime="text/html",
            use_container_width=True,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Streamlit app entry point."""
    st.set_page_config(
        page_title="Port Scanner Pro",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        """
        # 🔍 Port Scanner Pro
        **Async network port scanner** — TCP/UDP, CIDR support, real-time progress, export to JSON/CSV/HTML.
        """,
        unsafe_allow_html=True,
    )

    params = _render_sidebar()

    # Tabs: Scanner | History
    tab_scan, tab_history = st.tabs(["Scanner", "History"])

    with tab_scan:
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            # Validation
            if not params["target"].strip():
                st.error("Target cannot be empty.")
                return

            if not _is_safe_target(params["target"]):
                st.error(f"Cannot resolve target: {params['target']}")
                return

            if not _check_cooldown():
                st.warning(f"Cooldown active. Wait {SCAN_COOLDOWN_SEC}s between scans.")
                return

            # Expand targets (CIDR support)
            targets = _expand_targets(params["target"])
            if not targets:
                st.error("No valid targets.")
                return

            if len(targets) > MAX_HOSTS_CIDR:
                st.warning(f"Host count capped at {MAX_HOSTS_CIDR}. Scanning first {MAX_HOSTS_CIDR} hosts.")
                targets = targets[:MAX_HOSTS_CIDR]

            ports = _build_ports(params["port_spec"], params["preset"], params["protocol"])
            if not ports:
                st.error("No valid ports to scan.")
                return

            if len(ports) > MAX_PORTS_WEB:
                st.warning(f"Port count capped at {MAX_PORTS_WEB}.")
                ports = ports[:MAX_PORTS_WEB]

            # Scan all targets
            all_results = []
            total_hosts = len(targets)
            overall_progress = st.progress(0, text="Starting scan...")
            start_time = time.time()

            with st.status(f"Scanning {total_hosts} target(s)...", expanded=True) as status:
                for host_idx, target in enumerate(targets):
                    st.markdown(f"**Scanning `{target}` ({host_idx + 1}/{total_hosts})**")
                    progress_bar = st.progress(0, text=f"Initializing {target}...")

                    try:
                        results, host, ip = asyncio.run(
                            _run_scan(
                                target=target,
                                ports=ports,
                                timeout_ms=params["timeout_ms"],
                                concurrency=params["concurrency"],
                                detect_services=params["detect_services"],
                                grab_banners=params["grab_banners"],
                                progress_bar=progress_bar,
                            )
                        )

                        open_count = sum(1 for r in results if r.state == PortState.OPEN)
                        st.markdown(f"→ `{host}` ({ip}): **{open_count}** open ports")

                        scan_time_single = time.time() - start_time
                        all_results.append({
                            "host": host,
                            "ip": ip,
                            "results": results,
                        })

                        # Add to history
                        _add_to_history(host, ip, results, scan_time_single, params)

                    except Exception as e:
                        st.error(f"Failed to scan `{target}`: {e}")
                        continue

                    overall_progress.progress(
                        (host_idx + 1) / total_hosts,
                        text=f"Completed {host_idx + 1}/{total_hosts} targets",
                    )

                total_time = time.time() - start_time
                status.update(
                    label=f"Scan complete — {total_time:.1f}s — {len(all_results)} target(s)",
                    state="complete",
                )

            # Display results for each target
            for entry in all_results:
                st.markdown("---")
                _render_results(
                    entry["results"],
                    entry["host"],
                    entry["ip"],
                    total_time,
                )

            # Export (use last target for single-target export, or combine for multi)
            if all_results:
                if len(all_results) == 1:
                    _render_export(
                        all_results[0]["results"],
                        all_results[0]["host"],
                        all_results[0]["ip"],
                        total_time,
                        params,
                    )
                else:
                    # Multi-target: combine all results for export
                    combined = []
                    for entry in all_results:
                        combined.extend(entry["results"])
                    combined_host = f"{len(all_results)} targets"
                    combined_ip = ", ".join(e["ip"] for e in all_results[:5])
                    _render_export(combined, combined_host, combined_ip, total_time, params)

            st.session_state.last_scan_time = time.time()

        # Show last results if available
        elif "scan_history" in st.session_state and st.session_state.scan_history:
            last = st.session_state.scan_history[-1]
            st.info(f"Showing results from last scan: `{last['host']}` ({last['ip']})")
            # Re-render not possible without full results — show summary only
            st.markdown(f"**{last['open_count']}** open ports out of **{last['total_ports']}** scanned")
            if last["open_ports"]:
                st.markdown(f"Open: {', '.join(str(p) for p in last['open_ports'])}")

    with tab_history:
        _render_history()


if __name__ == "__main__":
    main()
