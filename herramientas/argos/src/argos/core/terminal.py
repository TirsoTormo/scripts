# pylint: disable=import-outside-toplevel, line-too-long
"""
ARGOS v1 — Terminal Output Module
==================================
Consolidated Rich-based terminal formatting for CLI output.
Corporate purple palette. No emojis. Pure text and ASCII.

This module merges the former ui/theme.py and ui/report.py into
a single file under core/ for a flat, maintainable structure.
"""

import time

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

from argos.core.models import DeviceModel

# ─────────────────────────────────────────────────────────────
# CORPORATE PALETTE — ELITE PURPLE
# ─────────────────────────────────────────────────────────────

# Purple / Magenta — Main color
ARGOS_PRIMARY = "magenta"
ARGOS_PRIMARY_BOLD = "bold magenta"
ARGOS_PRIMARY_DIM = "#8B008B"

# White / Gray — Descriptive text and data
ARGOS_WHITE = "bright_white"
ARGOS_DIM = "dim"
ARGOS_MUTED = "#888888"

# Green — Only for success states
ARGOS_SUCCESS = "green"
ARGOS_SUCCESS_BOLD = "bold green"

# Red — Critical errors and denial
ARGOS_ERROR = "#FF1744"
ARGOS_ERROR_BOLD = "bold red"

# Yellow — Warnings
ARGOS_WARN = "yellow"
ARGOS_WARN_BOLD = "bold yellow"


# ─────────────────────────────────────────────────────────────
# RICH THEME
# ─────────────────────────────────────────────────────────────

ARGOS_THEME = Theme(
    {
        "argos.title": ARGOS_PRIMARY_BOLD,
        "argos.subtitle": f"bold {ARGOS_WHITE}",
        "argos.label": ARGOS_PRIMARY,
        "argos.value": ARGOS_WHITE,
        "argos.success": ARGOS_SUCCESS_BOLD,
        "argos.warning": ARGOS_WARN_BOLD,
        "argos.error": ARGOS_ERROR_BOLD,
        "argos.dim": ARGOS_DIM,
        "argos.border": ARGOS_PRIMARY,
        "argos.header": f"bold {ARGOS_WHITE} on #2D002D",
    }
)


# ─────────────────────────────────────────────────────────────
# BANNER ASCII
# ─────────────────────────────────────────────────────────────

BANNER_ART = r"""[bold magenta]
   █████╗ ██████╗  ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗██╔════╝
  ███████║██████╔╝██║  ███╗██║   ██║███████╗
  ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
  ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
[/bold magenta]"""

BANNER_SUBTITLE = f"[{ARGOS_WHITE}]  Network Intelligence & Packet Factory[/{ARGOS_WHITE}]"
BANNER_VERSION = f"[{ARGOS_DIM}]  ARGOS v1.0 — CLI Network Tool (RFC 1918)[/{ARGOS_DIM}]"


# ─────────────────────────────────────────────────────────────
# FORMATTING HELPERS
# ─────────────────────────────────────────────────────────────


def format_latency(ms: float | None) -> str:
    """Formats latency with color according to value."""
    if ms is None:
        return f"[{ARGOS_MUTED}]N/A[/{ARGOS_MUTED}]"
    if ms < 5:
        return f"[{ARGOS_SUCCESS}]{ms:.1f} ms[/{ARGOS_SUCCESS}]"
    if ms < 50:
        return f"[{ARGOS_WARN}]{ms:.1f} ms[/{ARGOS_WARN}]"
    return f"[{ARGOS_ERROR}]{ms:.1f} ms[/{ARGOS_ERROR}]"


def format_port_status(status: str) -> str:
    """Port status with color. No emojis."""
    if status == "open":
        return f"[{ARGOS_SUCCESS_BOLD}]OPEN[/{ARGOS_SUCCESS_BOLD}]"
    if status == "closed":
        return f"[{ARGOS_ERROR_BOLD}]CLOSED[/{ARGOS_ERROR_BOLD}]"
    if status == "filtered":
        return f"[{ARGOS_WARN_BOLD}]FILTERED[/{ARGOS_WARN_BOLD}]"
    if "open|filtered" in status:
        return f"[{ARGOS_WARN}]OPEN|FILTERED[/{ARGOS_WARN}]"
    return f"[{ARGOS_MUTED}]{status.upper()}[/{ARGOS_MUTED}]"


def argos_log(console: Console, msg: str, level: str = "info"):
    """Visual logger. No emojis."""
    icons = {
        "info": "|",
        "success": "+",
        "warning": "!",
        "error": "X",
    }
    colors = {
        "info": ARGOS_PRIMARY,
        "success": ARGOS_SUCCESS,
        "warning": ARGOS_WARN,
        "error": ARGOS_ERROR,
    }
    color = colors.get(level, ARGOS_PRIMARY)
    icon = icons.get(level, "|")
    console.print(f"  [{color}]{icon}[/{color}] {msg}")


# ─────────────────────────────────────────────────────────────
# TABLES & PANELS — NETWORK REPORTS
# ─────────────────────────────────────────────────────────────


def display_animated_device_table(
    console: Console,
    devices: list[DeviceModel],
    scan_method: str = "",
    _local_ip: str = "",
):
    """Displays the device table with Matrix-style row animation."""
    title = f"DISCOVERED DEVICES ({len(devices)})"
    if scan_method:
        title += f"  ::  Method: {scan_method}"

    table = Table(
        title=title,
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Hostname", style=ARGOS_WHITE, width=28)
    table.add_column("Latency", width=12, justify="right")
    table.add_column("Vendor", style=ARGOS_MUTED, width=15)

    with Live(table, console=console, refresh_per_second=15, vertical_overflow="visible"):
        for i, device in enumerate(devices, 1):
            hostname = device.hostname
            if hostname == "Unknown" and device.ip.endswith(".1"):
                hostname = f"[{ARGOS_WARN}]>> Gateway (probable)[/{ARGOS_WARN}]"

            table.add_row(
                str(i),
                device.ip,
                device.mac,
                hostname,
                format_latency(device.latency_ms),
                device.vendor,
            )
            time.sleep(0.04)


def create_interface_table(interfaces: list[dict]) -> Table:
    """Network interfaces table."""
    table = Table(
        title="NETWORK INTERFACES",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("#", style=ARGOS_DIM, width=4, justify="center")
    table.add_column("Name", style=ARGOS_WHITE, width=30)
    table.add_column("Type", style=ARGOS_PRIMARY, width=14)
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("Mask", style=ARGOS_MUTED, width=16)
    table.add_column("MAC", style=ARGOS_WHITE, width=19)
    table.add_column("Status", width=10, justify="center")

    for i, iface in enumerate(interfaces, 1):
        status = (
            f"[{ARGOS_SUCCESS}]UP[/{ARGOS_SUCCESS}]"
            if iface["is_up"]
            else f"[{ARGOS_ERROR}]DOWN[/{ARGOS_ERROR}]"
        )
        table.add_row(
            str(i),
            iface["name"],
            iface["type"],
            iface["ip"],
            iface["mask"],
            iface["mac"],
            status,
        )

    return table


def create_speed_result_panel(result: dict) -> Panel:
    """Speed test results panel."""
    lines = []

    lines.append(
        f"  [{ARGOS_DIM}]Server:[/{ARGOS_DIM}]    [{ARGOS_WHITE}]"
        f"{result.get('server_ip', 'N/A')}:{result.get('port', 'N/A')}[/{ARGOS_WHITE}]"
    )
    lines.append(
        f"  [{ARGOS_DIM}]Duration:[/{ARGOS_DIM}]  [{ARGOS_WHITE}]"
        f"{result.get('duration_s', 0)} s[/{ARGOS_WHITE}]"
    )
    lines.append(
        f"  [{ARGOS_DIM}]Transferred:[/{ARGOS_DIM}] [{ARGOS_WHITE}]"
        f"{result.get('total_MB', 0)} MB[/{ARGOS_WHITE}]"
    )
    lines.append("")

    speed_mbps = result.get("client_speed_mbps", 0)
    speed_mbs = result.get("client_speed_mbs", 0)

    if speed_mbps >= 900:
        color = ARGOS_SUCCESS
        rating = "EXCELLENT (Gigabit)"
    elif speed_mbps >= 400:
        color = ARGOS_SUCCESS
        rating = "GOOD"
    elif speed_mbps >= 100:
        color = ARGOS_WARN
        rating = "ACCEPTABLE"
    elif speed_mbps >= 10:
        color = ARGOS_ERROR
        rating = "SLOW"
    else:
        color = ARGOS_ERROR
        rating = "VERY SLOW"

    lines.append(f"  [{color}]  >> Speed: {speed_mbps} Mbps  ({speed_mbs} MB/s)[/{color}]")
    lines.append(f"  [{color}]  >> Rating: {rating}[/{color}]")
    lines.append("")

    if "server_speed_mbps" in result:
        lines.append(
            f"  [{ARGOS_DIM}]Server measures:[/{ARGOS_DIM}]  [{ARGOS_WHITE}]"
            f"{result['server_speed_mbps']} Mbps ({result.get('server_speed_mbs', 0)} MB/s)"
            f"[/{ARGOS_WHITE}]"
        )

    bar_width = 40
    fill = min(int((speed_mbps / 1000) * bar_width), bar_width)
    progress_bar = (
        f"[{ARGOS_PRIMARY}]{'#' * fill}[/{ARGOS_PRIMARY}]"
        f"[{ARGOS_MUTED}]{'.' * (bar_width - fill)}[/{ARGOS_MUTED}]"
    )
    lines.append(f"\n  {progress_bar}  [{ARGOS_DIM}]{speed_mbps}/1000 Mbps[/{ARGOS_DIM}]")

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]SPEED TEST RESULTS[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEAD,
    )


def create_scan_summary(
    devices: list[DeviceModel], scan_method: str, duration: float, network_cidr: str
) -> Panel:
    """Scan summary panel."""
    total = len(devices)
    with_hostname = sum(1 for d in devices if d.hostname != "Unknown")

    latencies = [d.latency_ms for d in devices if d.latency_ms is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    lines = [
        f"  [{ARGOS_DIM}]Scanned Network:[/{ARGOS_DIM}]  "
        f"[{ARGOS_WHITE}]{network_cidr}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Method:[/{ARGOS_DIM}]         "
        f"[{ARGOS_WHITE}]{scan_method}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Time:[/{ARGOS_DIM}]           "
        f"[{ARGOS_WHITE}]{duration:.1f} s[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Devices:[/{ARGOS_DIM}]        [{ARGOS_SUCCESS}]{total}[/{ARGOS_SUCCESS}]",
        f"  [{ARGOS_DIM}]With hostname:[/{ARGOS_DIM}]   "
        f"[{ARGOS_WHITE}]{with_hostname}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Avg Latency:[/{ARGOS_DIM}]     "
        f"[{ARGOS_WHITE}]{avg_latency:.1f} ms[/{ARGOS_WHITE}]",
    ]

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]SCAN SUMMARY[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEAD,
    )


def create_port_table(results: list[dict]) -> Table:
    """Port scan results table."""
    table = Table(
        title="PORT SCAN RESULTS",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("Port", style=ARGOS_WHITE, width=8, justify="right")
    table.add_column("Service", style=ARGOS_PRIMARY, width=12)
    table.add_column("Status", width=18)
    table.add_column("Flags", style=ARGOS_MUTED, width=10)
    table.add_column("Banner / Info", style=ARGOS_WHITE, width=32)

    for r in results:
        table.add_row(
            str(r["port"]),
            r.get("service", ""),
            format_port_status(r["status"]),
            r.get("flags_received", "-"),
            r.get("banner", "")[:32],
        )

    return table


def create_traceroute_table(hops: list[dict]) -> Table:
    """Traceroute table."""
    table = Table(
        title="TRACEROUTE",
        title_style=ARGOS_PRIMARY_BOLD,
        border_style=ARGOS_PRIMARY,
        header_style=f"bold {ARGOS_WHITE} on #2D002D",
        show_lines=True,
        padding=(0, 1),
        box=box.SQUARE_DOUBLE_HEAD,
    )

    table.add_column("TTL", style=ARGOS_PRIMARY, width=5, justify="center")
    table.add_column("IP", style=ARGOS_WHITE, width=16)
    table.add_column("Latency", width=12, justify="right")
    table.add_column("Status", width=10)

    for hop in hops:
        lat = format_latency(hop.get("latency_ms"))
        status_str = (
            f"[{ARGOS_SUCCESS}]OK[/{ARGOS_SUCCESS}]"
            if hop.get("status") == "ok"
            else f"[{ARGOS_WARN}]TIMEOUT[/{ARGOS_WARN}]"
        )
        ip_str = hop["ip"] if hop["ip"] != "*" else f"[{ARGOS_MUTED}]*[/{ARGOS_MUTED}]"
        table.add_row(str(hop["ttl"]), ip_str, lat, status_str)

    return table


def create_ping_summary(stats: dict) -> Panel:
    """ICMP ping summary panel."""
    lines = [
        f"  [{ARGOS_DIM}]Target:[/{ARGOS_DIM}]      "
        f"[{ARGOS_WHITE}]{stats.get('dst', 'N/A')}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Sent:[/{ARGOS_DIM}]        "
        f"[{ARGOS_WHITE}]{stats.get('sent', 0)}[/{ARGOS_WHITE}]",
        f"  [{ARGOS_DIM}]Received:[/{ARGOS_DIM}]    "
        f"[{ARGOS_SUCCESS}]{stats.get('received', 0)}[/{ARGOS_SUCCESS}]",
        f"  [{ARGOS_DIM}]Lost:[/{ARGOS_DIM}]        "
        f"[{ARGOS_ERROR}]{stats.get('lost', 0)} ({stats.get('loss_pct', 0)}%)[/{ARGOS_ERROR}]",
        "",
    ]

    if stats.get("min_ms") is not None:
        lines.extend(
            [
                f"  [{ARGOS_DIM}]Minimum:[/{ARGOS_DIM}]       {format_latency(stats['min_ms'])}",
                f"  [{ARGOS_DIM}]Average:[/{ARGOS_DIM}]       {format_latency(stats['avg_ms'])}",
                f"  [{ARGOS_DIM}]Maximum:[/{ARGOS_DIM}]       {format_latency(stats['max_ms'])}",
            ]
        )

    return Panel(
        "\n".join(lines),
        title=f"[{ARGOS_PRIMARY_BOLD}]ICMP PING RESULTS[/{ARGOS_PRIMARY_BOLD}]",
        border_style=ARGOS_PRIMARY,
        padding=(1, 2),
        box=box.SQUARE_DOUBLE_HEAD,
    )
