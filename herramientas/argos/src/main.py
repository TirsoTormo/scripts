#!/usr/bin/env python3
# pylint: disable=import-outside-toplevel, broad-exception-caught, no-member, too-many-branches, wrong-import-position
"""
ARGOS v1 — Network Intelligence & Packet Factory
==================================================
CLI-only tool for network engineering:
- Local network device discovery (ARP / ICMP)
- LAN speed test between devices (TCP throughput)
- Custom packet factory (Layers 2/3/4 of the OSI model)

Usage:
    argos --scan                         Quick network scan
    argos --interfaces                   Show interfaces
    argos --server                       Speed test server
    argos --client <IP>                  Speed test client
    argos --dst <IP> --flags S --port 443   Send custom TCP
    argos --probe <IP> --ports web       TCP port probe
    argos --traceroute <IP>              Manual traceroute
    argos --ping <IP>                    ICMP ping

ARGOS v1 — Network Intelligence Tool
Requires administrator privileges for Layer 2 operations and raw sockets.
"""

import argparse
import ctypes
import os
import platform
import subprocess
import sys
import time


def auto_installer():
    """Checks dependencies and installs them if missing before loading anything."""
    required = ["rich", "psutil", "scapy", "requests"]
    missing = []

    for req in required:
        try:
            __import__(req)
        except ImportError:
            missing.append(req)

    if missing:
        print("\033[35m")
        print("  ========================================")
        print("  :: ARGOS AUTO-INSTALLER ::")
        print(f"  Missing dependencies: {', '.join(missing)}")
        print("  Installing automatically via pip...")
        print("  ========================================\033[0m\n")

        try:
            subprocess.run([sys.executable, "-m", "pip", "install"] + missing, check=True)
            print("\033[32m  + Installation successful. Loading ARGOS...\033[0m\n")
        except subprocess.CalledProcessError:
            print("\033[31m  X Error: Could not install dependencies automatically.\033[0m")
            print("\033[31m  Please run: pip install rich psutil scapy requests pydantic\033[0m")
            sys.exit(1)
        except Exception as e:
            print(f"\033[31m  X Unexpected error installing dependencies: {e}\033[0m")
            sys.exit(1)

    # Check Npcap on Windows
    if platform.system().lower() == "windows":
        try:
            from argos.core.packet_factory import _install_npcap

            _install_npcap(log_callback=print)
        except (ImportError, Exception):
            pass


# Run installer before heavy imports
auto_installer()

from rich import box  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402

console = Console()


def enforce_admin():
    """
    Verifies that ARGOS is running with administrator or root privileges.
    If not, displays a panel warning and exits gracefully.
    """
    system = platform.system().lower()
    is_admin = False

    if system == "windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
    else:
        try:
            is_admin = os.geteuid() == 0
        except Exception:
            is_admin = False

    if not is_admin:
        if system == "windows":
            # Auto-elevate using UAC prompt
            try:
                console.print("[yellow]Requesting Administrator privileges via UAC...[/yellow]")
                args_list = ["-m", "argos"] + sys.argv[1:]
                py_args = " ".join([f'"{arg}"' if " " in arg else arg for arg in args_list])
                params = f'/c "{sys.executable}" {py_args}'
                ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", params, None, 1)
                sys.exit(0)
            except Exception:
                pass  # Fall through if user denies UAC

        console.print()
        console.print(
            Panel(
                "[bright_white]ARGOS requires full access to network interfaces "
                "and raw sockets.[/bright_white]\n\n"
                "  [dim]On Windows:[/dim]  [magenta]Run your terminal "
                "as Administrator.[/magenta]\n"
                "  [dim]On Linux:[/dim]    [magenta]sudo argos <command>[/magenta]",
                title="[bold magenta]:: REQUIRED PRIVILEGES ::[/bold magenta]",
                border_style="magenta",
                box=box.DOUBLE,
                padding=(1, 2),
            )
        )
        console.print(
            "  [yellow]WARNING: Starting without administrator privileges. "
            "Some features will be limited (e.g., ARP Scan capped to Ping).[/yellow]"
        )
        console.print()
        sys.exit(0)


def parse_args():
    """Parses ARGOS command line arguments."""
    parser = argparse.ArgumentParser(
        prog="argos",
        description="ARGOS v1 — Network Intelligence & Packet Factory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  argos --scan                            Quick network scan
  argos --scan --export-json report.json  Scan and export to JSON
  argos --interfaces                      Show network interfaces
  argos --server                          Speed test server
  argos --client 192.168.1.10             Speed test client

  Packet Factory (requires admin + Scapy):
  argos --dst 192.168.1.1 --flags S --port 443
  argos --probe 192.168.1.1 --ports 80,443,22
  argos --probe 192.168.1.1 --ports web
  argos --traceroute 8.8.8.8
  argos --ping 192.168.1.1 --count 10 --ttl 128
        """,
    )

    # General options
    general = parser.add_argument_group("General")
    general.add_argument("--scan", action="store_true", help="Quick network scan")
    general.add_argument("--interfaces", action="store_true", help="Show network interfaces")
    general.add_argument("--export-json", type=str, metavar="FILE", help="Export results to JSON")
    general.add_argument("--export-md", type=str, metavar="FILE", help="Export results to Markdown")
    general.add_argument("--export-csv", type=str, metavar="FILE", help="Export results to CSV")

    # Speed test
    speed = parser.add_argument_group("LAN Speed Test")
    speed.add_argument("--server", action="store_true", help="Start speed test server")
    speed.add_argument("--client", type=str, metavar="IP", help="Connect as client to server")
    speed.add_argument(
        "--duration", type=int, default=10, help="Speed test duration (default: 10s)"
    )

    # Packet Factory
    pf = parser.add_argument_group("Packet Factory (Layers 2/3/4)")
    pf.add_argument(
        "--dst", type=str, metavar="IP", help="Destination IP for custom TCP/UDP packet"
    )
    pf.add_argument(
        "--flags",
        type=str,
        default="S",
        help="TCP Flags: S(YN) A(CK) F(IN) R(ST) P(SH) (default: S)",
    )
    pf.add_argument(
        "--port", type=int, default=80, help="Destination port for custom packet (default: 80)"
    )
    pf.add_argument("--probe", type=str, metavar="IP", help="TCP SYN probe to IP ports")
    pf.add_argument(
        "--ports",
        type=str,
        default="top20",
        help="Ports for --probe (e.g: 80,443 or group: web,top20,mikrotik)",
    )
    pf.add_argument(
        "--traceroute",
        type=str,
        metavar="IP",
        help="Manual ICMP traceroute with incremental TTL",
    )
    pf.add_argument(
        "--max-hops", type=int, default=30, help="Max hops for traceroute (default: 30)"
    )
    pf.add_argument("--ping", type=str, metavar="IP", help="Custom ICMP ping")
    pf.add_argument("--count", type=int, default=4, help="Number of pings (default: 4)")
    pf.add_argument("--ttl", type=int, default=64, help="TTL for IP packets (default: 64)")
    pf.add_argument("--size", type=int, default=56, help="ICMP payload size in bytes (default: 56)")

    # Shared
    parser.add_argument(
        "--sport", type=int, default=None, help="Source port TCP/UDP (default: random)"
    )

    return parser.parse_args(), parser


# ─────────────────────────────────────────────────────────────
# CLI Commands
# ─────────────────────────────────────────────────────────────


def cmd_show_interfaces():
    """Shows network interfaces."""
    from argos.core.net_utils import get_active_interfaces
    from argos.core.terminal import create_interface_table
    interfaces = get_active_interfaces()
    if interfaces:
        console.print(create_interface_table(interfaces))
    else:
        console.print("[yellow]No interfaces found.[/yellow]")


def cmd_server(port: int = 45678):
    """Starts speed test server."""
    from argos.core.net_utils import get_active_interfaces
    from argos.core.speed_test import SpeedTestServer
    from argos.core.terminal import create_speed_result_panel

    active = get_active_interfaces()
    if active:
        console.print("\n[bright_green]ARGOS Speed Server — IPs:[/bright_green]")
        for iface in active:
            console.print(f"  > {iface['ip']}  ({iface['name']})")

    def log(msg):
        console.print(f"  [bright_white]|[/bright_white] {msg}")

    server = SpeedTestServer(port=port, status_callback=log)
    server.start()

    console.print(f"\n[bright_green]Server active on port {port}[/bright_green]")
    console.print("[dim]Press Ctrl+C to stop...[/dim]\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    server.stop()

    if server.last_result:
        result = server.last_result
        result["server_ip"] = "localhost"
        result["port"] = port
        result["total_MB"] = round(result.get("total_bytes", 0) / (1024 * 1024), 2)
        result["client_speed_mbps"] = result.get("speed_mbps", 0)
        result["client_speed_MBs"] = result.get("speed_MBs", 0)
        console.print(create_speed_result_panel(result))

    console.print("\n[dim]Server stopped.[/dim]")


def cmd_client(server_ip: str, port: int, duration: int):
    """Runs speed test client."""
    from argos.core.net_utils import is_private_ip
    from argos.core.speed_test import SpeedTestClient
    from argos.core.terminal import create_speed_result_panel

    if not is_private_ip(server_ip):
        console.print(f"[bold red]X {server_ip} is not a private IP. Aborted.[/bold red]")
        return

    def log(msg):
        console.print(f"  [bright_white]|[/bright_white] {msg}")

    client = SpeedTestClient(status_callback=log)
    console.print(f"\n[bright_yellow]ARGOS connecting to {server_ip}:{port}...[/bright_yellow]\n")

    result = client.run_test(server_ip, port, duration)

    if result:
        console.print()
        console.print(create_speed_result_panel(result))
    else:
        console.print("[bold red]X Could not complete the test.[/bold red]")


def cmd_tcp_custom(dst_ip: str, port: int, flags: str, src_port=None):
    """Sends a custom TCP segment."""
    from argos.core.packet_factory import describe_flags, send_tcp_custom

    def log(msg):
        console.print(f"  [bright_white]|[/bright_white] {msg}")

    console.print(
        f"\n[bright_cyan]ARGOS Packet Factory — TCP {describe_flags(flags)} "
        f"-> {dst_ip}:{port}[/bright_cyan]\n"
    )

    result = send_tcp_custom(dst_ip, port, flags=flags, src_port=src_port, log_callback=log)

    if result:
        console.print(f"\n  [bold]Status: {result.get('status', 'N/A')}[/bold]")
        if result.get("flags_received"):
            console.print(f"  Response Flags: {result['flags_received']}")
        if result.get("latency_ms"):
            console.print(f"  Latency: {result['latency_ms']} ms")


def cmd_tcp_probe(dst_ip: str, ports_input: str):
    """TCP SYN probe to specific ports."""
    from argos.core.packet_factory import get_common_port_groups, tcp_port_probe

    def log(msg):
        console.print(f"  [bright_white]|[/bright_white] {msg}")

    groups = get_common_port_groups()
    if ports_input in groups:
        ports = groups[ports_input]
    else:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            console.print("[red]Invalid port format[/red]")
            return

    console.print(
        f"\n[bright_cyan]ARGOS TCP SYN Probe -> {dst_ip} ({len(ports)} ports)[/bright_cyan]\n"
    )

    results = tcp_port_probe(dst_ip, ports, log_callback=log)
    open_ports = [r for r in results if r["status"] == "open"]
    console.print(
        f"\n  [bold bright_green]Open ports: {len(open_ports)}/{len(results)}[/bold bright_green]"
    )


def cmd_traceroute(dst_ip: str, max_hops: int):
    """Manual traceroute."""
    from argos.core.packet_factory import manual_traceroute

    def log(msg):
        console.print(f"  [bright_white]|[/bright_white] {msg}")

    console.print(
        f"\n[bright_cyan]ARGOS Traceroute -> {dst_ip} (max {max_hops} hops)[/bright_cyan]\n"
    )
    hops = manual_traceroute(dst_ip, max_hops=max_hops, log_callback=log)
    console.print(f"\n  [bold bright_green]Completed: {len(hops)} hops[/bold bright_green]")


def cmd_icmp_ping(dst_ip: str, count: int, ttl: int, size: int):
    """Custom ICMP ping."""
    from argos.core.packet_factory import send_icmp_ping

    def log(msg):
        console.print(f"  [bright_white]|[/bright_white] {msg}")

    console.print(
        f"\n[bright_cyan]ARGOS ICMP Ping -> {dst_ip} "
        f"(count={count}, ttl={ttl}, size={size})[/bright_cyan]\n"
    )
    stats = send_icmp_ping(dst_ip, count=count, ttl=ttl, payload_size=size, log_callback=log)

    if stats["avg_ms"] is not None:
        console.print(
            f"\n  [bold bright_green]Min: {stats['min_ms']}ms  "
            f"Avg: {stats['avg_ms']}ms  Max: {stats['max_ms']}ms[/bold bright_green]"
        )
    console.print(f"  [dim]Loss: {stats['loss_pct']}%[/dim]")


def _check_admin_silent():
    """Check admin privileges without exiting."""
    system = platform.system().lower()
    if system == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────


def main():
    """Main entry point for ARGOS v1."""
    # Parse args first so --help always works without admin
    args, parser = parse_args()

    # If no CLI command requested, launch interactive menu
    if not any(
        [
            args.scan,
            args.interfaces,
            args.server,
            args.client,
            args.dst,
            args.probe,
            args.traceroute,
            args.ping,
        ]
    ):
        from argos.core.terminal import BANNER_ART, BANNER_SUBTITLE, BANNER_VERSION
        enforce_admin()
        
        from argos.core.updater import check_for_updates
        check_for_updates()
        
        console.print(BANNER_ART)
        console.print(BANNER_SUBTITLE)
        console.print(BANNER_VERSION)
        console.print()

        from argos.core.controller import ArgosController
        ArgosController().run_main_menu()
        return

    # CLI mode: require admin for actual operations
    enforce_admin()

    # Check for updates on GitHub
    from argos.core.updater import check_for_updates

    check_for_updates()

    # Dispatch to the requested command
    if args.scan:
        from argos.core.controller import ArgosController
        ArgosController().cmd_lan_scan(ports_to_scan=[])
    elif args.interfaces:
        cmd_show_interfaces()
    elif args.server:
        from argos.core.speed_test import DEFAULT_PORT

        cmd_server(DEFAULT_PORT)
    elif args.client:
        from argos.core.speed_test import DEFAULT_PORT

        cmd_client(args.client, DEFAULT_PORT, args.duration)
    elif args.dst:
        cmd_tcp_custom(args.dst, args.port, args.flags, args.sport)
    elif args.probe:
        cmd_tcp_probe(args.probe, args.ports)
    elif args.traceroute:
        cmd_traceroute(args.traceroute, args.max_hops)
    elif args.ping:
        cmd_icmp_ping(args.ping, args.count, args.ttl, args.size)


if __name__ == "__main__":
    main()
