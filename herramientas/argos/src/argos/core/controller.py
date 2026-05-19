import json
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from argos.core.config import config
from argos.core.discovery import full_scan
from argos.core.models import ScanResultModel
from argos.core.net_utils import get_active_interfaces, get_network_cidr
from argos.core.terminal import (
    ARGOS_DIM,
    ARGOS_ERROR,
    ARGOS_PRIMARY,
    ARGOS_PRIMARY_BOLD,
    ARGOS_SUCCESS,
    ARGOS_WARN,
    ARGOS_WHITE,
)
from argos.main import _check_admin_silent
from argos.core.vendor_manager import VendorManager
from argos.storage.exporter import ReportExporter

console = Console()


class ArgosController:
    def __init__(self):
        self.vm = VendorManager()
        self.last_scan_data: dict[str, str] = self._load_last_scan()

    def _load_last_scan(self) -> dict[str, str]:
        """Loads previous scan MAC addresses to identify NEW devices."""
        try:
            path = Path(config.last_scan_file)
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                    # We just need a set/dict of MACs
                    return {
                        d.get("mac", ""): d.get("ip", "")
                        for d in data.get("devices", [])
                        if "mac" in d
                    }
        except Exception:
            pass
        return {}

    def _save_last_scan(self, scan_result: ScanResultModel):
        try:
            path = Path(config.last_scan_file)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(scan_result.model_dump(mode="json"), f, indent=4)
        except Exception:
            pass

    def run_main_menu(self):
        while True:
            console.print()
            menu = Table(
                show_header=False,
                box=box.ROUNDED,
                border_style=ARGOS_PRIMARY,
                padding=(0, 2),
                title=f"[{ARGOS_PRIMARY_BOLD}]ARGOS v1.1 -- MAIN MENU[/{ARGOS_PRIMARY_BOLD}]",
                title_style="bold",
            )
            menu.add_column(width=6, justify="center", style=ARGOS_PRIMARY_BOLD)
            menu.add_column(style=ARGOS_WHITE)

            menu.add_row("1", "NETWORK DISCOVERY -- Scan LAN & DHCP")
            menu.add_row("2", "PACKET FACTORY -- Send custom L2/L3/L4 packets")
            menu.add_row("3", "SPEED TEST -- Test LAN throughput")
            menu.add_row("4", "SETTINGS -- Configure Argos")
            menu.add_row("9", "EXIT")

            console.print(menu)

            try:
                choice = Prompt.ask(
                    f"[{ARGOS_PRIMARY}]ARGOS >[/{ARGOS_PRIMARY}]",
                    choices=["1", "2", "3", "4", "9"],
                    default="9",
                )
            except KeyboardInterrupt:
                console.print(f"\n[{ARGOS_DIM}]Exiting ARGOS.[/{ARGOS_DIM}]")
                break

            if choice == "1":
                self.menu_discovery()
            elif choice == "2":
                self.menu_packet_factory()
            elif choice == "3":
                self.menu_speed_test()
            elif choice == "4":
                self.menu_settings()
            elif choice == "9":
                break

    def menu_discovery(self):
        while True:
            console.print()
            menu = Table(
                show_header=False,
                box=box.ROUNDED,
                border_style=ARGOS_PRIMARY,
                padding=(0, 2),
                title=f"[{ARGOS_PRIMARY_BOLD}]DISCOVERY MENU[/{ARGOS_PRIMARY_BOLD}]",
            )
            menu.add_column(width=6, justify="center", style=ARGOS_PRIMARY_BOLD)
            menu.add_column(style=ARGOS_WHITE)
            menu.add_row("1", "QUICK LAN SCAN -- Standard Host Discovery")
            menu.add_row("2", "ADVANCED LAN SCAN -- Specify custom ports to probe")
            menu.add_row("3", "DHCP DISCOVERY -- Find Rogue DHCP Servers")
            menu.add_row("9", "BACK")
            console.print(menu)

            choice = Prompt.ask(
                f"[{ARGOS_PRIMARY}]DISCOVERY >[/{ARGOS_PRIMARY}]",
                choices=["1", "2", "3", "9"],
                default="9",
            )

            if choice == "1":
                self.cmd_lan_scan(ports_to_scan=[])
            elif choice == "2":
                ports_str = Prompt.ask(
                    f"[{ARGOS_PRIMARY}]Ports to scan "
                    f"(comma separated, e.g. 22,80,443)[/{ARGOS_PRIMARY}]",
                    default="80,443",
                )
                try:
                    ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
                    self.cmd_lan_scan(ports_to_scan=ports)
                except ValueError:
                    console.print("[red]Invalid ports format.[/red]")
            elif choice == "3":
                self.cmd_dhcp_discovery()
            elif choice == "9":
                break

    def cmd_dhcp_discovery(self):
        from argos.core.packet_factory import discover_dhcp_servers

        timeout = int(
            Prompt.ask(f"[{ARGOS_PRIMARY}]Timeout (seconds)[/{ARGOS_PRIMARY}]", default="5")
        )

        console.print(
            f"\n[bright_cyan]Broadcasting DHCP Discover for {timeout} seconds...[/bright_cyan]"
        )

        # We need admin for Scapy DHCP
        if not _check_admin_silent():
            console.print(
                f"[{ARGOS_WARN}]Warning: Root/Admin privileges "
                f"recommended for accurate packet crafting.[/{ARGOS_WARN}]"
            )

        with Progress(
            SpinnerColumn(spinner_name="dots2"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Listening for offers...", total=None)
            servers = discover_dhcp_servers(timeout=timeout)
            progress.update(task, completed=True)

        if not servers:
            console.print(
                f"[{ARGOS_WARN}]No DHCP servers responded in the given time.[/{ARGOS_WARN}]"
            )
            return

        table = Table(box=box.MINIMAL_DOUBLE_HEAD, border_style=ARGOS_PRIMARY)
        table.add_column("DHCP Server IP", style="cyan", justify="center")
        table.add_column("MAC Address", style="magenta")
        table.add_column("Subnet Mask", style="white")
        table.add_column("Router", style="yellow")
        table.add_column("DNS Servers", style="green")

        for s in servers:
            dns_str = ", ".join(s.get("dns", []))
            table.add_row(s["ip"], s["mac"], s.get("subnet_mask", ""), s.get("router", ""), dns_str)

        console.print()
        console.print(table)
        if len(servers) > 1:
            console.print(
                f"[{ARGOS_ERROR}]WARNING: Multiple DHCP servers detected! "
                f"Potential Rogue DHCP.[/{ARGOS_ERROR}]"
            )

    def cmd_lan_scan(self, ports_to_scan: list[int]):
        active = get_active_interfaces()
        if not active:
            console.print("[red]No active network interfaces found.[/red]")
            return

        iface = active[0]
        ip = iface["ip"]
        mask = iface["mask"]
        cidr = get_network_cidr(ip, mask)

        console.print(f"\n[bright_cyan]ARGOS scanning {cidr} ({iface['name']})...[/bright_cyan]\n")
        start = time.perf_counter()

        with Progress(
            SpinnerColumn(spinner_name="line"),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("[cyan]Starting...", total=1.0)

            def update_progress(msg: str, pct: float):
                progress.update(task_id, description=f"[cyan]{msg}", completed=pct)

            devices, method = full_scan(ip, mask, progress_callback=update_progress)

            progress.update(task_id, description="[cyan]Resolving manufacturers...", completed=0.8)
            self.vm.resolve_vendors_concurrently(devices)
            progress.update(task_id, completed=1.0)

        # Handle Port Scanning if requested
        if ports_to_scan and devices:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            from argos.core.packet_factory import tcp_port_probe

            console.print(
                f"\n[{ARGOS_DIM}]Starting Stealth SYN Port Scan (Evasion Mode)...[/{ARGOS_DIM}]"
            )

            def scan_host(device):
                res = tcp_port_probe(device.ip, ports_to_scan)
                open_ports = [r["port"] for r in res if r["status"] == "open"]
                device.open_ports = open_ports
                return device

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as prog:
                task = prog.add_task("[magenta]Scanning ports...", total=len(devices))
                with ThreadPoolExecutor(
                    max_workers=min(len(devices), config.max_threads)
                ) as executor:
                    futures = [executor.submit(scan_host, d) for d in devices]
                    for _f in as_completed(futures):
                        prog.update(task, advance=1)

        elapsed = time.perf_counter() - start

        # Mark New Devices
        for d in devices:
            if d.mac and d.mac != "N/A" and d.mac not in self.last_scan_data:
                d.is_new = True

        scan_result = ScanResultModel(
            network_cidr=cidr,
            scan_method=method,
            duration_sec=elapsed,
            devices_found=len(devices),
            devices=devices,
        )

        self._save_last_scan(scan_result)
        self.display_advanced_table(devices, method, elapsed, cidr)

        if config.auto_export_json:
            out_file = "argos_auto_export.json"
            if ReportExporter.to_json(out_file, scan_result):
                console.print(
                    f"[{ARGOS_SUCCESS}]Results auto-exported to {out_file}[/{ARGOS_SUCCESS}]"
                )
            out_csv = "argos_auto_export.csv"
            if ReportExporter.to_csv(out_csv, devices):
                console.print(
                    f"[{ARGOS_SUCCESS}]Results auto-exported to {out_csv}[/{ARGOS_SUCCESS}]"
                )

    def display_advanced_table(self, devices, method, elapsed, cidr):
        table = Table(
            box=box.MINIMAL_DOUBLE_HEAD,
            border_style=ARGOS_PRIMARY,
            header_style=f"bold {ARGOS_PRIMARY}",
        )
        table.add_column("IP Address", style=ARGOS_WHITE, justify="right")
        table.add_column("MAC Address", style=ARGOS_DIM)
        table.add_column("Hostname", style="cyan")
        table.add_column("Vendor", style="magenta")
        table.add_column("Ping", justify="right", style="green")
        table.add_column("Status", justify="center")
        table.add_column("Open Ports", style="yellow")

        for d in devices:
            lat = f"{d.latency_ms:.1f}ms" if d.latency_ms is not None else "-"
            # Highlight new devices
            status = (
                f"[{ARGOS_SUCCESS} blink]NEW[/{ARGOS_SUCCESS} blink]"
                if getattr(d, "is_new", False)
                else f"[{ARGOS_DIM}]Known[/{ARGOS_DIM}]"
            )
            ports_str = (
                ",".join(map(str, getattr(d, "open_ports", [])))
                if getattr(d, "open_ports", [])
                else ""
            )

            table.add_row(d.ip, d.mac, d.hostname, d.vendor, lat, status, ports_str)

        console.print(table)
        console.print(
            f"  [{ARGOS_DIM}]Network:[/{ARGOS_DIM}] {cidr}  |  "
            f"[{ARGOS_DIM}]Time:[/{ARGOS_DIM}] {elapsed:.1f}s  |  "
            f"[{ARGOS_DIM}]Devices:[/{ARGOS_DIM}] {len(devices)}"
        )

    def menu_packet_factory(self):
        while True:
            console.print()
            menu = Table(
                show_header=False,
                box=box.ROUNDED,
                border_style=ARGOS_PRIMARY,
                padding=(0, 2),
                title=f"[{ARGOS_PRIMARY_BOLD}]PACKET FACTORY[/{ARGOS_PRIMARY_BOLD}]",
            )
            menu.add_column(width=6, justify="center", style=ARGOS_PRIMARY_BOLD)
            menu.add_column(style=ARGOS_WHITE)
            menu.add_row("1", "TCP CUSTOM -- Send custom TCP segment with flags")
            menu.add_row("2", "ICMP PING -- Custom ping with TTL and size")
            menu.add_row("3", "TRACEROUTE -- Manual ICMP traceroute")
            menu.add_row("9", "BACK")
            console.print(menu)

            choice = Prompt.ask(
                f"[{ARGOS_PRIMARY}]FACTORY >[/{ARGOS_PRIMARY}]",
                choices=["1", "2", "3", "9"],
                default="9",
            )

            if choice == "1":
                from argos.main import cmd_tcp_custom

                dst = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
                port = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Port[/{ARGOS_PRIMARY}]", default="80"))
                flags = Prompt.ask(
                    f"  [{ARGOS_PRIMARY}]TCP Flags (S/SA/FA/R)[/{ARGOS_PRIMARY}]", default="S"
                )
                if dst:
                    cmd_tcp_custom(dst, port, flags)
            elif choice == "2":
                from argos.main import cmd_icmp_ping

                dst = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
                count = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]Count[/{ARGOS_PRIMARY}]", default="4"))
                ttl = int(Prompt.ask(f"  [{ARGOS_PRIMARY}]TTL[/{ARGOS_PRIMARY}]", default="64"))
                size = int(
                    Prompt.ask(f"  [{ARGOS_PRIMARY}]Payload size[/{ARGOS_PRIMARY}]", default="56")
                )
                if dst:
                    cmd_icmp_ping(dst, count, ttl, size)
            elif choice == "3":
                from argos.main import cmd_traceroute

                dst = Prompt.ask(f"  [{ARGOS_PRIMARY}]Destination IP[/{ARGOS_PRIMARY}]")
                max_hops = int(
                    Prompt.ask(f"  [{ARGOS_PRIMARY}]Max hops[/{ARGOS_PRIMARY}]", default="30")
                )
                if dst:
                    cmd_traceroute(dst, max_hops)
            elif choice == "9":
                break

    def menu_speed_test(self):
        while True:
            console.print()
            menu = Table(
                show_header=False,
                box=box.ROUNDED,
                border_style=ARGOS_PRIMARY,
                padding=(0, 2),
                title=f"[{ARGOS_PRIMARY_BOLD}]SPEED TEST[/{ARGOS_PRIMARY_BOLD}]",
            )
            menu.add_column(width=6, justify="center", style=ARGOS_PRIMARY_BOLD)
            menu.add_column(style=ARGOS_WHITE)
            menu.add_row("1", "SERVER -- Start speed test server")
            menu.add_row("2", "CLIENT -- Connect to a server")
            menu.add_row("9", "BACK")
            console.print(menu)

            choice = Prompt.ask(
                f"[{ARGOS_PRIMARY}]SPEED >[/{ARGOS_PRIMARY}]", choices=["1", "2", "9"], default="9"
            )

            if choice == "1":
                from argos.core.speed_test import DEFAULT_PORT
                from argos.main import cmd_server

                cmd_server(DEFAULT_PORT)
            elif choice == "2":
                from argos.core.speed_test import DEFAULT_PORT
                from argos.main import cmd_client

                server_ip = Prompt.ask(f"  [{ARGOS_PRIMARY}]Server IP[/{ARGOS_PRIMARY}]")
                if server_ip:
                    cmd_client(server_ip, DEFAULT_PORT, 10)
            elif choice == "9":
                break

    def menu_settings(self):
        console.print(f"\n[{ARGOS_PRIMARY_BOLD}]CURRENT SETTINGS:[/{ARGOS_PRIMARY_BOLD}]")
        console.print(f"  - Auto Export JSON/CSV: {config.auto_export_json}")
        console.print(f"  - Stealth Scan Mode: {config.stealth_mode}")
        console.print(f"  - Max Threads: {config.max_threads}")
        console.print(f"  - Last Scan File: {config.last_scan_file}")

        if Prompt.ask("Toggle Auto Export?", choices=["y", "n"], default="n") == "y":
            config.auto_export_json = not config.auto_export_json

        if Prompt.ask("Toggle Stealth Mode?", choices=["y", "n"], default="n") == "y":
            config.stealth_mode = not config.stealth_mode

        config.save()
        console.print(f"[{ARGOS_SUCCESS}]Settings saved.[/{ARGOS_SUCCESS}]")
