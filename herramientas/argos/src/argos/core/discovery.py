# pylint: disable=too-many-locals, broad-exception-caught, import-outside-toplevel, unused-variable, subprocess-run-check, unused-import
"""
NetScanner - Network Discovery Module
Scans the local network to detect connected devices.
Uses ARP Scan (Scapy) as the primary method and Ping Sweep as fallback.
"""

import ipaddress
import platform
import re
import subprocess
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from argos.core.models import DeviceModel
from argos.core.net_utils import (
    get_all_host_ips,
    get_network_cidr,
    resolve_hostname,
)


def arp_scan(ip: str, mask: str, progress_callback: Callable | None = None) -> list[dict]:
    """
    ARP Scan using Scapy. Fast and precise method.
    Requires administrator privileges.

    Args:
        ip: Local host IP
        mask: Subnet mask
        progress_callback: Optional function to report progress

    Returns:
        List of discovered devices
    """
    try:
        from scapy.all import ARP, Ether, conf, srp

        conf.verb = 0  # Silenciar output de Scapy

        cidr = get_network_cidr(ip, mask)

        if progress_callback:
            progress_callback("Sending ARP packets...", 0.1)

        arp_request = ARP(pdst=cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        if progress_callback:
            progress_callback("Waiting for responses...", 0.3)

        try:
            answered, _ = srp(packet, timeout=3, retry=1, verbose=False)
        except Exception as e:
            msg = str(e).lower()
            if (
                "winpcap is not installed" in msg
                or "npcap" in msg
                or "not available at layer 2" in msg
                or "layer 2" in msg
                and "pcap" in msg
            ):
                if progress_callback:
                    progress_callback(
                        "Layer 2 not available (Npcap/WinPcap missing). Using Ping Sweep...",
                        0.05,
                    )
                return []
            raise

        devices = []
        total = len(answered)

        for i, (_sent, received) in enumerate(answered):
            target_ip = received.psrc
            target_mac = received.hwsrc

            if target_ip == ip:
                continue

            if progress_callback:
                pct = 0.4 + (0.5 * (i + 1) / max(total, 1))
                progress_callback(f"Resolving {target_ip}...", pct)

            hostname = resolve_hostname(target_ip)
            latency = _ping_host(target_ip)

            devices.append(
                DeviceModel(
                    ip=target_ip,
                    mac=target_mac,
                    hostname=hostname,
                    latency_ms=latency,
                    method="ARP",
                )
            )

        if progress_callback:
            progress_callback("ARP Scan completed", 1.0)

        devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
        return devices

    except ImportError:
        if progress_callback:
            progress_callback("Scapy not available. Using Ping Sweep...", 0.05)
        return []
    except PermissionError:
        if progress_callback:
            progress_callback("No privileges for ARP (Admin required). Using Ping Sweep...", 0.05)
        return []
    except Exception as e:
        if progress_callback:
            progress_callback(f"ARP Scan failed ({e}). Using Ping Sweep...", 0.05)
        return []


def ping_sweep(
    ip: str, mask: str, max_workers: int = 50, progress_callback: Callable | None = None
) -> list[dict]:
    """
    Ping Sweep scan using system's native 'ping' command.
    Fallback method that doesn't require special privileges.

    Args:
        ip: Local host IP
        mask: Subnet mask
        max_workers: Maximum number of concurrent threads
        progress_callback: Optional function to report progress

    Returns:
        List of discovered devices
    """
    host_ips = get_all_host_ips(ip, mask)
    # Excluir nuestra propia IP
    host_ips = [h for h in host_ips if h != ip]

    if not host_ips:
        return []

    devices = []
    total = len(host_ips)
    completed = 0

    def ping_single(target_ip: str) -> dict | None:
        nonlocal completed
        latency = _ping_host(target_ip)
        completed += 1

        if progress_callback and completed % 10 == 0:
            pct = completed / total
            progress_callback(f"Ping {completed}/{total} - {target_ip}", pct)

        if latency is not None:
            hostname = resolve_hostname(target_ip)
            mac = _get_mac_from_arp_table(target_ip)
            return DeviceModel(
                ip=target_ip, mac=mac, hostname=hostname, latency_ms=latency, method="Ping"
            )
        return None

    if progress_callback:
        progress_callback(f"Starting ping sweep on {total} hosts...", 0.0)

    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = {executor.submit(ping_single, h): h for h in host_ips}
    try:
        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)
    except KeyboardInterrupt:
        for f in futures:
            f.cancel()
        executor.shutdown(wait=False)
        raise
    else:
        executor.shutdown(wait=True)

    if progress_callback:
        progress_callback("Ping sweep completed", 1.0)

    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return devices


def full_scan(ip: str, mask: str, progress_callback: Callable | None = None) -> tuple:
    """
    Executes a complete scan: attempts ARP first, if it fails uses Ping Sweep.

    Args:
        ip: Local host IP
        mask: Subnet mask
        progress_callback: Progress callback

    Returns:
        Tuple (device_list, method_used)
    """
    if progress_callback:
        progress_callback("Attempting ARP scan...", 0.0)

    devices = arp_scan(ip, mask, progress_callback)

    if devices:
        return devices, "ARP Scan (Scapy)"

    if progress_callback:
        progress_callback("ARP not available, using Ping Sweep...", 0.05)

    devices = ping_sweep(ip, mask, progress_callback=progress_callback)
    return devices, "Ping Sweep (fallback)"


def _ping_host(ip: str, count: int = 1, timeout: int = 1) -> float | None:
    """
    Pings a host and returns latency in ms.

    Returns:
        Latency in ms or None if no response
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]

    try:
        start = time.perf_counter()
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0,
        )
        elapsed = (time.perf_counter() - start) * 1000

        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="ignore")
            # Intentar extraer latencia del output
            match = re.search(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", output)
            if match:
                return float(match.group(1))
            return round(elapsed, 2)
        return None
    except (subprocess.TimeoutExpired, Exception):
        return None


def _get_mac_from_arp_table(ip: str) -> str:
    """
    Looks for the MAC of an IP in the system ARP table.
    """
    try:
        system = platform.system().lower()
        cmd = ["arp", "-a", ip] if system == "windows" else ["arp", "-n", ip]

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0,
        )
        output = result.stdout.decode("utf-8", errors="ignore")

        # Buscar MAC en formato xx-xx-xx-xx-xx-xx o xx:xx:xx:xx:xx:xx
        mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
        match = re.search(mac_pattern, output)
        if match:
            return match.group(0).upper().replace("-", ":")
        return "N/A"
    except Exception:
        return "N/A"
