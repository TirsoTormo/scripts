# pylint: disable=no-else-return, too-many-boolean-expressions, wrong-import-order
"""
NetScanner - Network Utilities
Helper functions to obtain network interface information,
calculate subnets, and validate private IP addresses.
"""

import ipaddress
import socket

import psutil


def get_local_interfaces() -> list[dict]:
    """
    Obtains all active network interfaces of the system with their information.

    Returns:
        List of dictionaries with info for each interface:
        - name: Interface name
        - ip: IPv4 address
        - mask: Subnet mask
        - mac: MAC address
        - type: Estimated type (Ethernet/Wi-Fi/Loopback/Virtual)
        - is_up: Whether the interface is active
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for iface_name, iface_addrs in addrs.items():
        ipv4 = None
        mask = None
        mac = None

        for addr in iface_addrs:
            # IPv4
            if addr.family == socket.AF_INET:
                ipv4 = addr.address
                mask = addr.netmask
            # MAC
            if addr.family == psutil.AF_LINK:
                mac = addr.address

        if ipv4 is None:
            continue

        is_up = stats.get(iface_name, None)
        is_up = is_up.isup if is_up else False

        iface_type = _detect_interface_type(iface_name, ipv4)

        interfaces.append(
            {
                "name": iface_name,
                "ip": ipv4,
                "mask": mask or "255.255.255.0",
                "mac": mac or "N/A",
                "type": iface_type,
                "is_up": is_up,
            }
        )

    return interfaces


def _detect_interface_type(name: str, ip: str) -> str:
    """Detects the type of interface based on its name and IP."""
    name_lower = name.lower()

    if ip == "127.0.0.1":
        return "🔁 Loopback"
    elif any(kw in name_lower for kw in ["wi-fi", "wifi", "wlan", "wireless"]):
        return "📶 Wi-Fi"
    elif any(kw in name_lower for kw in ["ethernet", "eth", "en0", "enp", "eno"]):
        return "🔌 Ethernet"
    elif any(
        kw in name_lower
        for kw in ["vmware", "virtualbox", "vbox", "hyper-v", "docker", "vethernet"]
    ):
        return "💻 Virtual"
    elif any(kw in name_lower for kw in ["vpn", "tun", "tap", "wg"]):
        return "🔒 VPN"
    else:
        return "🌐 Other"


def get_network_cidr(ip: str, mask: str) -> str:
    """
    Calculates the CIDR of the subnet from IP and mask.

    Args:
        ip: IPv4 address (e.g., '192.168.1.100')
        mask: Subnet mask (e.g., '255.255.255.0')

    Returns:
        String with the network in CIDR format (e.g., '192.168.1.0/24')
    """
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network)
    except (ValueError, TypeError):
        return f"{ip}/24"


def is_private_ip(ip: str) -> bool:
    """
    Verifies that an IP address is private (RFC 1918).
    This ensures that it never goes out to the Internet.

    Args:
        ip: IPv4 address

    Returns:
        True if the IP is private
    """
    try:
        return ipaddress.IPv4Address(ip).is_private
    except (ValueError, TypeError):
        return False


def resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    """
    Attempts to resolve the hostname of an IP using reverse DNS and NetBIOS.

    Args:
        ip: IPv4 address
        timeout: Maximum wait time in seconds

    Returns:
        Resolved hostname or 'Unknown'
    """
    # 1. DNS Standard (mDNS / Local DNS)
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except (TimeoutError, socket.herror, socket.gaierror, OSError):
        pass

    # 2. NetBIOS Fallback (Windows)
    try:
        import platform
        import re
        import subprocess

        if platform.system().lower() == "windows":
            cmd = ["nbtstat", "-A", ip]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1.5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # Search for line type: "   DEVICENAME   <00>  UNIQUE"
            match = re.search(r"\s+([A-Za-z0-9\-_]+)\s+<00>\s+UNIQUE", result.stdout)
            if match:
                return match.group(1).strip()
    except Exception:
        pass

    return "Unknown"


def get_active_interfaces() -> list[dict]:
    """
    Obtains only active interfaces with a private IP (excluding loopback and virtuals).
    Ideal for selecting the scanning interface.
    """
    interfaces = get_local_interfaces()
    active = []
    for iface in interfaces:
        if (
            iface["is_up"]
            and iface["ip"] != "127.0.0.1"
            and is_private_ip(iface["ip"])
            and "Virtual" not in iface["type"]
            and "VPN" not in iface["type"]
            and "Loopback" not in iface["type"]
        ):
            active.append(iface)
    return active


def get_gateway_ip(ip: str, mask: str) -> str:
    """
    Estimates the gateway IP (normally .1 of the subnet).

    Args:
        ip: IPv4 address of the host
        mask: Subnet mask

    Returns:
        Estimated gateway IP
    """
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        hosts = list(network.hosts())
        return str(hosts[0]) if hosts else ip
    except (ValueError, TypeError):
        parts = ip.split(".")
        parts[-1] = "1"
        return ".".join(parts)


def get_all_host_ips(ip: str, mask: str) -> list[str]:
    """
    Generates the list of all possible host IPs in the subnet.

    Args:
        ip: IPv4 address
        mask: Subnet mask

    Returns:
        List of IPs as strings
    """
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return [str(h) for h in network.hosts()]
    except (ValueError, TypeError):
        return []
