"""
ARGOS v1 — Packet Factory Package
===================================
A modular suite for low-level packet crafting and network probing.
Categorized by OSI layers for better maintainability.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .dhcp import discover_dhcp_servers as discover_dhcp_servers
from .l2 import craft_ethernet_frame as craft_ethernet_frame
from .l2 import send_arp_request as send_arp_request
from .l3 import manual_traceroute as manual_traceroute
from .l3 import send_icmp_ping as send_icmp_ping
from .l4 import craft_tcp_packet as craft_tcp_packet
from .l4 import send_tcp_custom as send_tcp_custom
from .l4 import send_udp_probe as send_udp_probe
from .l4 import tcp_port_probe as tcp_port_probe
from .utils import _validate_target as _validate_target


def craft_ip_packet(dst_ip: str, src_ip: str | None = None, ttl: int = 64) -> Any:
    """Craft a raw IP packet via Scapy."""
    from scapy.all import IP

    pkt = IP(dst=dst_ip, ttl=ttl)
    if src_ip:
        pkt.src = src_ip
    return pkt


def send_custom_packet(
    pkt: Any,
    timeout: int = 2,
    layer2: bool = False,
    log_callback: Callable | None = None,
) -> Any:
    """Send a custom packet and return the response."""
    from scapy.all import conf, sr1, srp1

    conf.verb = 0
    try:
        if layer2:
            ans = srp1(pkt, timeout=timeout, verbose=False)
        else:
            ans = sr1(pkt, timeout=timeout, verbose=False)

        if ans:
            if log_callback:
                log_callback(f"[PACKET FACTORY] Response received: {ans.summary()}")
            return ans
    except Exception as e:
        if log_callback:
            log_callback(f"[PACKET FACTORY] Error: {e}")
    return None


def describe_flags(flags: str) -> str:
    """Return a human-readable description of TCP flags."""
    flag_map = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }
    parts = [flag_map.get(c, c) for c in flags.upper()]
    return "+".join(parts)


def get_common_port_groups() -> dict[str, list[int]]:
    """Returns preset port groups for scanning."""
    return {
        "top20": [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1723,
            3306,
            3389,
            5900,
            8080,
        ],
        "web": [80, 443, 8080, 8443, 3000, 5000],
        "infra": [22, 23, 53, 161, 445, 3389],
        "db": [1433, 3306, 5432, 6379, 27017],
    }
