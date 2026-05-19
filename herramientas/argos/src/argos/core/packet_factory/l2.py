"""
Argos Packet Factory - Layer 2 (Data Link)
==========================================
ARP operations and frames resolution.
"""

from collections.abc import Callable

from scapy.all import ARP, Ether, conf, srp1

from .utils import _log_msg, _validate_target


def send_arp_request(
    target_ip: str, src_mac: str | None = None, log_callback: Callable | None = None
) -> dict | None:
    """
    Sends an ARP Request to the network.
    Returns a dict with {ip, response_mac, latency_ms} or None.
    """
    _validate_target(target_ip)
    _log_msg(log_callback, f"[LAYER 2] ARP Request → {target_ip}")

    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    if src_mac:
        pkt[Ether].src = src_mac

    try:
        ans = srp1(pkt, timeout=2, verbose=False)
        if ans:
            _log_msg(log_callback, f"[LAYER 2] Received ARP Response from {ans.psrc}")
            return {
                "ip": ans.psrc,
                "response_mac": ans.hwsrc.upper(),
                "latency_ms": round((ans.time - pkt.time) * 1000, 2),
            }
    except Exception as e:
        _log_msg(log_callback, f"[LAYER 2] Error sending ARP: {e}")

    return None


def craft_ethernet_frame(dst_mac: str, src_mac: str) -> Ether:
    """Creates a basic Ethernet II frame."""
    return Ether(dst=dst_mac, src=src_mac)
