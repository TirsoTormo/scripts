import time
from collections.abc import Callable
from typing import Any

from argos.core.packet_factory.utils import _log_msg


def discover_dhcp_servers(
    timeout: int = 5, log_callback: Callable | None = None
) -> list[dict[str, Any]]:
    """
    Sends a DHCP Discover broadcast and collects all DHCP Offers.
    Useful for identifying Rogue DHCP servers on the subnet.
    """
    try:
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, srp
    except ImportError:
        _log_msg(log_callback, "[ERROR] Scapy is required for DHCP discovery.")
        return []

    conf.verb = 0
    _log_msg(log_callback, "[DHCP] Sending DHCP Discover Broadcast...")

    # Craft DHCP Discover Packet
    # Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
    # / UDP(sport=68, dport=67) / BOOTP(chaddr=mac_address)
    # / DHCP(options=[("message-type", "discover"), "end"])
    import uuid

    mac = uuid.getnode()
    mac_bytes = mac.to_bytes(6, byteorder="big")

    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes, xid=int(time.time()))
        / DHCP(options=[("message-type", "discover"), "end"])
    )

    servers = []
    _log_msg(log_callback, f"[DHCP] Listening for Offers for {timeout} seconds...")

    try:
        ans, unans = srp(dhcp_discover, multi=True, timeout=timeout, verbose=False)
        for _snd, rcv in ans:
            if rcv.haslayer(DHCP):
                options = rcv[DHCP].options
                server_ip = rcv[IP].src
                mac_addr = rcv[Ether].src

                # Extract options
                subnet_mask = ""
                router = ""
                dns = []
                for opt in options:
                    if isinstance(opt, tuple):
                        if opt[0] == "subnet_mask":
                            subnet_mask = opt[1]
                        elif opt[0] == "router":
                            router = opt[1]
                        elif opt[0] == "name_server":
                            dns.append(opt[1])

                server_info = {
                    "ip": server_ip,
                    "mac": mac_addr,
                    "subnet_mask": subnet_mask,
                    "router": router,
                    "dns": dns,
                }
                servers.append(server_info)
                _log_msg(log_callback, f"[DHCP] Found Offer from {server_ip} ({mac_addr})")
    except Exception as e:
        _log_msg(log_callback, f"[DHCP] Error during discovery: {e}")

    return servers
