"""
Argos Packet Factory - Utilities
================================
Validation and internal helpers for packet crafting.
"""

import ipaddress
from collections.abc import Callable


def _validate_target(ip: str):
    """Validates IP format before proceeding."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as err:
        raise ValueError(f"Invalid IPv4 address: {ip}") from err


def _log_msg(log_callback: Callable | None, msg: str):
    """Internal logger helper."""
    if log_callback:
        log_callback(msg)
