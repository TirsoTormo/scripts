"""
Argos Packet Factory - Layer 3 (Network)
========================================
ICMP Ping and Traceroute operations.
"""

import time
from collections.abc import Callable

from scapy.all import ICMP, IP, conf, sr1

from .utils import _log_msg, _validate_target


def send_icmp_ping(
    target_ip: str,
    count: int = 4,
    ttl: int = 64,
    payload_size: int = 56,
    log_callback: Callable | None = None,
) -> dict:
    """Sends a custom ICMP Ping."""
    _validate_target(target_ip)
    _log_msg(log_callback, f"[LAYER 3] ICMP Echo Request → {target_ip} (TTL: {ttl})")

    conf.verb = 0
    stats = {
        "dst": target_ip,
        "sent": 0,
        "received": 0,
        "lost": 0,
        "min_ms": None,
        "max_ms": None,
        "avg_ms": 0,
    }
    latencies = []

    for i in range(count):
        stats["sent"] += 1
        pkt = IP(dst=target_ip, ttl=ttl) / ICMP() / (b"X" * payload_size)
        try:
            ans = sr1(pkt, timeout=2, verbose=False)
            if ans:
                stats["received"] += 1
                lat = round((ans.time - pkt.time) * 1000, 2)
                latencies.append(lat)
                _log_msg(
                    log_callback,
                    f"  Reply from {target_ip}: bytes={payload_size} latency={lat}ms TTL={ans.ttl}",
                )
            else:
                _log_msg(log_callback, "  Request timed out.")
        except Exception as e:
            _log_msg(log_callback, f"  Error: {e}")

        if i < count - 1:
            time.sleep(0.5)

    if latencies:
        stats["min_ms"] = min(latencies)
        stats["max_ms"] = max(latencies)
        stats["avg_ms"] = round(sum(latencies) / len(latencies), 2)

    stats["lost"] = stats["sent"] - stats["received"]
    stats["loss_pct"] = round((stats["lost"] / stats["sent"]) * 100, 1)
    # Store last response TTL for fingerprinting
    stats["ttl"] = ans.ttl if "ans" in locals() and ans else None
    return stats


def manual_traceroute(
    target_ip: str, max_hops: int = 30, log_callback: Callable | None = None
) -> list[dict]:
    """Manual Traceroute with incremental TTL."""
    _validate_target(target_ip)
    _log_msg(log_callback, f"[LAYER 3] Manual Traceroute to {target_ip} (Max Hops: {max_hops})")

    hops = []
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / ICMP()
        start_time = time.perf_counter()

        try:
            ans = sr1(pkt, timeout=2, verbose=False)
            elapsed = round((time.perf_counter() - start_time) * 1000, 2)

            if ans is None:
                hops.append({"ttl": ttl, "ip": "*", "latency_ms": None, "status": "timeout"})
                _log_msg(log_callback, f"  {ttl}\t*\tRequest timed out.")
            else:
                hops.append(
                    {
                        "ttl": ttl,
                        "ip": ans.src,
                        "latency_ms": elapsed,
                        "status": "ok",
                        "response_ttl": ans.ttl,
                    }
                )
                _log_msg(log_callback, f"  {ttl}\t{ans.src}\t{elapsed}ms")
                if ans.src == target_ip:
                    _log_msg(log_callback, "Target reached.")
                    break
        except Exception as e:
            _log_msg(log_callback, f"  {ttl}\tError: {e}")
            break

    return hops
