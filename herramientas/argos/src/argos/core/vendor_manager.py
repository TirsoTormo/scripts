"""
Argos v1.1.1 - Vendor Manager
Handles OUI/Manufacturer resolution by MAC concurrently,
implementing a persistent JSON cache system for maximum efficiency
and to respect Clean Architecture principles (Separation of Concerns).
"""

import json
import os
import ssl
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from argos.core.models import DeviceModel

CACHE_FILE = "vendors_cache.json"


def _resilient_retry(max_retries=3, base_delay=0.5):
    """Critical Retry Decorator (Exponential Backoff)."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            import time

            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception:
                    retries += 1
                    if retries == max_retries:
                        return ""
                    time.sleep(base_delay * (2 ** (retries - 1)))

        return wrapper

    return decorator


class VendorManager:
    def __init__(self):
        self.cache: dict[str, str] = self._load_cache()
        # Local fallback for most common network MACs (to avoid API calls)
        self.fast_fallback = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "08:00:27": "VirtualBox",
            "B8:27:EB": "Raspberry Pi",
            "3C:22:FB": "Apple",
            "A4:83:E7": "Apple",
            "00:1A:2B": "Cisco",
            "00:1B:54": "Cisco",
            "C8:D9:D2": "TP-Link",
            "10:FE:ED": "MikroTik",
            "00:1C:25": "Samsung",
            "94:B4:0F": "Ubiquiti",
            "04:18:D6": "Ubiquiti",
        }

    def _load_cache(self) -> dict[str, str]:
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=4)
        except Exception:
            pass

    @_resilient_retry(max_retries=3, base_delay=0.5)
    def _fetch_from_api(self, prefix: str) -> str:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            f"https://api.macvendors.com/{prefix.replace(':', '-')}",
            headers={"User-Agent": "Argos-Network-Audit/1.2.0"},
        )
        with urllib.request.urlopen(req, timeout=2.0, context=ctx) as response:
            return response.read().decode("utf-8").strip()

    def _resolve_single_mac(self, mac: str) -> str:
        if not mac or mac == "N/A":
            return ""

        prefix = mac.upper().replace("-", ":").replace(".", ":")[:8]

        # 1. Caché JSON (Memoria)
        if prefix in self.cache:
            return self.cache[prefix]

        # 2. Fallback dict interno
        if prefix in self.fast_fallback:
            return self.fast_fallback[prefix]

        # 3. HTTP API API (Costoso)
        vendor = self._fetch_from_api(prefix)
        if vendor:
            self.cache[prefix] = vendor
        return vendor

    def resolve_vendors_concurrently(
        self,
        devices: list[DeviceModel],
        max_workers: int = 15,
        progress_callback: Callable | None = None,
    ):
        """
        Resolves vendors for the device list in-place (mutating the list).
        Uses JSON cache and HTTP concurrency to avoid blocking the main scanner.
        """
        # Get unique MACs that we don't already know
        macs_to_resolve = set()
        for d in devices:
            mac = d.mac
            if mac and mac != "N/A":
                prefix = mac.upper().replace("-", ":").replace(".", ":")[:8]
                if prefix not in self.cache and prefix not in self.fast_fallback:
                    macs_to_resolve.add(mac)

        total_api_calls = len(macs_to_resolve)
        completed = 0

        # First we resolve fast or hit API in parallel
        if total_api_calls > 0:
            if progress_callback:
                progress_callback("Consulting OUI database...", 0.0)

            needs_save = False
            executor = ThreadPoolExecutor(max_workers=max_workers)
            futures = {
                executor.submit(self._resolve_single_mac, mac): mac for mac in macs_to_resolve
            }
            try:
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        needs_save = True

                    completed += 1
                    if progress_callback:
                        progress_callback(
                            f"Resolving Manufacturers ({completed}/{total_api_calls})...",
                            completed / max(total_api_calls, 1),
                        )
            except KeyboardInterrupt:
                for f in futures:
                    f.cancel()
                executor.shutdown(wait=False)
                raise
            else:
                executor.shutdown(wait=True)

            if needs_save:
                self._save_cache()
        else:
            if progress_callback:
                progress_callback("Fabricantes cargados desde caché.", 1.0)

        # Assign vendors to the original model objects
        for d in devices:
            mac = d.mac
            if mac and mac != "N/A":
                prefix = mac.upper().replace("-", ":").replace(".", ":")[:8]
                if prefix in self.cache:
                    d.vendor = self.cache[prefix]
                elif prefix in self.fast_fallback:
                    d.vendor = self.fast_fallback[prefix]
                else:
                    d.vendor = ""
            else:
                d.vendor = ""
