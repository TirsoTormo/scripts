"""
Argos — Report Exporter
Module to export scan results to multiple formats
such as JSON, Markdown, and CSV for professional audits.
"""

import csv
import datetime
import json

from argos.core.models import DeviceModel, ScanResultModel


class ReportExporter:
    """Class to handle network data exports."""

    @staticmethod
    def _get_timestamp() -> str:
        """Returns current timestamp in ISO 8601 format."""
        return datetime.datetime.now().isoformat()

    @classmethod
    def to_json(cls, filepath: str, scan: ScanResultModel) -> bool:
        """
        Exports ScanResultModel to a structured JSON file.
        """
        # Convert Pydantic model to dict (using model_dump for v2+)
        try:
            data = scan.model_dump(mode="json")

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False

    @classmethod
    def to_markdown(cls, filepath: str, scan: ScanResultModel) -> bool:
        """
        Exports ScanResultModel to a renderable Markdown report.
        """
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("# Argos Network Audit — Discovery Report\n\n")

                f.write("## 1. Execution Summary\n")
                f.write(f"- **Date**: `{scan.timestamp.isoformat()}`\n")
                f.write(f"- **Network**: `{scan.network_cidr}`\n")
                f.write(f"- **Method**: `{scan.scan_method}`\n")
                f.write(f"- **Duration**: `{scan.duration_sec:.2f} s`\n")
                f.write(f"- **Total Devices**: `{scan.devices_found}`\n\n")

                f.write("## 2. Asset Inventory\n\n")
                f.write("| # | IP | MAC | Hostname | Latency (ms) | Manufacturer |\n")
                f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")

                for i, d in enumerate(scan.devices, 1):
                    ip = d.ip
                    mac = d.mac
                    host = d.hostname
                    lat = d.latency_ms if d.latency_ms is not None else "N/A"
                    if isinstance(lat, float):
                        lat = f"{lat:.1f}"
                    vendor = d.vendor
                    f.write(f"| {i} | `{ip}` | `{mac}` | {host} | {lat} | {vendor} |\n")

                f.write("\n---\n*Report generated automatically by Argos Network Toolkit*\n")

            return True
        except Exception as e:
            print(f"Error exporting to Markdown: {e}")
            return False

    @classmethod
    def to_csv(
        cls,
        filepath: str,
        devices: list[DeviceModel],
    ) -> bool:
        """
        Exports a list of DeviceModel objects to a CSV.
        """
        if not devices:
            return False

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Set headers
                headers = ["ip", "mac", "hostname", "vendor", "latency_ms", "method"]
                writer.writerow([h.upper() for h in headers])

                for d in devices:
                    row = [
                        d.ip,
                        d.mac,
                        d.hostname,
                        d.vendor,
                        d.latency_ms if d.latency_ms is not None else "",
                        d.method,
                    ]
                    writer.writerow(row)

            return True
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False
