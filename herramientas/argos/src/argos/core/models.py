"""
Argos Pro — Data Models
=============================================
Strict Pydantic schemas for enterprise data integrity.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class DeviceModel(BaseModel):
    """Schema for a discovered network device."""

    ip: str  # String for flexible CIDR/IP handling, but validated by Scapy/Utils
    mac: str = "N/A"
    hostname: str = "Unknown"
    vendor: str = ""
    latency_ms: float | None = None
    method: str = "Unknown"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_new: bool = False
    open_ports: list[int] = Field(default_factory=list)
    extra_info: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, v: str) -> str:
        return v.upper().replace("-", ":")


class ScanResultModel(BaseModel):
    """Schema for a complete network scan."""

    timestamp: datetime = Field(default_factory=datetime.now)
    network_cidr: str
    scan_method: str
    duration_sec: float
    devices_found: int
    devices: list[DeviceModel] = []
