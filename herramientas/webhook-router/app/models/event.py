import time
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

class EventSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

class Event(BaseModel):
    """
    Data model representing an infrastructure alert or event.
    Validates the incoming webhook payload.
    Supports flexible metadata keys for targeted automated SSH remediation.
    """
    token: str = Field(..., description="Security token to validate the request.")
    source: str = Field(..., description="Name of the server or source host that generated this event.")
    service: str = Field(..., description="Name of the affected service or component (e.g., docker-nginx).")
    severity: EventSeverity = Field(..., description="Severity level: INFO, WARNING, or CRITICAL.")
    message: str = Field(..., description="Explanatory text describing the event details.")
    timestamp: Optional[int] = Field(
        default_factory=lambda: int(time.time()), 
        description="UNIX timestamp of when the event occurred. Auto-generated if omitted."
    )
    
    # Flexible metadata dict supporting advanced Docker & SSH targeting overrides
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Flexible dictionary for advanced telemetry metadata. Can include:\n"
            "- 'docker_container': Target docker container name to restart.\n"
            "- 'remediation_cmd': Command to override default SSH remediation.\n"
            "- 'ssh_host_override': Direct specific host IP/Domain for remediation.\n"
            "- 'ssh_user_override': Direct specific SSH username for the host.\n"
            "- 'failing_streak': Consecutive failure counter.\n"
            "- 'logs': Last lines of the service log output."
        )
    )

    @field_validator("severity", mode="before")
    @classmethod
    def capitalize_severity(cls, value: str) -> str:
        """Coerces lowercase string severities (e.g. 'critical') to uppercase Enums."""
        if isinstance(value, str):
            return value.upper()
        return value

    def get_deduplication_key(self) -> str:
        """Generates a unique key based on source, service, and severity for deduplication."""
        return f"{self.source.lower()}:{self.service.lower()}:{self.severity.value}"
