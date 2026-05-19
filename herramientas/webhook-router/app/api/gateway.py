import hmac
import logging
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.models.event import Event, EventSeverity
from app.core.config import settings
from app.services.router_engine import router_engine
from app.api.auth import require_operator

logger = logging.getLogger("webhook-gateway.gateway")

router = APIRouter(tags=["Webhook Ingress"])

class SimulateRequest(BaseModel):
    source: str
    service: str
    severity: str = Field(pattern="^(INFO|WARNING|CRITICAL)$")
    message: str
    metadata: dict


@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def receive_webhook(
    event: Event, 
    background_tasks: BackgroundTasks,
    x_gateway_token: Optional[str] = Header(None, alias="X-Gateway-Token")
):
    """
    HTTP Webhook Ingress Port.
    
    1. Validates authentication token in a secure, constant-time compare block.
    2. Instantly responds with HTTP 202 Accepted.
    3. Asynchronously delegates execution and dynamic routing to the worker queue.
    """
    # Accept token either from the HTTP Header (preferred) or body field
    provided_token = x_gateway_token or event.token
    
    # Prevent timing attacks via constant-time comparison digest validation
    if not provided_token or not hmac.compare_digest(provided_token, settings.GATEWAY_TOKEN):
        logger.warning(f"Unauthorized Ingress attempt from server host '{event.source}' with invalid token.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid gateway credentials."
        )

    # Schedule event routing asynchronously to respond immediately to the client
    background_tasks.add_task(router_engine.route_event, event)
    
    logger.info(f"Ingress accepted alert for background queue: {event.source} -> {event.service} ({event.severity.value})")
    
    return {
        "status": "accepted",
        "message": "Event received and scheduled for background execution.",
        "details": {
            "source": event.source,
            "service": event.service,
            "severity": event.severity.value,
            "timestamp": event.timestamp
        }
    }

@router.post("/api/simulate", status_code=status.HTTP_202_ACCEPTED, dependencies=[require_operator])
async def simulate_webhook(
    payload: SimulateRequest,
    background_tasks: BackgroundTasks
):
    """
    Secure Webhook Simulation Endpoint.
    
    1. Authenticates operator session.
    2. Constructs Event using settings.GATEWAY_TOKEN.
    3. Triggers async worker engine routing.
    """
    event = Event(
        token=settings.GATEWAY_TOKEN,
        source=payload.source,
        service=payload.service,
        severity=EventSeverity(payload.severity),
        message=payload.message,
        metadata=payload.metadata
    )
    
    background_tasks.add_task(router_engine.route_event, event)
    
    logger.info(f"[SIMULATED] accepted alert for background queue: {event.source} -> {event.service} ({event.severity.value})")
    
    return {
        "status": "accepted",
        "message": "Simulated event received and scheduled for background execution.",
        "details": {
            "source": event.source,
            "service": event.service,
            "severity": event.severity.value,
            "timestamp": event.timestamp
        }
    }
