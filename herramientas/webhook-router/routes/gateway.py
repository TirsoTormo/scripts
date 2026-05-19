import hmac
import logging
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, status

from models import Event
from config import settings
from engine import router_engine

logger = logging.getLogger("webhook-gateway.gateway")

router = APIRouter(tags=["Webhook Ingress"])

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
