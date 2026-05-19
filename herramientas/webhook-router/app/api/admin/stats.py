import time
from fastapi import APIRouter, Depends, Request, status
from app.core.database import db_manager
from app.core.config import settings
from app.services.router_engine import router_engine
from app.api.auth import require_viewer

router = APIRouter()

@router.get("/stats", status_code=status.HTTP_200_OK, dependencies=[require_viewer])
async def get_live_statistics(request: Request):
    """
    Secure Operator/Viewer Endpoint.
    Retrieves real-time telemetry statistics, SQLite database remediation metrics,
    active deduplication settings, and gateway server uptime.
    """
    # Calculate system uptime metrics
    startup_time = getattr(request.app.state, "startup_time", time.time())
    uptime_seconds = int(time.time() - startup_time)
    
    # Query event statistics from SQLite (async)
    event_counters = await db_manager.get_event_counters()
    
    # Query remediation statistics from SQLite (async)
    remediations_succeeded, remediations_failed = await db_manager.get_remediation_statistics()
    
    # Fetch recent remediation attempts (async)
    recent_attempts = await db_manager.get_recent_remediations(limit=5)
    
    return {
        "gateway_status": "online",
        "server_uptime": {
            "seconds": uptime_seconds,
            "readable": f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s"
        },
        "event_telemetry": {
            "processed_by_severity": event_counters,
            "total_processed_events": sum(event_counters.values())
        },
        "automated_remediations": {
            "succeeded_count": remediations_succeeded,
            "failed_count": remediations_failed,
            "total_count": remediations_succeeded + remediations_failed,
            "success_rate_percent": (
                round((remediations_succeeded / (remediations_succeeded + remediations_failed)) * 100, 1)
                if (remediations_succeeded + remediations_failed) > 0 else 100.0
            ),
            "recent_remediation_history": recent_attempts
        },
        "active_configuration_profile": {
            "deduplication_window_seconds": settings.DEDUPLICATION_WINDOW_SECONDS,
            "digest_interval_seconds": settings.DIGEST_INTERVAL_SECONDS,
            "active_routing_rules": len(router_engine.rules)
        }
    }
