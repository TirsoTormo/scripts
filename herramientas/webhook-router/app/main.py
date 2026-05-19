import os
import time
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.responses import HTMLResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.core.config import settings
from app.services.router_engine import router_engine, send_periodic_digest
from app.core.database import db_manager

# Set up local logging format for server actions
logger = logging.getLogger("webhook-gateway.main")

# ======================================================================
# SECURE LIFESPAN CONTEXT MANAGER (FastAPI 2025/2026 Standards)
# ======================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP PROCESS ---
    # Premium English ASCII Banner
    print(r"""
======================================================================
  _    _      _Hobook   _____               _                       
 | |  | |    | |       |  __ \             | |                      
 | |  | | ___| |__     | |__) |___  _   _ _| |_ ___ _ __            
 | |/\| |/ _ \ '_ \    |  _  // _ \| | | | __/ _ \ '__|           
 \  /\  /  __/ |_) |   | | \ \ (_) | |_| | ||  __/ |               
  \/  \/ \___|_.__/    |_|  \_\___/ \__,_|\__\___|_|               
======================================================================
                  WEBHOOK GATEWAY INFRAROUTER v1.1.0
======================================================================
    """)
    logger.info("Initializing system configurations...")
    app.state.startup_time = time.time()
    
    # Initialize the database asynchronously
    logger.info("Initializing database...")
    await db_manager.initialize_database()
    
    token_hint = settings.GATEWAY_TOKEN[-4:] if len(settings.GATEWAY_TOKEN) > 4 else "Short"
    logger.info(f"Security: Secure verification active (Token suffix: ***{token_hint})")
    
    # Dynamically load YAML rules from disk
    router_engine.load_rules()
    
    # Assess target notification channels (Real client connections vs Local Simulation fallbacks)
    tg_mode = "🟢 REAL" if settings.is_telegram_configured else "🟡 SIMULATION (Console Only)"
    dsc_mode = "🟢 REAL" if settings.is_discord_configured else "🟡 SIMULATION (Console Only)"
    slk_mode = "🟢 REAL" if settings.is_slack_configured else "🟡 SIMULATION (Console Only)"
    ssh_mode = "🟢 REAL" if settings.is_ssh_configured else "🟡 SIMULATION (Console Only)"
    
    logger.info(f"Telegram Engine Status: {tg_mode}")
    logger.info(f"Discord Engine Status: {dsc_mode}")
    logger.info(f"Slack Engine Status: {slk_mode}")
    logger.info(f"SSH Remediation Target: {ssh_mode} (Target Host: {settings.SSH_HOST or 'N/A'})")
    logger.info(f"Deduplication Window: {settings.DEDUPLICATION_WINDOW_SECONDS} seconds")
    logger.info(f"Periodic Digest Interval: every {settings.DIGEST_INTERVAL_SECONDS} seconds")
    
    # Initialize and execute Async Scheduled Background Task loop
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        send_periodic_digest,
        trigger="interval",
        seconds=settings.DIGEST_INTERVAL_SECONDS,
        id="periodic_digest_job"
    )
    scheduler.start()
    logger.info("APScheduler worker launched successfully for consolidated digests.")
    
    yield  # API Server stays active and handles connections
    
    # --- SHUTDOWN PROCESS ---
    logger.info("Deactivating scheduled APScheduler worker...")
    scheduler.shutdown()
    logger.info("Webhook Gateway Server stopped cleanly.")


# ======================================================================
# FASTAPI APPLICATION SETUP
# ======================================================================
app = FastAPI(
    title="🛡️ Infrastructure Event Router (Webhook Gateway)",
    description=(
        "### Enterprise-Grade Ingress & Automation Gateway\n\n"
        "This service intercepts systems monitoring webhooks, securely validates payload authenticities "
        "using constant-time HMAC validations, routes events against custom `rules.yaml` triggers, "
        "and coordinates asynchronous rescue operations (SSH) or broadcasts (Telegram, Discord, Slack).\n\n"
        "**Advanced Features:**\n"
        "* ⚡ **Asynchronous Ingress:** sub-millisecond HTTP 202 responses using FastAPI BackgroundTasks.\n"
        "* 🛡️ **Role-Based Access Control (RBAC):** Gated access for Administrators, Operators, and Viewers.\n"
        "* 👤 **User Directory:** Built-in SQL user administration, dynamic password hashing, and active session control.\n"
        "* 🔄 **Hot-Reloading:** Dynamic real-time loading of YAML rules and environment configurations."
    ),
    version="1.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# ======================================================================
# MODULE ROUTERS INTEGRATION (MODULAR ARCHITECTURE)
# ======================================================================
from app.api.auth import router as auth_router
from app.api.admin import router as admin_router
from app.api.gateway import router as gateway_router

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(gateway_router)

# ======================================================================
# CORE GENERAL ENDPOINTS
# ======================================================================
@app.get("/", response_class=HTMLResponse, tags=["General"])
async def root_dashboard():
    """Serves the stunning, premium CodeTir Administration & Telemetry Web Dashboard SPA."""
    template_path = os.path.join("app", "templates", "dashboard.html")
    if not os.path.exists(template_path):
        return HTMLResponse(
            content="<h1>Critical Error: templates/dashboard.html not found!</h1>",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=status.HTTP_200_OK)
    except Exception as e:
        return HTMLResponse(
            content=f"<h1>Failed to load dashboard: {str(e)}</h1>",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@app.get("/health", status_code=status.HTTP_200_OK, tags=["General"])
async def health_check():
    """Monitoring healthcheck endpoint (Liveness & Readiness)."""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "uptime": "ok"
    }
