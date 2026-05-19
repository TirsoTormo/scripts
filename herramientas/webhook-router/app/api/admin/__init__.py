from fastapi import APIRouter
from app.api.admin.stats import router as stats_router
from app.api.admin.config import router as config_router
from app.api.admin.nodes import router as nodes_router

router = APIRouter(tags=["Console Administration"])

# Include the modular subrouters
router.include_router(stats_router)
router.include_router(config_router)
router.include_router(nodes_router)

__all__ = ["router"]
