"""
CREDTRACE V2 Routes Package
"""
from app.routes.auth import router as auth_router
from app.routes.portal import router as portal_router
from app.routes.simulator import router as simulator_router
from app.routes.investigator import router as investigator_router
from app.routes.reports import router as reports_router
from app.routes.ws import router as ws_router

__all__ = [
    "auth_router",
    "portal_router",
    "simulator_router",
    "investigator_router",
    "reports_router",
    "ws_router"
]
