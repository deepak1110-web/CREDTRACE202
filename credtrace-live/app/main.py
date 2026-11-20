"""
CREDTRACE V2 - Master FastAPI Application Entrypoint
Advanced Credential Intelligence, Incident Investigation & Digital Forensics Platform
CRIMEATHON'26 | Case CR-26-047
"""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from app.config import settings, BASE_DIR
from app.database import init_db
from app.routes import (
    auth_router,
    portal_router,
    simulator_router,
    investigator_router,
    reports_router,
    ws_router
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database & Seed Baseline Records
    init_db()
    yield
    # Shutdown

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced Credential Intelligence, Incident Investigation & Digital Forensics Platform",
    lifespan=lifespan
)

# Cross-Origin Resource Sharing (CORS) Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth_router)
app.include_router(portal_router)
app.include_router(simulator_router)
app.include_router(investigator_router)
app.include_router(reports_router)
app.include_router(ws_router)

# Mount Static Assets
static_dir = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Front-End Page Routes
@app.get("/", response_class=FileResponse)
async def serve_index():
    return FileResponse(static_dir / "index.html")

@app.get("/portal", response_class=FileResponse)
async def serve_portal():
    return FileResponse(static_dir / "portal.html")

@app.get("/simulator", response_class=FileResponse)
async def serve_simulator():
    return FileResponse(static_dir / "simulator.html")

@app.get("/investigator", response_class=FileResponse)
async def serve_investigator():
    return FileResponse(static_dir / "investigator.html")

# System Health & Readiness Probes
@app.get("/health")
@app.get("/api/status")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "case_id": settings.CASE_ID,
        "company": settings.COMPANY_NAME,
        "environment": settings.APP_ENV
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
