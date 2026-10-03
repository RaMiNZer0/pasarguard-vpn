"""
PasarGuard Unified VPN Standalone Application Server
"""
import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.vpn_router import router, get_vpn_engine
from backend.vpn_engine import VPNEngine

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_PLUGIN_DIR = BASE_DIR / "plugin"
PREVIEW_HTML_FILE = BASE_DIR / "preview_panel.html"

app = FastAPI(
    title="PasarGuard Unified VPN Server",
    version="1.0.0",
    description="Modular VPN Extension (OpenVPN, IKEv2, L2TP) for PasarGuard",
)

# CORS Support for local browser testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static plugin assets
if STATIC_PLUGIN_DIR.exists():
    app.mount("/plugin", StaticFiles(directory=str(STATIC_PLUGIN_DIR)), name="plugin")

# Include the VPN router
app.include_router(router)


@app.on_event("startup")
def setup_default_data():
    """Initializes mock users and policies for instant local testing."""
    engine = get_vpn_engine()
    # Mock VIP user
    engine.upsert_mock_user(
        username="ali",
        password="password123",
        status="active",
        data_limit=50 * 1024 * 1024 * 1024,  # 50 GB
        used_traffic=5 * 1024 * 1024 * 1024,   # 5 GB
        expire=4102444800,
        group="VIP",
    )
    # Mock Standard user
    engine.upsert_mock_user(
        username="sara",
        password="secret456",
        status="active",
        data_limit=10 * 1024 * 1024 * 1024,  # 10 GB
        used_traffic=8 * 1024 * 1024 * 1024,   # 8 GB
        expire=4102444800,
        group="Standard",
    )
    # Mock Group Policies
    engine.set_group_node_policy("VIP", ["DE-Hetzner1", "TR-Teknosos1", "US-AWS1"])
    engine.set_group_node_policy("Standard", ["DE-Hetzner1"])


@app.get("/", response_class=HTMLResponse)
def serve_preview_dashboard():
    """Serves the live interactive PasarGuard VPN preview dashboard."""
    if PREVIEW_HTML_FILE.exists():
        return FileResponse(str(PREVIEW_HTML_FILE), media_type="text/html")
    return HTMLResponse("<h1>PasarGuard VPN Server Running</h1><p><a href='/docs'>View Swagger API Docs</a></p>")


@app.get("/healthz")
def healthcheck():
    return {"status": "ok", "app": "pasarguard-vpn", "version": "1.0.0"}
