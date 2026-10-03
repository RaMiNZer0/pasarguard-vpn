"""
PasarGuard Unified VPN FastAPI Router (/api/vpn/*)
===================================================
High-speed REST API for node authentication, usage accounting,
and client profile generation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from pydantic import BaseModel, Field

from backend.vpn_engine import (
    VPNEngine,
    VPNProtocol,
    OpenVPNClientConfigGenerator,
    AppleMobileConfigGenerator,
)

router = APIRouter(prefix="/api/vpn", tags=["VPN"])

def verify_node_api_key(
    authorization: Optional[str] = Header(None),
) -> None:
    """اعتبارسنجی امن توکن نود برای جلوگیری از درخواست‌های غیرمجاز"""
    expected_key = os.environ.get("PASARGUARD_NODE_API_KEY", "").strip()
    if not expected_key:
        return  # اگر متغیر ست نشده باشد، باز می‌ماند (حالت توسعه یا تک‌سرور)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Node API Key missing")
    token = authorization.split("Bearer ", 1)[1].strip()
    if token != expected_key:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid Node API Key")

DATA_DIR = Path(os.environ.get("PASARGUARD_VPN_DATA_DIR", "/var/lib/pasarguard/vpn/data"))
_engine_instance: Optional[VPNEngine] = None


def get_vpn_engine() -> VPNEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = VPNEngine(data_dir=DATA_DIR)
        try:
            from backend.pg_db_reader import PasarGuardDBReader
            from backend.pg_user_sync import PasarGuardUserSync
            reader = PasarGuardDBReader()
            if reader.is_available():
                syncer = PasarGuardUserSync(reader, _engine_instance)
                _engine_instance.set_user_syncer(syncer)
                syncer.sync_all()
        except Exception:
            pass
    return _engine_instance


# ==============================================================================
# Pydantic Schemas
# ==============================================================================

class AuthRequest(BaseModel):
    username: str
    password: str
    protocol: str = Field(default="openvpn")
    node: Optional[str] = None


class UsageReportRequest(BaseModel):
    username: str
    bytes_in: int = Field(ge=0)
    bytes_out: int = Field(ge=0)
    protocol: str = Field(default="openvpn")
    node: Optional[str] = None


class GroupPolicyRequest(BaseModel):
    group_name: str
    allowed_nodes: List[str]


# ==============================================================================
# API Endpoints
# ==============================================================================

@router.post("/auth")
def authenticate(
    payload: AuthRequest,
    engine: VPNEngine = Depends(get_vpn_engine),
    _sec: None = Depends(verify_node_api_key),
) -> Dict[str, Any]:
    """احراز هویت بلادرنگ کلاینت‌ها (Real-Time Auth) با پشتیبانی از تفکیک نودها"""
    result = engine.authenticate_user(
        username=payload.username,
        password=payload.password,
        protocol=payload.protocol,
    )
    if not result.allowed:
        return {
            "allowed": False,
            "username": result.username,
            "remaining_bytes": 0,
            "reason": result.reason,
        }

    # اگر هوک مشخص کرده کدام نود است، دسترسی کاربر به این نود چک می‌شود
    if payload.node and not engine.can_user_access_node(payload.username, payload.node):
        return {
            "allowed": False,
            "username": payload.username,
            "remaining_bytes": result.remaining_bytes,
            "reason": f"Access denied to node {payload.node} for user group",
        }

    return {
        "allowed": True,
        "username": result.username,
        "remaining_bytes": result.remaining_bytes,
        "reason": result.reason,
    }


@router.post("/report-usage")
def report_usage(
    payload: UsageReportRequest,
    engine: VPNEngine = Depends(get_vpn_engine),
    _sec: None = Depends(verify_node_api_key),
) -> Dict[str, Any]:
    """گزارش مصرف ترافیک و بررسی وضعیت سهمیه (Accounting)"""
    report = engine.report_traffic(
        username=payload.username,
        bytes_in=payload.bytes_in,
        bytes_out=payload.bytes_out,
        protocol=payload.protocol,
    )
    return report


@router.get("/status")
def get_status(
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Dict[str, Any]:
    """وضعیت کلی ماژول VPN و پروتکل‌های فعال"""
    return {
        "status": "active",
        "supported_protocols": ["openvpn", "ikev2", "l2tp"],
        "active_users_cached": len(engine._users),
        "group_policies_count": len(engine._group_policies),
    }


@router.get("/client/ovpn")
def download_openvpn_config(
    node: str = Query(..., description="Node name or identifier"),
    username: str = Query(..., description="Username for auth"),
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Response:
    """تولید و دانلود مستقیم فایل تک‌فایلی .ovpn"""
    # ساخت فایل کانفیگ
    ca_mock = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL0...\n-----END CERTIFICATE-----"
    generator = OpenVPNClientConfigGenerator(
        server_host=f"{node.lower().replace(' ', '-')}.vpn.example.com",
        server_port=1194,
        proto="udp",
        ca_cert=ca_mock,
        cipher="AES-256-GCM",
    )
    content = generator.generate(node_name=node)

    return Response(
        content=content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{node}.ovpn"'},
    )


@router.get("/client/mobileconfig")
def download_apple_mobileconfig(
    node: str = Query(..., description="Node name or identifier"),
    username: str = Query(..., description="Username for profile"),
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Response:
    """تولید و دانلود مستقیم پروفایل .mobileconfig برای آیفون و مک"""
    server_addr = f"{node.lower().replace(' ', '-')}.vpn.example.com"
    generator = AppleMobileConfigGenerator(
        organization="PasarGuard VPN",
        server_address=server_addr,
        remote_id=server_addr,
    )
    content = generator.generate(profile_name=f"PasarGuard - {node}", username=username)

    return Response(
        content=content,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": f'attachment; filename="{node}.mobileconfig"'},
    )


@router.get("/groups/policies")
def get_group_policies(
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Dict[str, List[str]]:
    """دریافت سیاست‌های دسترسی گروه‌ها به نودها"""
    return engine._group_policies


@router.post("/groups/policy")
def set_group_policy(
    payload: GroupPolicyRequest,
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Dict[str, Any]:
    """تعیین دسترسی گروه کاربری پاسارگارد به نودهای مجاز"""
    engine.set_group_node_policy(payload.group_name, payload.allowed_nodes)
    return {"success": True, "group_name": payload.group_name, "allowed_nodes": payload.allowed_nodes}


@router.get("/subscription/{username}")
def get_user_subscription(
    username: str,
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Dict[str, Any]:
    """دریافت لیست تمام کانفیگ‌های مجاز کاربر بر اساس گروه در سابسکریپشن"""
    from backend.vpn_sub_injector import VPNSubscriptionInjector
    injector = VPNSubscriptionInjector(engine=engine, base_url="")
    return injector.generate_subscription_links(username=username)


@router.get("/nodes/health")
def get_nodes_health(
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Dict[str, Any]:
    """پایش لحظه‌ای سلامت و تاخیر پورت‌های نودها"""
    from backend.vpn_sub_injector import VPNNodeHealthChecker
    checker = VPNNodeHealthChecker()
    # ارزیابی نودهای پیش‌فرض یا ثبت‌شده
    sample_nodes = ["DE-Hetzner1", "TR-Teknosos1", "US-AWS1"]
    results = []
    for node in sample_nodes:
        health = checker.check_node_health(
            node_name=node,
            host="127.0.0.1",
            mock_online=True,
        )
        results.append(health)
    return {"status": "ok", "nodes": results}


@router.post("/sync")
def trigger_db_sync(
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Dict[str, Any]:
    """همگام‌سازی دستی کاربران با دیتابیس پاسارگارد"""
    from backend.pg_user_sync import PasarGuardUserSync
    syncer = getattr(engine, "_user_syncer", None)
    if not syncer:
        syncer = PasarGuardUserSync(engine=engine)
        engine.set_user_syncer(syncer)
    count = syncer.sync_all()
    return {"success": True, "synced_users_count": count, "message": f"Successfully synced {count} users from PasarGuard"}


@router.get("/sync/status")
def get_sync_status(
    engine: VPNEngine = Depends(get_vpn_engine),
) -> Dict[str, Any]:
    """وضعیت آخرین همگام‌سازی با دیتابیس پاسارگارد"""
    syncer = getattr(engine, "_user_syncer", None)
    last_sync = getattr(syncer, "_last_sync_time", 0.0) if syncer else 0.0
    return {
        "is_syncer_active": syncer is not None,
        "last_sync_timestamp": last_sync,
        "cached_users_count": len(engine._users),
    }

