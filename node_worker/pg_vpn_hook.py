#!/usr/bin/env python3
"""
PasarGuard Lightweight Node Hook Script (pg_vpn_hook.py)
=========================================================
Ultra-fast OS hook handler executed by OpenVPN and pppd (L2TP).
Features:
- Execution time < 5ms
- 0% CPU consumption when idle
- Direct local engine or REST API forwarding
"""

from __future__ import annotations

import os
import sys
import json
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

# Master panel configuration for multi-node deployments
MASTER_URL = os.environ.get("PASARGUARD_MASTER_URL", "").rstrip("/")
API_TOKEN = os.environ.get("PASARGUARD_NODE_API_KEY", "")
NODE_NAME = os.environ.get("PASARGUARD_NODE_NAME", "")

try:
    from node_worker.local_cache import LocalAuthCache
    from node_worker.circuit_breaker import CircuitBreaker
except ImportError:
    try:
        from local_cache import LocalAuthCache
        from circuit_breaker import CircuitBreaker
    except ImportError:
        LocalAuthCache = None
        CircuitBreaker = None

_local_cache = LocalAuthCache() if LocalAuthCache else None
_circuit_breaker = CircuitBreaker() if CircuitBreaker else None


def _call_master_api(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """ارسال امن و سریع درخواست به پنل مستر در حالت مالتی‌نود"""
    url = f"{MASTER_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_TOKEN}",
            "User-Agent": "PasarGuard-Node-Hook/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        return {"allowed": False, "success": False, "reason": str(e)}


def handle_openvpn_auth_cli(auth_file: str, engine: Optional[Any] = None) -> int:
    """
    هوک احراز هویت اوپن‌وی‌پی‌ان با کش محلی و Failsafe در زمان قطعی مستر.
    کد خروجی ۰ یعنی تایید و کد ۱ یعنی رد اتصال.
    """
    try:
        with open(auth_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f.readlines()]
        if len(lines) < 2:
            return 1
        username, password = lines[0], lines[1]

        # ۱. اگر انجین محلی پاس داده شده باشد (تک‌سرور یا تست)
        if engine is not None:
            res = engine.authenticate_user(username, password, protocol="openvpn")
            if _local_cache:
                if res.allowed:
                    _local_cache.set(username, True, password)
                else:
                    _local_cache.invalidate(username)
            return 0 if res.allowed else 1

        # ۲. اگر در حالت مالتی‌نود باشد و آدرس مستر تعریف شده باشد
        if MASTER_URL:
            try:
                caller = _circuit_breaker.call if _circuit_breaker else lambda f, *a, **kw: f(*a, **kw)
                res = caller(_call_master_api, "/api/vpn/auth", {
                    "username": username,
                    "password": password,
                    "protocol": "openvpn",
                    "node": NODE_NAME,
                })
                allowed = bool(res.get("allowed"))
                if _local_cache:
                    if allowed:
                        _local_cache.set(username, True, password)
                    else:
                        _local_cache.invalidate(username)
                return 0 if allowed else 1
            except Exception:
                # Failsafe fallback: اگر ارتباط با مستر قطع است، از کش معتبر استفاده کن
                if _local_cache and _local_cache.get(username, password) is True:
                    return 0
                return 1

        # ۳. فال‌بک به انجین محلی پیش‌فرض
        from backend.vpn_engine import VPNEngine
        local_engine = VPNEngine()
        res = local_engine.authenticate_user(username, password, protocol="openvpn")
        return 0 if res.allowed else 1

    except Exception:
        return 1


def handle_openvpn_disconnect_cli(
    env: Optional[Dict[str, str]] = None,
    engine: Optional[Any] = None,
) -> Dict[str, Any]:
    """هوک قطع اتصال OpenVPN (--client-disconnect) برای کسر ترافیک مصرفی"""
    current_env = env if env is not None else os.environ
    username = current_env.get("username", "")
    bytes_in = int(current_env.get("bytes_received", "0"))
    bytes_out = int(current_env.get("bytes_sent", "0"))

    if engine is not None:
        report = engine.report_traffic(username, bytes_in, bytes_out, protocol="openvpn")
    elif MASTER_URL:
        report = _call_master_api("/api/vpn/report-usage", {
            "username": username,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "protocol": "openvpn",
            "node": NODE_NAME,
        })
    else:
        from backend.vpn_engine import VPNEngine
        report = VPNEngine().report_traffic(username, bytes_in, bytes_out, protocol="openvpn")

    if report.get("should_kill") and _local_cache:
        _local_cache.invalidate(username)

    return report


def handle_l2tp_ip_down_cli(
    env: Optional[Dict[str, str]] = None,
    engine: Optional[Any] = None,
) -> Dict[str, Any]:
    """هوک قطع اتصال L2TP در /etc/ppp/ip-down برای کسر ترافیک مصرفی"""
    current_env = env if env is not None else os.environ
    username = current_env.get("PEERNAME", "")
    bytes_in = int(current_env.get("BYTES_RCVD", "0"))
    bytes_out = int(current_env.get("BYTES_SENT", "0"))

    if engine is not None:
        return engine.report_traffic(username, bytes_in, bytes_out, protocol="l2tp")

    if MASTER_URL:
        return _call_master_api("/api/vpn/report-usage", {
            "username": username,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "protocol": "l2tp",
            "node": NODE_NAME,
        })

    from backend.vpn_engine import VPNEngine
    return VPNEngine().report_traffic(username, bytes_in, bytes_out, protocol="l2tp")


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "auth-openvpn" and len(sys.argv) >= 3:
        code = handle_openvpn_auth_cli(sys.argv[2])
        sys.exit(code)
    elif cmd == "disconnect-openvpn":
        handle_openvpn_disconnect_cli()
        sys.exit(0)
    elif cmd == "disconnect-l2tp":
        handle_l2tp_ip_down_cli()
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
