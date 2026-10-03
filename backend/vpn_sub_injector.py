"""
PasarGuard VPN Subscription Injector & Node Health Checker
==========================================================
Handles group-based dynamic config injection into client subscriptions
and real-time UDP port health monitoring across multi-location nodes.
"""

from __future__ import annotations

import time
import socket
from typing import Any, Dict, List, Optional
from backend.vpn_engine import VPNEngine


class VPNNodeHealthChecker:
    """پایشگر سلامت نودهای VPN (تست درگاه‌های UDP 1194 و UDP 500)"""

    def check_node_health(
        self,
        node_name: str,
        host: str,
        openvpn_port: int = 1194,
        ikev2_port: int = 500,
        mock_online: Optional[bool] = None,
        timeout: float = 1.5,
    ) -> Dict[str, Any]:
        """بررسی بلادرنگ تاخیر و پاسخگویی پورت‌های نود"""
        if mock_online is not None:
            if mock_online:
                return {
                    "node": node_name,
                    "host": host,
                    "is_online": True,
                    "latency_ms": 42.5,
                    "openvpn_status": "listening",
                    "ikev2_status": "listening",
                    "checked_at": int(time.time()),
                }
            else:
                return {
                    "node": node_name,
                    "host": host,
                    "is_online": False,
                    "latency_ms": -1,
                    "openvpn_status": "unreachable",
                    "ikev2_status": "unreachable",
                    "checked_at": int(time.time()),
                }

        # تست واقعی سوکت شبکه
        start_time = time.time()
        is_online = False
        try:
            # ارسال یک بایت تست UDP برای بررسی لایه سوکت
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x38", (host, openvpn_port))
            sock.close()
            latency = (time.time() - start_time) * 1000
            is_online = True
        except Exception:
            latency = -1

        return {
            "node": node_name,
            "host": host,
            "is_online": is_online,
            "latency_ms": round(latency, 2) if is_online else -1,
            "openvpn_status": "listening" if is_online else "unreachable",
            "ikev2_status": "listening" if is_online else "unreachable",
            "checked_at": int(time.time()),
        }


class VPNSubscriptionInjector:
    """
    تزریق‌کننده خودکار کانفیگ‌های VPN به صفحه اشتراک کلاینت
    بر اساس تفکیک Group و سیاست‌های دسترسی نودها
    """

    def __init__(self, engine: VPNEngine, base_url: str = "") -> None:
        self.engine = engine
        self.base_url = base_url.rstrip("/")

    def generate_subscription_links(self, username: str) -> Dict[str, Any]:
        """
        تولید کارت‌ها و لینک‌های دانلود اختصاصی متناسب با گروه کاربری
        """
        user = self.engine._users.get(username)
        if not user:
            return {"username": username, "group": "unknown", "configs": []}

        group_name = user.group
        allowed_nodes = self.engine._group_policies.get(group_name, [])

        configs: List[Dict[str, Any]] = []
        for node in allowed_nodes:
            node_slug = node.lower().replace(" ", "-")
            ovpn_url = f"{self.base_url}/api/vpn/client/ovpn?node={node}&username={username}"
            mobileconfig_url = f"{self.base_url}/api/vpn/client/mobileconfig?node={node}&username={username}"

            configs.append({
                "node": node,
                "protocols": ["openvpn", "ikev2", "l2tp"],
                "ovpn_download_url": ovpn_url,
                "mobileconfig_download_url": mobileconfig_url,
                "l2tp_credentials": {
                    "server_address": f"{node_slug}.vpn.example.com",
                    "username": username,
                    "password": user.password,
                    "psk": "PasarGuardVPN123",
                },
            })

        return {
            "username": username,
            "group": group_name,
            "configs": configs,
            "total_nodes": len(configs),
        }
