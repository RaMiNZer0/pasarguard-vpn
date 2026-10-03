"""
Phase 6: End-to-End (E2E) Integration Test Suite
Validates the complete lifecycle:
Group Configuration -> User Provisioning -> Real-time Node Auth ->
Traffic Accounting -> Over-quota Kill Switch -> Subscription Payload Generation.
"""
import pytest
import tempfile
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.vpn_engine import VPNEngine, VPNProtocol
from backend.vpn_router import router, get_vpn_engine
from backend.vpn_sub_injector import VPNSubscriptionInjector
from node_worker.pg_vpn_hook import (
    handle_openvpn_auth_cli,
    handle_openvpn_disconnect_cli,
    handle_l2tp_ip_down_cli,
)


@pytest.fixture
def e2e_system():
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        data_dir = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=data_dir)

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_vpn_engine] = lambda: engine

        client = TestClient(app)
        yield {
            "engine": engine,
            "client": client,
            "temp_dir": temp_dir,
        }


def test_full_e2e_lifecycle(e2e_system):
    """
    تست سناریوی کامل واقعی از ورود کاربر تا مصرف حجم و قطع خودکار
    """
    engine: VPNEngine = e2e_system["engine"]
    client: TestClient = e2e_system["client"]
    temp_dir = e2e_system["temp_dir"]

    # گام ۱: مدیر سیستم دسترسی گروه VIP را به نودهای آلمان و ترکیه تنظیم می‌کند
    res_policy = client.post(
        "/api/vpn/groups/policy",
        json={"group_name": "VIP", "allowed_nodes": ["DE-Hetzner1", "TR-Teknosos1"]},
    )
    assert res_policy.status_code == 200

    # گام ۲: کاربر جدید با سهمیه 10 گیگابایت ثبت می‌شود
    engine.upsert_mock_user(
        username="john_doe",
        password="supersecretpassword",
        status="active",
        data_limit=10 * 1024 * 1024 * 1024,  # 10 GB
        used_traffic=0,
        expire=4102444800,
        group="VIP",
    )

    # گام ۳: کاربر از طریق OpenVPN به نود متصل می‌شود (اجرای هوک سیستم‌عامل روی نود)
    auth_file = Path(temp_dir) / "auth_openvpn.txt"
    auth_file.write_text("john_doe\nsupersecretpassword\n", encoding="utf-8")
    auth_exit_code = handle_openvpn_auth_cli(str(auth_file), engine=engine)
    assert auth_exit_code == 0  # اجازه اتصال صادر شد

    # گام ۴: کاربر ۴ گیگابایت دانلود می‌کند و قطع می‌شود
    disconnect_env = {
        "username": "john_doe",
        "bytes_received": str(1 * 1024 * 1024 * 1024),  # 1 GB
        "bytes_sent": str(3 * 1024 * 1024 * 1024),      # 3 GB
        "time_duration": "1800",
    }
    report1 = handle_openvpn_disconnect_cli(env=disconnect_env, engine=engine)
    assert report1["success"] is True
    assert report1["consumed_bytes"] == 4 * 1024 * 1024 * 1024
    assert report1["used_traffic"] == 4 * 1024 * 1024 * 1024
    assert report1["should_kill"] is False  # هنوز ۶ گیگ باقیمانده دارد

    # گام ۵: نشست دوم - کاربر ۷ گیگابایت دیگر دانلود می‌کند (مجموع ۱۱ گیگ > سهمیه ۱۰ گیگ)
    disconnect_env2 = {
        "username": "john_doe",
        "bytes_received": str(2 * 1024 * 1024 * 1024),
        "bytes_sent": str(5 * 1024 * 1024 * 1024),
    }
    report2 = handle_openvpn_disconnect_cli(env=disconnect_env2, engine=engine)
    assert report2["success"] is True
    assert report2["should_kill"] is True  # کیل‌سوئیچ فعال شد!
    assert report2["reason"] == "Quota exceeded"

    # گام ۶: کاربر تلاش می‌کند مجدداً وصل شود ⬅️ سیستم بلافاصله رد می‌کند
    auth_exit_code_after_limit = handle_openvpn_auth_cli(str(auth_file), engine=engine)
    assert auth_exit_code_after_limit == 1  # رد اتصال به دلیل اتمام سهمیه

    # گام ۷: کلاینت وارد صفحه سابسکریپشن می‌شود و لینک‌های نودهای مجاز گروه خود را بررسی می‌کند
    res_sub = client.get("/api/vpn/subscription/john_doe")
    assert res_sub.status_code == 200
    sub_data = res_sub.json()
    assert sub_data["username"] == "john_doe"
    assert sub_data["group"] == "VIP"
    assert len(sub_data["configs"]) == 2  # DE و TR

    # دانلود کانفیگ .ovpn برای نود آلمان
    res_ovpn = client.get("/api/vpn/client/ovpn?node=DE-Hetzner1&username=john_doe")
    assert res_ovpn.status_code == 200
    assert "remote de-hetzner1.vpn.example.com 1194" in res_ovpn.text
