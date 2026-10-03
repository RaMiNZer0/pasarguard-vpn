"""
Multi-Node Distributed Deployment & Quota Enforcement Simulation Test
Verifies multi-node behavior across disparate servers (Germany, Turkey, USA)
"""
import tempfile
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.vpn_router import router, get_vpn_engine, VPNEngine


@pytest.fixture
def multi_node_cluster():
    """ایجاد کلاستر شبیه‌سازی‌شده پنل مستر و نودهای توزیع‌شده"""
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        engine = VPNEngine(data_dir=Path(temp_dir) / "vpn_data")

        # ثبت کاربر VIP با سهمیه 10 گیگابایت
        engine.upsert_mock_user(
            username="vip_user",
            password="pass_vip_123",
            status="active",
            data_limit=10 * 1024 * 1024 * 1024, # 10 GB
            used_traffic=0,
            group="VIP",
        )

        # ثبت کاربر Standard با سهمیه 5 گیگابایت
        engine.upsert_mock_user(
            username="std_user",
            password="pass_std_456",
            status="active",
            data_limit=5 * 1024 * 1024 * 1024, # 5 GB
            used_traffic=0,
            group="Standard",
        )

        # سیاست دسترسی گروه‌ها به نودها
        # VIP: آلمان، ترکیه، آمریکا
        # Standard: فقط آلمان
        engine.set_group_node_policy("VIP", ["DE-Hetzner1", "TR-Teknosos1", "US-AWS1"])
        engine.set_group_node_policy("Standard", ["DE-Hetzner1"])

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_vpn_engine] = lambda: engine

        yield {
            "client": TestClient(app),
            "engine": engine,
        }


def test_multi_node_distributed_auth_and_routing(multi_node_cluster):
    """تست اعتبارسنجی احراز هویت متمرکز بر اساس نودهای درخواستی"""
    client: TestClient = multi_node_cluster["client"]

    # ۱. کاربر VIP اجازه اتصال به تمام نودها را دارد
    for node in ["DE-Hetzner1", "TR-Teknosos1", "US-AWS1"]:
        res = client.post("/api/vpn/auth", json={
            "username": "vip_user",
            "password": "pass_vip_123",
            "protocol": "openvpn",
            "node": node,
        })
        assert res.status_code == 200
        assert res.json()["allowed"] is True

    # ۲. کاربر Standard فقط به نود آلمان اجازه اتصال دارد
    res_de = client.post("/api/vpn/auth", json={
        "username": "std_user",
        "password": "pass_std_456",
        "protocol": "openvpn",
        "node": "DE-Hetzner1",
    })
    assert res_de.status_code == 200
    assert res_de.json()["allowed"] is True

    # اما اتصال کاربر Standard به نود ترکیه یا آمریکا باید با خطای دسترسی رد شود
    res_tr = client.post("/api/vpn/auth", json={
        "username": "std_user",
        "password": "pass_std_456",
        "protocol": "openvpn",
        "node": "TR-Teknosos1",
    })
    assert res_tr.status_code == 200
    assert res_tr.json()["allowed"] is False
    assert "Access denied" in res_tr.json()["reason"]


def test_multi_node_cross_server_quota_aggregation(multi_node_cluster):
    """تست تجمیع مصرف ترافیک روی چند نود و قطع فوری هنگام سقف حجم مشترک"""
    client: TestClient = multi_node_cluster["client"]

    # کاربر VIP روی نود آلمان متصل می‌شود و 6 گیگابایت مصرف می‌کند
    res_usage_de = client.post("/api/vpn/report-usage", json={
        "username": "vip_user",
        "bytes_in": 3 * 1024 * 1024 * 1024,
        "bytes_out": 3 * 1024 * 1024 * 1024,
        "protocol": "openvpn",
        "node": "DE-Hetzner1",
    })
    assert res_usage_de.status_code == 200
    assert res_usage_de.json()["used_traffic"] == 6 * 1024 * 1024 * 1024
    assert res_usage_de.json()["should_kill"] is False

    # کاربر سپس روی نود ترکیه متصل می‌شود و 5 گیگابایت دیگر مصرف می‌کند (مجموع 11 گیگ > سقف 10 گیگ)
    res_usage_tr = client.post("/api/vpn/report-usage", json={
        "username": "vip_user",
        "bytes_in": 2 * 1024 * 1024 * 1024,
        "bytes_out": 3 * 1024 * 1024 * 1024,
        "protocol": "ikev2",
        "node": "TR-Teknosos1",
    })
    assert res_usage_tr.status_code == 200
    assert res_usage_tr.json()["used_traffic"] == 11 * 1024 * 1024 * 1024
    assert res_usage_tr.json()["should_kill"] is True  # نود ترکیه بلافاصله سشن را کیل می‌کند!

    # اکنون اگر کاربر حتی به نود آمریکا تلاش کند وصل شود، به دلیل اتمام سهمیه در کل کلاستر رد می‌شود
    res_auth_us = client.post("/api/vpn/auth", json={
        "username": "vip_user",
        "password": "pass_vip_123",
        "protocol": "openvpn",
        "node": "US-AWS1",
    })
    assert res_auth_us.status_code == 200
    assert res_auth_us.json()["allowed"] is False
    assert "quota" in res_auth_us.json()["reason"].lower()
