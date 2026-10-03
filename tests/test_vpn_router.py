"""
Tests for PasarGuard Unified VPN FastAPI Router (/api/vpn/*)
"""
import pytest
import tempfile
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.vpn_router import router, get_vpn_engine, VPNEngine


@pytest.fixture
def vpn_client(monkeypatch):
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        data_dir = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=data_dir)
        engine.upsert_mock_user(
            username="test_user",
            password="pass123456",
            status="active",
            data_limit=5 * 1024 * 1024 * 1024,  # 5 GB
            used_traffic=1 * 1024 * 1024 * 1024,  # 1 GB
            expire=4102444800,
            group="VIP",
        )
        engine.set_group_node_policy("VIP", ["DE-Hetzner1", "TR-Teknosos1"])

        app = FastAPI()
        app.include_router(router)
        # Override dependency
        app.dependency_overrides[get_vpn_engine] = lambda: engine

        yield TestClient(app)


def test_vpn_auth_endpoint_success(vpn_client):
    """تست اندپوینت احراز هویت با موفقیت"""
    res = vpn_client.post(
        "/api/vpn/auth",
        json={"username": "test_user", "password": "pass123456", "protocol": "openvpn"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is True
    assert data["username"] == "test_user"
    assert data["remaining_bytes"] == 4 * 1024 * 1024 * 1024


def test_vpn_auth_endpoint_fail(vpn_client):
    """تست اندپوینت احراز هویت با رمز اشتباه"""
    res = vpn_client.post(
        "/api/vpn/auth",
        json={"username": "test_user", "password": "wrongpass", "protocol": "ikev2"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is False
    assert data["reason"] == "Invalid credentials"


def test_vpn_report_usage_endpoint(vpn_client):
    """تست گزارش مصرف و کسر ترافیک"""
    res = vpn_client.post(
        "/api/vpn/report-usage",
        json={
            "username": "test_user",
            "bytes_in": 200 * 1024 * 1024,
            "bytes_out": 300 * 1024 * 1024,
            "protocol": "openvpn",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["should_kill"] is False
    assert data["consumed_bytes"] == 500 * 1024 * 1024


def test_vpn_status_endpoint(vpn_client):
    """تست وضعیت سرویس و نودها"""
    res = vpn_client.get("/api/vpn/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "active"
    assert "supported_protocols" in data
    assert "openvpn" in data["supported_protocols"]
    assert "ikev2" in data["supported_protocols"]
    assert "l2tp" in data["supported_protocols"]


def test_vpn_client_ovpn_download(vpn_client):
    """تست تولید و دانلود فایل کانفیگ .ovpn"""
    res = vpn_client.get("/api/vpn/client/ovpn?node=DE-Hetzner1&username=test_user")
    assert res.status_code == 200
    assert "client" in res.text
    assert "auth-user-pass" in res.text
    assert res.headers["content-type"].startswith("application/x-openvpn-profile")


def test_vpn_client_mobileconfig_download(vpn_client):
    """تست تولید و دانلود پروفایل .mobileconfig آیفون"""
    res = vpn_client.get("/api/vpn/client/mobileconfig?node=DE-Hetzner1&username=test_user")
    assert res.status_code == 200
    assert "com.apple.vpn.managed" in res.text
    assert "test_user" in res.text
    assert res.headers["content-type"].startswith("application/x-apple-aspen-config")


def test_vpn_group_policy_endpoint(vpn_client):
    """تست مدیریت دسترسی گروه‌ها به نودها"""
    # تنظیم سیاست جدید برای گروه Standard
    res = vpn_client.post(
        "/api/vpn/groups/policy",
        json={"group_name": "Standard", "allowed_nodes": ["TR-Teknosos1"]},
    )
    assert res.status_code == 200
    assert res.json()["success"] is True

    # خواندن وضعیت
    res_get = vpn_client.get("/api/vpn/groups/policies")
    assert res_get.status_code == 200
    policies = res_get.json()
    assert "Standard" in policies
    assert "TR-Teknosos1" in policies["Standard"]
