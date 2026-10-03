"""
Tests for Production Security Hardening (Phase 2)
"""
import os
import tempfile
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.vpn_router import router, get_vpn_engine, VPNEngine
from backend.vpn_sub_injector import VPNSubscriptionInjector


@pytest.fixture
def secured_app(monkeypatch):
    """ایجاد کلاینت با API Key فعال در متغیر محیطی"""
    monkeypatch.setenv("PASARGUARD_NODE_API_KEY", "super_secret_node_token_12345")
    monkeypatch.setenv("VPN_L2TP_PSK", "custom_production_psk_999")

    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        data_dir = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=data_dir)
        engine.upsert_mock_user("sec_user", "sec_pass", status="active", data_limit=1000000)

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_vpn_engine] = lambda: engine

        yield TestClient(app)


def test_node_api_key_unauthorized_when_missing_token(secured_app):
    """درخواست هوک نود بدون API Key باید کد 401 بدهد"""
    res = secured_app.post(
        "/api/vpn/auth",
        json={"username": "sec_user", "password": "sec_pass", "protocol": "openvpn"}
    )
    assert res.status_code == 401
    assert "unauthorized" in res.json().get("detail", "").lower()


def test_node_api_key_authorized_when_token_matches(secured_app):
    """درخواست هوک نود با توکن صحیح باید پذیرفته شود"""
    res = secured_app.post(
        "/api/vpn/auth",
        json={"username": "sec_user", "password": "sec_pass", "protocol": "openvpn"},
        headers={"Authorization": "Bearer super_secret_node_token_12345"}
    )
    assert res.status_code == 200
    assert res.json()["allowed"] is True


def test_configurable_l2tp_psk(monkeypatch):
    """بررسی اینکه PSK از متغیر محیطی خوانده می‌شود و دیگر مقدار هاردکد ثابت نیست"""
    monkeypatch.setenv("VPN_L2TP_PSK", "my_custom_production_secret_key")
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        engine = VPNEngine(data_dir=Path(temp_dir) / "vpn_data")
        engine.upsert_mock_user("alice", "pass123", group="VIP")
        engine.set_group_node_policy("VIP", ["DE-Node1"])

        injector = VPNSubscriptionInjector(engine=engine, base_url="https://vpn.example.com")
        sub = injector.generate_subscription_links("alice")
        assert len(sub["configs"]) == 1
        assert sub["configs"][0]["l2tp_credentials"]["psk"] == "my_custom_production_secret_key"
