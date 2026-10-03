"""
Tests for Phase 4: VPN Node Health Checks and Subscription Group Injection
"""
import pytest
import tempfile
from pathlib import Path
from backend.vpn_engine import VPNEngine
from backend.vpn_sub_injector import (
    VPNNodeHealthChecker,
    VPNSubscriptionInjector,
)


@pytest.fixture
def phase4_env():
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        data_dir = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=data_dir)

        # Seed users in different groups
        engine.upsert_mock_user(
            username="vip_user",
            password="pass_vip_123",
            status="active",
            data_limit=50 * 1024 * 1024 * 1024,
            group="VIP",
        )
        engine.upsert_mock_user(
            username="de_only_user",
            password="pass_de_123",
            status="active",
            data_limit=20 * 1024 * 1024 * 1024,
            group="Germany-Only",
        )

        # Define policies
        engine.set_group_node_policy("VIP", ["DE-Hetzner1", "TR-Teknosos1", "US-AWS1"])
        engine.set_group_node_policy("Germany-Only", ["DE-Hetzner1"])

        yield engine


def test_vpn_node_health_check_simulation():
    """تست ارزیابی سلامت پورت‌های نود (UDP 1194 و UDP 500)"""
    checker = VPNNodeHealthChecker()
    # Mocking node check
    status = checker.check_node_health(
        node_name="DE-Hetzner1",
        host="127.0.0.1",
        openvpn_port=1194,
        ikev2_port=500,
        mock_online=True,
    )
    assert status["node"] == "DE-Hetzner1"
    assert status["is_online"] is True
    assert status["openvpn_status"] == "listening"
    assert status["ikev2_status"] == "listening"
    assert status["latency_ms"] >= 0


def test_vpn_node_health_offline_simulation():
    """تست نود آفلاین"""
    checker = VPNNodeHealthChecker()
    status = checker.check_node_health(
        node_name="Offline-Node",
        host="192.0.2.1",
        openvpn_port=1194,
        ikev2_port=500,
        mock_online=False,
    )
    assert status["is_online"] is False
    assert status["openvpn_status"] == "unreachable"


def test_subscription_injection_vip_user(phase4_env):
    """کاربر VIP باید کانفیگ‌های هر ۳ نود را در سابسکریپشن دریافت کند"""
    injector = VPNSubscriptionInjector(engine=phase4_env, base_url="https://panel.example.com")
    sub_data = injector.generate_subscription_links(username="vip_user")

    assert sub_data["username"] == "vip_user"
    assert sub_data["group"] == "VIP"
    assert len(sub_data["configs"]) == 3  # DE, TR, US

    node_names = [c["node"] for c in sub_data["configs"]]
    assert "DE-Hetzner1" in node_names
    assert "TR-Teknosos1" in node_names
    assert "US-AWS1" in node_names

    # بررسی وجود لینک‌های دانلود
    first_cfg = sub_data["configs"][0]
    assert "ovpn_download_url" in first_cfg
    assert "mobileconfig_download_url" in first_cfg
    assert "l2tp_credentials" in first_cfg


def test_subscription_injection_restricted_user(phase4_env):
    """کاربر آلمان فقط باید کانفیگ آلمان را دریافت کند و نودهای ترکیه/آمریکا را نبیند"""
    injector = VPNSubscriptionInjector(engine=phase4_env, base_url="https://panel.example.com")
    sub_data = injector.generate_subscription_links(username="de_only_user")

    assert sub_data["username"] == "de_only_user"
    assert sub_data["group"] == "Germany-Only"
    assert len(sub_data["configs"]) == 1  # Only DE-Hetzner1
    assert sub_data["configs"][0]["node"] == "DE-Hetzner1"
