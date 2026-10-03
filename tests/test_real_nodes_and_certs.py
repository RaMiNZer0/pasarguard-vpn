import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.vpn_router import router, get_vpn_engine, VPNEngine
from backend.vpn_engine import AppleMobileConfigGenerator, OpenVPNClientConfigGenerator
from backend.pg_db_reader import PasarGuardDBReader
from backend.vpn_sub_injector import VPNSubscriptionInjector

def test_apple_mobileconfig_embedded_ca_and_password():
    fake_ca = "-----BEGIN CERTIFICATE-----\nMIIFakeData123456789==\n-----END CERTIFICATE-----"
    gen = AppleMobileConfigGenerator(
        organization="PasarGuard VPN",
        server_address="tur.mobx48.ir",
        remote_id="tur.mobx48.ir",
        ca_cert=fake_ca,
    )
    xml = gen.generate(profile_name="Turkey Node", username="test-ramin", password="secretpassword123")
    
    assert "com.apple.security.root" in xml
    assert "MIIFakeData123456789==" in xml
    assert "<key>AuthName</key>\n                <string>test-ramin</string>" in xml
    assert "<key>AuthPassword</key>\n                <string>secretpassword123</string>" in xml
    assert "<string>tur.mobx48.ir</string>" in xml

import tempfile

def test_subscription_auto_fallback_to_all_nodes():
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        engine = VPNEngine(data_dir=Path(temp_dir) / "data")
        engine.upsert_mock_user(
            username="auto_user",
            password="my_trojan_password",
            status="active",
            group="BETA",  # group has NO entry in _group_policies
            valid_passwords=["my_trojan_password", "my_vless_uuid"],
        )
    
    injector = VPNSubscriptionInjector(engine=engine, base_url="https://sub.mob48.ir:410")
    res = injector.generate_subscription_links("auto_user")
    
    assert res["username"] == "auto_user"
    assert res["group"] == "BETA"
    assert res["total_nodes"] >= 2  # turk and finland automatically included
    
    nodes = [c["node"] for c in res["configs"]]
    assert "turk" in nodes
    assert "finland" in nodes
    
    turk_cfg = next(c for c in res["configs"] if c["node"] == "turk")
    assert turk_cfg["server_host"] == "tur.mobx48.ir"
    assert turk_cfg["credentials"]["password"] == "my_trojan_password"
    assert "my_vless_uuid" in turk_cfg["credentials"]["valid_passwords"]
    assert "api/vpn/client/ovpn?node=turk&username=auto_user" in turk_cfg["ovpn_download_url"]
    assert "api/vpn/client/mobileconfig?node=turk&username=auto_user" in turk_cfg["mobileconfig_download_url"]

def test_vless_vmess_password_extraction():
    settings = {
        "vless": {"id": "11111111-2222-3333-4444-555555555555"},
        "vmess": {"id": "66666666-7777-8888-9999-000000000000"},
        "trojan": {"password": "trojan_pw"},
    }
    passwords = PasarGuardDBReader._extract_passwords_from_proxy_settings(settings)
    assert "11111111-2222-3333-4444-555555555555" in passwords
    assert "66666666-7777-8888-9999-000000000000" in passwords
    assert "trojan_pw" in passwords
