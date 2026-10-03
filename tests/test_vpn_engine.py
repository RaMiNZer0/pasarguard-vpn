import pytest
import xml.etree.ElementTree as ET
import tempfile
from pathlib import Path
from backend.vpn_engine import (
    VPNEngine,
    VPNAuthResult,
    VPNProtocol,
    OpenVPNClientConfigGenerator,
    AppleMobileConfigGenerator,
)


@pytest.fixture
def vpn_engine():
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        data_dir = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=data_dir)
        # Seed mock user data representing PasarGuard users
        engine.upsert_mock_user(
            username="ali_active",
            password="securepass123",
            status="active",
            data_limit=10 * 1024 * 1024 * 1024,  # 10 GB
            used_traffic=2 * 1024 * 1024 * 1024,  # 2 GB used
            expire=4102444800,  # Far in the future
            group="VIP",
        )
        engine.upsert_mock_user(
            username="reza_expired",
            password="securepass123",
            status="expired",
            data_limit=10 * 1024 * 1024 * 1024,
            used_traffic=1 * 1024 * 1024 * 1024,
            expire=1600000000,  # In the past
            group="Standard",
        )
        engine.upsert_mock_user(
            username="sara_limited",
            password="securepass123",
            status="active",
            data_limit=5 * 1024 * 1024 * 1024,  # 5 GB
            used_traffic=5 * 1024 * 1024 * 1024,  # 5 GB used (full)
            expire=4102444800,
            group="VIP",
        )
        yield engine


# ==============================================================================
# 1. تست‌های احراز هویت بلادرنگ (Real-Time Authentication Tests)
# ==============================================================================

def test_vpn_user_auth_success(vpn_engine):
    """کاربر فعال با پسورد درست و حجم باقیمانده باید اجازه اتصال بگیرد"""
    result = vpn_engine.authenticate_user(
        username="ali_active",
        password="securepass123",
        protocol=VPNProtocol.OPENVPN,
    )
    assert result.allowed is True
    assert result.username == "ali_active"
    assert result.remaining_bytes == 8 * 1024 * 1024 * 1024
    assert result.reason == "Authorized"


def test_vpn_user_auth_wrong_password(vpn_engine):
    """کاربر با پسورد اشتباه باید بلافاصله رد شود"""
    result = vpn_engine.authenticate_user(
        username="ali_active",
        password="wrongpassword!",
        protocol=VPNProtocol.IKEV2,
    )
    assert result.allowed is False
    assert result.reason == "Invalid credentials"


def test_vpn_user_auth_nonexistent(vpn_engine):
    """کاربر ناموجود باید رد شود"""
    result = vpn_engine.authenticate_user(
        username="ghost_user",
        password="password",
        protocol=VPNProtocol.L2TP,
    )
    assert result.allowed is False
    assert result.reason == "User not found"


def test_vpn_user_auth_expired(vpn_engine):
    """کاربر منقضی‌شده باید رد شود"""
    result = vpn_engine.authenticate_user(
        username="reza_expired",
        password="securepass123",
        protocol=VPNProtocol.OPENVPN,
    )
    assert result.allowed is False
    assert result.reason == "User expired"


def test_vpn_user_auth_quota_exceeded(vpn_engine):
    """کاربری که حجمش پر شده باید رد شود"""
    result = vpn_engine.authenticate_user(
        username="sara_limited",
        password="securepass123",
        protocol=VPNProtocol.IKEV2,
    )
    assert result.allowed is False
    assert result.reason == "Data quota exceeded"


# ==============================================================================
# 2. تست‌های اکانتینگ و کسر حجم (Accounting & Kill-Switch Tests)
# ==============================================================================

def test_accounting_deduct_traffic(vpn_engine):
    """گزارش مصرف باید از حجم کاربر کسر شود"""
    # ali_active 2GB used out of 10GB.
    consumed_bytes = 500 * 1024 * 1024  # 500 MB
    report = vpn_engine.report_traffic(
        username="ali_active",
        bytes_in=300 * 1024 * 1024,
        bytes_out=200 * 1024 * 1024,
        protocol=VPNProtocol.OPENVPN,
    )
    assert report["success"] is True
    assert report["used_traffic"] == (2 * 1024 * 1024 * 1024) + consumed_bytes
    assert report["should_kill"] is False


def test_accounting_triggers_kill_when_limit_reached(vpn_engine):
    """اگر در حین اتصال حجم کاربر تمام شود، دستور قطع باید صادر شود"""
    # ali_active has 8GB remaining. Let's consume 8.5 GB:
    consumed_bytes = 8500 * 1024 * 1024
    report = vpn_engine.report_traffic(
        username="ali_active",
        bytes_in=4000 * 1024 * 1024,
        bytes_out=4500 * 1024 * 1024,
        protocol=VPNProtocol.IKEV2,
    )
    assert report["success"] is True
    assert report["should_kill"] is True
    assert report["reason"] == "Quota exceeded"


# ==============================================================================
# 3. تست‌های پارسر هوک‌های سیستم‌عامل (OS Hook Parsers)
# ==============================================================================

def test_openvpn_auth_file_parser(vpn_engine):
    """پارسر فایل موقت OpenVPN (--auth-user-pass-verify via-file)"""
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        auth_file = Path(temp_dir) / "auth.txt"
        auth_file.write_text("ali_active\nsecurepass123\n", encoding="utf-8")
        
        auth_result = vpn_engine.handle_openvpn_auth_file(str(auth_file))
        assert auth_result.allowed is True
        assert auth_result.username == "ali_active"


def test_l2tp_ip_down_hook_parser(vpn_engine):
    """پارسر متغیرهای محیطی pppd در /etc/ppp/ip-down"""
    env_vars = {
        "PEERNAME": "ali_active",
        "BYTES_RCVD": "104857600",  # 100 MB
        "BYTES_SENT": "52428800",   # 50 MB
        "CONNECT_TIME": "360",
    }
    report = vpn_engine.handle_l2tp_ip_down(env_vars)
    assert report["success"] is True
    assert report["username"] == "ali_active"
    assert report["total_bytes"] == 157286400


def test_strongswan_vici_session_parser(vpn_engine):
    """پارسر ساختار بازگشتی سشن‌های strongSwan VICI list_sas"""
    vici_raw = {
        "remote-eap-id": "ali_active",
        "bytes-in": "209715200",  # 200 MB
        "bytes-out": "104857600", # 100 MB
        "ike-id": "14",
    }
    report = vpn_engine.handle_vici_session_update(vici_raw)
    assert report["success"] is True
    assert report["username"] == "ali_active"
    assert report["total_bytes"] == 314572800


# ==============================================================================
# 4. تست‌های تولید فایل‌های کلاینت (Config Generators)
# ==============================================================================

def test_generate_openvpn_client_config():
    """تولید فایل تک‌فایلی .ovpn استاندارد با کلید CA درون‌برنامه‌ای"""
    gen = OpenVPNClientConfigGenerator(
        server_host="de1.vpn.iranbu.fun",
        server_port=1194,
        proto="udp",
        ca_cert="-----BEGIN CERTIFICATE-----\nMOCK_CA_DATA\n-----END CERTIFICATE-----",
        cipher="AES-256-GCM",
    )
    ovpn_text = gen.generate(node_name="DE-Hetzner1")
    assert "remote de1.vpn.iranbu.fun 1194" in ovpn_text
    assert "proto udp" in ovpn_text
    assert "cipher AES-256-GCM" in ovpn_text
    assert "auth-user-pass" in ovpn_text
    assert "<ca>" in ovpn_text
    assert "MOCK_CA_DATA" in ovpn_text
    assert "</ca>" in ovpn_text


def test_generate_apple_mobileconfig():
    """تولید پروفایل معتبر XML اپل برای آیفون و مک (.mobileconfig)"""
    gen = AppleMobileConfigGenerator(
        organization="PasarGuard VPN",
        server_address="de1.vpn.iranbu.fun",
        remote_id="de1.vpn.iranbu.fun",
    )
    profile_xml = gen.generate(
        profile_name="PasarGuard DE1 (IKEv2)",
        username="ali_active",
    )
    assert "<?xml version=" in profile_xml
    assert "com.apple.vpn.managed" in profile_xml
    assert "de1.vpn.iranbu.fun" in profile_xml
    assert "ali_active" in profile_xml
    
    # اعتبارسنجی سینتکس معتبر XML
    root = ET.fromstring(profile_xml)
    assert root.tag == "plist"


# ==============================================================================
# 5. تست‌های مپینگ گروه‌ها و نودها (Group & Node Mapping Tests)
# ==============================================================================

def test_group_and_node_access(vpn_engine):
    """بررسی دسترسی کاربر بر اساس Group پاسارگارد به نود مشخص"""
    # گروه VIP به نود آلمان و هلند دسترسی دارد، گروه Standard فقط به آلمان
    vpn_engine.set_group_node_policy("VIP", allowed_nodes=["DE-Hetzner1", "NL-Server1"])
    vpn_engine.set_group_node_policy("Standard", allowed_nodes=["DE-Hetzner1"])

    # ali_active در گروه VIP است
    assert vpn_engine.can_user_access_node("ali_active", "DE-Hetzner1") is True
    assert vpn_engine.can_user_access_node("ali_active", "NL-Server1") is True
    assert vpn_engine.can_user_access_node("ali_active", "TR-Teknosos1") is False

    # reza_expired در گروه Standard است
    assert vpn_engine.can_user_access_node("reza_expired", "DE-Hetzner1") is True
    assert vpn_engine.can_user_access_node("reza_expired", "NL-Server1") is False
