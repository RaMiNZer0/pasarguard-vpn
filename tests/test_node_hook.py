"""
Tests for PasarGuard Lightweight Node Hook Script (pg_vpn_hook.py)
"""
import os
import sys
import tempfile
from pathlib import Path
import pytest

from node_worker.pg_vpn_hook import (
    handle_openvpn_auth_cli,
    handle_openvpn_disconnect_cli,
    handle_l2tp_ip_down_cli,
)
from backend.vpn_engine import VPNEngine


@pytest.fixture
def mock_engine_env():
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        data_dir = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=data_dir)
        engine.upsert_mock_user(
            username="node_user",
            password="pass123456",
            status="active",
            data_limit=5 * 1024 * 1024 * 1024,
            used_traffic=100 * 1024 * 1024,
            expire=4102444800,
        )
        yield engine


def test_openvpn_auth_cli_exit_zero(mock_engine_env):
    """تست خروج با کد صفر (اجازه اتصال) برای کاربر معتبر"""
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        auth_file = Path(temp_dir) / "auth.txt"
        auth_file.write_text("node_user\npass123456\n", encoding="utf-8")

        exit_code = handle_openvpn_auth_cli(str(auth_file), engine=mock_engine_env)
        assert exit_code == 0


def test_openvpn_auth_cli_exit_one_on_invalid_pass(mock_engine_env):
    """تست خروج با کد یک (رد اتصال) برای پسورد اشتباه"""
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        auth_file = Path(temp_dir) / "auth.txt"
        auth_file.write_text("node_user\nwrongpass\n", encoding="utf-8")

        exit_code = handle_openvpn_auth_cli(str(auth_file), engine=mock_engine_env)
        assert exit_code == 1


def test_openvpn_disconnect_cli(mock_engine_env):
    """تست هوک قطع اتصال اوپن‌وی‌پی‌ان و گزارش مصرف"""
    env = {
        "username": "node_user",
        "bytes_received": "52428800",  # 50 MB
        "bytes_sent": "104857600",     # 100 MB
        "time_duration": "120",
    }
    result = handle_openvpn_disconnect_cli(env=env, engine=mock_engine_env)
    assert result["success"] is True
    assert result["consumed_bytes"] == 157286400
    assert result["should_kill"] is False


def test_l2tp_ip_down_cli(mock_engine_env):
    """تست هوک پایان سشن L2TP در pppd"""
    env = {
        "PEERNAME": "node_user",
        "BYTES_RCVD": "20971520",  # 20 MB
        "BYTES_SENT": "31457280",  # 30 MB
        "CONNECT_TIME": "60",
    }
    result = handle_l2tp_ip_down_cli(env=env, engine=mock_engine_env)
    assert result["success"] is True
    assert result["consumed_bytes"] == 52428800
