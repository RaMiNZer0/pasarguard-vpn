"""
Tests for IKEv2 strongSwan VICI Poller (Phase 3)
"""
import pytest
from unittest.mock import MagicMock
from node_worker.vici_poller import StrongSwanVICIPoller


def test_vici_poller_parse_sas_output():
    """تست پارس کردن خروجی نشست‌های فعال strongSwan"""
    mock_sa_data = {
        "ike-vpn-1": {
            "remote-eap-id": "reza_ios",
            "bytes-in": 52428800,   # 50 MB
            "bytes-out": 104857600, # 100 MB
            "state": "ESTABLISHED",
        },
        "ike-vpn-2": {
            "remote-eap-id": "sara_mac",
            "bytes-in": 10485760,  # 10 MB
            "bytes-out": 20971520,  # 20 MB
            "state": "ESTABLISHED",
        }
    }

    poller = StrongSwanVICIPoller(master_url="https://master.example.com", api_token="secret_token")
    deltas = poller.compute_traffic_deltas(mock_sa_data)

    assert len(deltas) == 2
    reza = next(d for d in deltas if d["username"] == "reza_ios")
    assert reza["bytes_in_delta"] == 52428800
    assert reza["bytes_out_delta"] == 104857600

    # در دور دوم پولینگ، فقط مابه‌التفاوت محاسبه شود
    mock_sa_data_2 = {
        "ike-vpn-1": {
            "remote-eap-id": "reza_ios",
            "bytes-in": 52428800 + 1048576,   # +1 MB
            "bytes-out": 104857600 + 2097152, # +2 MB
            "state": "ESTABLISHED",
        }
    }
    deltas_2 = poller.compute_traffic_deltas(mock_sa_data_2)
    assert len(deltas_2) == 1
    reza_2 = deltas_2[0]
    assert reza_2["bytes_in_delta"] == 1048576
    assert reza_2["bytes_out_delta"] == 2097152


def test_vici_poller_kill_switch_trigger(monkeypatch):
    """تست تریگر شدن قطع اتصال در صورت اتمام حجم کاربر در پاسخ مستر"""
    poller = StrongSwanVICIPoller(master_url="https://master.example.com", api_token="secret_token")

    # ماک کردن درخواست HTTP به مستر که اعلام می‌کند سهمیه تمام شده
    poller._report_traffic_api = MagicMock(return_value={"success": True, "should_kill": True})
    poller._terminate_sa = MagicMock(return_value=True)

    poller.process_session_update({
        "ike-vpn-1": {
            "remote-eap-id": "limited_user",
            "bytes-in": 500000000,
            "bytes-out": 500000000,
        }
    })

    # باید دستور قطع SA فراخوانی شود
    poller._terminate_sa.assert_called_once_with("ike-vpn-1")
