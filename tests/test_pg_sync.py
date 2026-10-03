"""
Tests for PasarGuard Database Reader and User Sync (Phase 1)
"""
import sqlite3
import tempfile
import time
from pathlib import Path
import pytest

from backend.vpn_engine import VPNEngine
from backend.pg_db_reader import PasarGuardDBReader
from backend.pg_user_sync import PasarGuardUserSync


@pytest.fixture
def mock_pasarguard_db():
    """ایجاد دیتابیس شبیه‌سازی‌شده پاسارگارد با اسکیما و داده‌های واقعی"""
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        db_path = Path(temp_dir) / "test_pasarguard.sqlite3"
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # اسکیما جداول کاربران و گروه‌های پاسارگارد
        cursor.execute("""
            CREATE TABLE groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                used_traffic INTEGER NOT NULL DEFAULT 0,
                data_limit INTEGER,
                expire TIMESTAMP,
                proxy_settings TEXT DEFAULT '{}',
                created_at TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE users_groups_association (
                user_id INTEGER,
                groups_id INTEGER,
                PRIMARY KEY (user_id, groups_id)
            )
        """)

        # درج گروه‌ها
        cursor.execute("INSERT INTO groups (id, name) VALUES (1, 'VIP')")
        cursor.execute("INSERT INTO groups (id, name) VALUES (2, 'Standard')")

        # درج کاربر فعال
        cursor.execute("""
            INSERT INTO users (id, username, status, used_traffic, data_limit, expire, proxy_settings)
            VALUES (
                1, 'reza', 'active', 1073741824, 10737418240, 4102444800,
                '{"trojan": {"password": "pass_reza_123"}, "hysteria": {"auth": "hy_auth_789"}}'
            )
        """)
        cursor.execute("INSERT INTO users_groups_association (user_id, groups_id) VALUES (1, 1)")

        # درج کاربر مسدود/غیرفعال (disabled)
        cursor.execute("""
            INSERT INTO users (id, username, status, used_traffic, data_limit, expire, proxy_settings)
            VALUES (
                2, 'blocked_user', 'disabled', 5000, 10737418240, 4102444800,
                '{"trojan": {"password": "secret_blocked"}}'
            )
        """)

        # درج کاربر با حجم تمام‌شده (limited)
        cursor.execute("""
            INSERT INTO users (id, username, status, used_traffic, data_limit, expire, proxy_settings)
            VALUES (
                3, 'quota_full_user', 'limited', 10737418240, 10737418240, 4102444800,
                '{"trojan": {"password": "pass_limited"}}'
            )
        """)

        conn.commit()
        conn.close()

        yield db_path


def test_db_reader_fetch_all_users(mock_pasarguard_db):
    """تست واکشی کامل اطلاعات کاربران از دیتابیس پاسارگارد"""
    reader = PasarGuardDBReader(db_url=f"sqlite:///{mock_pasarguard_db}")
    users = reader.fetch_all_users()

    assert len(users) == 3
    reza = next(u for u in users if u["username"] == "reza")
    assert reza["status"] == "active"
    assert reza["used_traffic"] == 1073741824
    assert reza["data_limit"] == 10737418240
    assert "pass_reza_123" in reza["valid_passwords"]
    assert "hy_auth_789" in reza["valid_passwords"]
    assert "VIP" in reza["groups"]


def test_user_sync_into_vpn_engine(mock_pasarguard_db):
    """تست همگام‌سازی کاربران به درون حافظه رم VPN Engine"""
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        vpn_data = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=vpn_data)
        reader = PasarGuardDBReader(db_url=f"sqlite:///{mock_pasarguard_db}")
        syncer = PasarGuardUserSync(engine=engine, db_reader=reader)

        # اجرای سینک
        count = syncer.sync_all()
        assert count == 3

        # کاربر فعال می‌تواند احراز هویت شود
        auth_ok = engine.authenticate_user("reza", "pass_reza_123", protocol="openvpn")
        assert auth_ok.allowed is True
        assert auth_ok.username == "reza"

        # کاربر با پسورد دیگرش در proxy_settings هم می‌تواند متصل شود
        auth_ok_hy = engine.authenticate_user("reza", "hy_auth_789", protocol="openvpn")
        assert auth_ok_hy.allowed is True

        # کاربر غیرفعال‌شده در پاسارگارد مسدود می‌شود
        auth_blocked = engine.authenticate_user("blocked_user", "secret_blocked", protocol="openvpn")
        assert auth_blocked.allowed is False
        assert "disabled" in auth_blocked.reason.lower()

        # کاربر حجم تمام‌شده در پاسارگارد مسدود می‌شود
        auth_limited = engine.authenticate_user("quota_full_user", "pass_limited", protocol="openvpn")
        assert auth_limited.allowed is False


def test_on_demand_realtime_sync_new_user(mock_pasarguard_db):
    """تست همگام‌سازی بلادرنگ برای کاربری که لحظه‌ای در دیتابیس ساخته می‌شود"""
    with tempfile.TemporaryDirectory(dir=".") as temp_dir:
        vpn_data = Path(temp_dir) / "vpn_data"
        engine = VPNEngine(data_dir=vpn_data)
        reader = PasarGuardDBReader(db_url=f"sqlite:///{mock_pasarguard_db}")
        syncer = PasarGuardUserSync(engine=engine, db_reader=reader)
        engine.set_user_syncer(syncer)

        # کاربری که هنوز در کش موتور نیست
        # در دیتابیس اضافه می‌کنیم
        conn = sqlite3.connect(str(mock_pasarguard_db))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, status, used_traffic, data_limit, expire, proxy_settings)
            VALUES ('new_instant_user', 'active', 0, 5000000, 4102444800, '{"trojan": {"password": "instant_pass"}}')
        """)
        conn.commit()
        conn.close()

        # احراز هویت بلافاصله بدون نیاز به پولینگ، کاربر را مستقیم از DB می‌خواند
        res = engine.authenticate_user("new_instant_user", "instant_pass", protocol="openvpn")
        assert res.allowed is True
        assert res.username == "new_instant_user"
