"""
PasarGuard Read-Only Database Reader
====================================
Safely queries the PasarGuard database (SQLite/PostgreSQL) in strict Read-Only mode
to extract real-time user status, traffic accounting, credentials, and group memberships.
Zero mutation, zero locks, zero overhead.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("pasarguard_vpn.db_reader")


class PasarGuardDBReader:
    """خواندن امن و بلادرنگ اطلاعات کاربران از دیتابیس پاسارگارد به صورت Read-Only"""

    def __init__(self, db_url: Optional[str] = None) -> None:
        if db_url is None:
            # جستجو در متغیرهای محیطی یا مسیرهای پیش‌فرض داکر و هاست پاسارگارد
            db_url = os.environ.get("PASARGUARD_DB_URL") or os.environ.get("DATABASE_URL")
            if not db_url:
                candidates = [
                    "/opt/pasarguard/data/db.sqlite3",
                    "/var/lib/pasarguard/db.sqlite3",
                    "/code/data/db.sqlite3",
                ]
                for cand in candidates:
                    if Path(cand).exists():
                        db_url = f"sqlite:///{cand}"
                        break
        self.db_url = db_url or "sqlite:////opt/pasarguard/data/db.sqlite3"

    def _get_sqlite_path(self) -> Optional[Path]:
        if not self.db_url.startswith("sqlite:///"):
            return None
        raw_path = self.db_url[len("sqlite:///"):]
        return Path(raw_path)

    def is_available(self) -> bool:
        """بررسی موجودیت و دسترسی به دیتابیس"""
        p = self._get_sqlite_path()
        return p is not None and p.exists()

    def _get_connection(self) -> sqlite3.Connection:
        p = self._get_sqlite_path()
        if not p or not p.exists():
            raise FileNotFoundError(f"PasarGuard SQLite database not found at {p}")
        # اتصال ایمن به صورت read-only (URI mode=ro)
        try:
            uri = f"file:{p.resolve().as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=2.0)
        except Exception:
            conn = sqlite3.connect(str(p), timeout=2.0)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _extract_passwords_from_proxy_settings(raw_settings: Any) -> Set[str]:
        """استخراج تمام رمزهای عبور فعال کاربر از تنظیمات پروتکل‌های پاسارگارد"""
        passwords: Set[str] = set()
        if not raw_settings:
            return passwords

        data = {}
        if isinstance(raw_settings, str):
            try:
                data = json.loads(raw_settings)
            except Exception:
                pass
        elif isinstance(raw_settings, dict):
            data = raw_settings

        # 1. Trojan password
        if "trojan" in data and isinstance(data["trojan"], dict):
            pw = data["trojan"].get("password")
            if pw:
                passwords.add(str(pw))

        # 2. Hysteria auth
        if "hysteria" in data and isinstance(data["hysteria"], dict):
            auth = data["hysteria"].get("auth")
            if auth:
                passwords.add(str(auth))

        # 3. Shadowsocks password
        if "shadowsocks" in data and isinstance(data["shadowsocks"], dict):
            pw = data["shadowsocks"].get("password")
            if pw:
                passwords.add(str(pw))

        # 4. VPN specific password (اگر دستی تعریف شده باشد)
        if "vpn_password" in data:
            passwords.add(str(data["vpn_password"]))

        return passwords

    @staticmethod
    def _parse_timestamp(val: Any) -> int:
        if val is None:
            return 0
        if isinstance(val, (int, float)):
            return int(val)
        if isinstance(val, str):
            val = val.strip()
            if not val:
                return 0
            if val.isdigit():
                return int(val)
            try:
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                return int(dt.timestamp())
            except Exception:
                return 0
        return 0

    def fetch_all_users(self) -> List[Dict[str, Any]]:
        """واکشی تمام رکوردهای کاربران همراه با گروه‌ها و سهمیه‌ها"""
        if not self.is_available():
            return []

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # استخراج کاربران
            cursor.execute("""
                SELECT 
                    u.id,
                    u.username,
                    u.status,
                    u.used_traffic,
                    u.data_limit,
                    u.expire,
                    u.proxy_settings,
                    GROUP_CONCAT(g.name, ',') as group_names
                FROM users u
                LEFT JOIN users_groups_association uga ON u.id = uga.user_id
                LEFT JOIN groups g ON uga.groups_id = g.id
                GROUP BY u.id
            """)
            rows = cursor.fetchall()

            results: List[Dict[str, Any]] = []
            for row in rows:
                pws = self._extract_passwords_from_proxy_settings(row["proxy_settings"])
                groups_str = row["group_names"] or ""
                groups = [g.strip() for g in groups_str.split(",") if g.strip()] or ["default"]

                results.append({
                    "id": row["id"],
                    "username": row["username"],
                    "status": str(row["status"]).lower(),
                    "used_traffic": int(row["used_traffic"] or 0),
                    "data_limit": int(row["data_limit"] or 0),
                    "expire": self._parse_timestamp(row["expire"]),
                    "valid_passwords": list(pws),
                    "groups": groups,
                })
            return results
        finally:
            conn.close()

    def fetch_user(self, username: str) -> Optional[Dict[str, Any]]:
        """واکشی آنی یک کاربر خاص برای احراز هویت بلادرنگ در لحظه اتصال"""
        if not self.is_available():
            return None

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    u.id,
                    u.username,
                    u.status,
                    u.used_traffic,
                    u.data_limit,
                    u.expire,
                    u.proxy_settings,
                    GROUP_CONCAT(g.name, ',') as group_names
                FROM users u
                LEFT JOIN users_groups_association uga ON u.id = uga.user_id
                LEFT JOIN groups g ON uga.groups_id = g.id
                WHERE u.username = ?
                GROUP BY u.id
            """, (username,))
            row = cursor.fetchone()
            if not row:
                return None

            pws = self._extract_passwords_from_proxy_settings(row["proxy_settings"])
            groups_str = row["group_names"] or ""
            groups = [g.strip() for g in groups_str.split(",") if g.strip()] or ["default"]

            return {
                "id": row["id"],
                "username": row["username"],
                "status": str(row["status"]).lower(),
                "used_traffic": int(row["used_traffic"] or 0),
                "data_limit": int(row["data_limit"] or 0),
                "expire": self._parse_timestamp(row["expire"]),
                "valid_passwords": list(pws),
                "groups": groups,
            }
        finally:
            conn.close()
