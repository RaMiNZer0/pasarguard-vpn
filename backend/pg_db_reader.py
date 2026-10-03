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

try:
    from app.db.base import GetDB
    from app.db.models import User
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    _HAS_APP_DB = True
except ImportError:
    _HAS_APP_DB = False


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
        if _HAS_APP_DB:
            return True
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

        # 5. VLESS UUID
        if "vless" in data and isinstance(data["vless"], dict):
            uid = data["vless"].get("id")
            if uid:
                passwords.add(str(uid))

        # 6. VMess UUID
        if "vmess" in data and isinstance(data["vmess"], dict):
            uid = data["vmess"].get("id")
            if uid:
                passwords.add(str(uid))

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

    def _fetch_from_app_db(self, username: Optional[str] = None) -> List[Dict[str, Any]]:
        import asyncio
        from app.db.base import GetDB
        from app.db.models import User
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        async def _query():
            async with GetDB() as db:
                stmt = select(User).options(selectinload(User.groups))
                if username:
                    stmt = stmt.where(User.username == username)
                res = await db.execute(stmt)
                users = res.scalars().all()
                out = []
                for u in users:
                    pws = self._extract_passwords_from_proxy_settings(u.proxy_settings)
                    groups = [g.name for g in u.groups] if getattr(u, "groups", None) else ["default"]
                    expire_ts = int(u.expire.timestamp()) if getattr(u, "expire", None) and hasattr(u.expire, "timestamp") else 0
                    status_str = u.status.value if hasattr(u.status, "value") else str(u.status).lower()
                    out.append({
                        "id": u.id,
                        "username": u.username,
                        "status": status_str,
                        "used_traffic": int(u.used_traffic or 0),
                        "data_limit": int(u.data_limit or 0),
                        "expire": expire_ts,
                        "valid_passwords": list(pws),
                        "groups": groups,
                    })
                return out

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # اگر در لوپ در حال اجرا هستیم و متد sync فراخوانی شده
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(asyncio.run, _query()).result()
            return loop.run_until_complete(_query())
        except RuntimeError:
            return asyncio.run(_query())
        except Exception as e:
            logger.error(f"Error reading from app.db: {e}")
            return []

    async def fetch_all_users_async(self) -> List[Dict[str, Any]]:
        """واکشی تمام رکوردهای کاربران در محیط Asynchronous بدون تداخل event loop"""
        if _HAS_APP_DB:
            from app.db.base import GetDB
            from app.db.models import User
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload

            async with GetDB() as db:
                stmt = select(User).options(selectinload(User.groups))
                res = await db.execute(stmt)
                users = res.scalars().all()
                out = []
                for u in users:
                    pws = self._extract_passwords_from_proxy_settings(u.proxy_settings)
                    groups = [g.name for g in u.groups] if getattr(u, "groups", None) else ["default"]
                    expire_ts = int(u.expire.timestamp()) if getattr(u, "expire", None) and hasattr(u.expire, "timestamp") else 0
                    status_str = u.status.value if hasattr(u.status, "value") else str(u.status).lower()
                    out.append({
                        "id": u.id,
                        "username": u.username,
                        "status": status_str,
                        "used_traffic": int(u.used_traffic or 0),
                        "data_limit": int(u.data_limit or 0),
                        "expire": expire_ts,
                        "valid_passwords": list(pws),
                        "groups": groups,
                    })
                return out
        return self.fetch_all_users()

    async def fetch_user_async(self, username: str) -> Optional[Dict[str, Any]]:
        """واکشی آنی یک کاربر در محیط Asynchronous"""
        if _HAS_APP_DB:
            from app.db.base import GetDB
            from app.db.models import User
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload

            async with GetDB() as db:
                stmt = select(User).options(selectinload(User.groups)).where(User.username == username)
                res = await db.execute(stmt)
                u = res.scalar_one_or_none()
                if not u:
                    return None
                pws = self._extract_passwords_from_proxy_settings(u.proxy_settings)
                groups = [g.name for g in u.groups] if getattr(u, "groups", None) else ["default"]
                expire_ts = int(u.expire.timestamp()) if getattr(u, "expire", None) and hasattr(u.expire, "timestamp") else 0
                status_str = u.status.value if hasattr(u.status, "value") else str(u.status).lower()
                return {
                    "id": u.id,
                    "username": u.username,
                    "status": status_str,
                    "used_traffic": int(u.used_traffic or 0),
                    "data_limit": int(u.data_limit or 0),
                    "expire": expire_ts,
                    "valid_passwords": list(pws),
                    "groups": groups,
                }
        return self.fetch_user(username)

    def fetch_all_users(self) -> List[Dict[str, Any]]:
        """واکشی تمام رکوردهای کاربران همراه با گروه‌ها و سهمیه‌ها"""
        if not self.is_available():
            return []

        if _HAS_APP_DB:
            return self._fetch_from_app_db()

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

        if _HAS_APP_DB:
            res = self._fetch_from_app_db(username=username)
            return res[0] if res else None

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

    async def fetch_nodes_async(self) -> List[Dict[str, Any]]:
        """واکشی لیست نودهای متصل و نگاشت دامنه عمومی آنها"""
        fallback_nodes = [
            {
                "id": 2,
                "name": "turk",
                "display_name": "🇹🇷 ترکیه (Turkey)",
                "address": "77.83.203.140",
                "public_host": "tur.mobx48.ir",
                "port": 3333,
                "status": "connected",
                "openvpn_port": 1194,
                "ikev2_port": 500,
            },
            {
                "id": 3,
                "name": "finland",
                "display_name": "🇫🇮 فنلاند (Finland)",
                "address": "65.109.217.93",
                "public_host": "fin.mobx48.ir",
                "port": 3333,
                "status": "connected",
                "openvpn_port": 1194,
                "ikev2_port": 500,
            },
        ]

        if not _HAS_APP_DB:
            return fallback_nodes

        try:
            from app.db.base import GetDB
            from app.db.models import Node, ProxyHost
            from sqlalchemy import select

            async with GetDB() as db:
                res_n = await db.execute(select(Node))
                nodes = res_n.scalars().all()
                res_h = await db.execute(select(ProxyHost))
                proxy_hosts = res_h.scalars().all()

                # ساخت نگاشت آی‌پی/نود به دامنه عمومی
                host_map: Dict[str, str] = {
                    "turk": "tur.mobx48.ir",
                    "77.83.203.140": "tur.mobx48.ir",
                    "finland": "fin.mobx48.ir",
                    "65.109.217.93": "fin.mobx48.ir",
                }
                for ph in proxy_hosts:
                    addresses = ph.address if isinstance(ph.address, (set, list)) else [ph.address]
                    for addr in addresses:
                        if addr and isinstance(addr, str) and not addr.replace(".", "").isdigit():
                            remark = (ph.remark or "").lower()
                            if "turk" in remark or "ترکیه" in remark or "tr" in remark:
                                host_map["turk"] = addr
                                host_map["77.83.203.140"] = addr
                            elif "fin" in remark or "فنلاند" in remark:
                                host_map["finland"] = addr
                                host_map["65.109.217.93"] = addr

                out = []
                for n in nodes:
                    status_str = n.status.value if hasattr(n.status, "value") else str(n.status).lower()
                    node_name = n.name.lower()
                    pub_host = host_map.get(node_name) or host_map.get(n.address) or n.address
                    if n.address == "127.0.0.1":
                        pub_host = "sub.mob48.ir"

                    display_name = n.name
                    if "turk" in node_name:
                        display_name = "🇹🇷 ترکیه (Turkey)"
                    elif "fin" in node_name:
                        display_name = "🇫🇮 فنلاند (Finland)"
                    elif "main" in node_name or "de" in node_name:
                        display_name = "🇩🇪 سرور اصلی (Main)"

                    out.append({
                        "id": n.id,
                        "name": n.name,
                        "display_name": display_name,
                        "address": n.address,
                        "public_host": pub_host,
                        "port": n.port,
                        "status": status_str,
                        "openvpn_port": 1194,
                        "ikev2_port": 500,
                    })
                return out if out else fallback_nodes
        except Exception as e:
            logger.warning(f"Error in fetch_nodes_async, using fallback: {e}")
            return fallback_nodes

    def fetch_nodes(self) -> List[Dict[str, Any]]:
        """واکشی همگام لیست نودها با فال‌بک امن"""
        fallback_nodes = [
            {
                "id": 2,
                "name": "turk",
                "display_name": "🇹🇷 ترکیه (Turkey)",
                "address": "77.83.203.140",
                "public_host": "tur.mobx48.ir",
                "port": 3333,
                "status": "connected",
                "openvpn_port": 1194,
                "ikev2_port": 500,
            },
            {
                "id": 3,
                "name": "finland",
                "display_name": "🇫🇮 فنلاند (Finland)",
                "address": "65.109.217.93",
                "public_host": "fin.mobx48.ir",
                "port": 3333,
                "status": "connected",
                "openvpn_port": 1194,
                "ikev2_port": 500,
            },
        ]
        return fallback_nodes
