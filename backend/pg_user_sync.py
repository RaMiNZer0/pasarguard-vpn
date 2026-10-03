"""
PasarGuard User Synchronizer (Real-Time & Polled Sync)
======================================================
Bridges PasarGuard core user database with the VPN Engine.
Ensures zero delay when users are enabled/disabled/quota-limited in the panel.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional

from backend.pg_db_reader import PasarGuardDBReader
from backend.vpn_engine import VPNEngine, VPNUser

logger = logging.getLogger("pasarguard_vpn.user_sync")


class PasarGuardUserSync:
    """همگام‌ساز خودکار وضعیت کاربران پاسارگارد با حافظه موتور VPN"""

    def __init__(
        self,
        engine: Any,
        db_reader: Optional[Any] = None,
    ) -> None:
        if hasattr(engine, "is_available") and hasattr(db_reader, "authenticate_user"):
            engine, db_reader = db_reader, engine
        self.engine = engine
        self.db_reader = db_reader or PasarGuardDBReader()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_sync_time: float = 0.0

    def _apply_user_dict(self, data: Dict[str, Any]) -> VPNUser:
        username = data["username"]
        status = data.get("status", "active")
        used_traffic = data.get("used_traffic", 0)
        data_limit = data.get("data_limit", 0)
        expire = data.get("expire", 0)
        valid_passwords = data.get("valid_passwords", [])
        primary_pw = valid_passwords[0] if valid_passwords else ""
        groups = data.get("groups", ["default"])
        primary_group = groups[0] if groups else "default"

        # ثبت یا بروزرسانی در موتور
        user = VPNUser(
            username=username,
            password=primary_pw,
            status=status,
            data_limit=data_limit,
            used_traffic=used_traffic,
            expire=expire,
            group=primary_group,
            valid_passwords=valid_passwords,
        )
        self.engine._users[username] = user
        return user

    async def sync_all_async(self) -> int:
        """همگام‌سازی ناهمگام کامل تمام کاربران بدون مسدود کردن event loop"""
        if not self.db_reader.is_available():
            return 0

        if hasattr(self.db_reader, "fetch_all_users_async"):
            users_data = await self.db_reader.fetch_all_users_async()
        else:
            users_data = self.db_reader.fetch_all_users()

        for u in users_data:
            self._apply_user_dict(u)

        if users_data:
            self.engine._save_state()
        self._last_sync_time = time.time()
        logger.info(f"Synced {len(users_data)} users asynchronously from PasarGuard DB")
        return len(users_data)

    async def sync_user_async(self, username: str) -> Optional[VPNUser]:
        """همگام‌سازی ناهمگام یک کاربر در لحظه درخواست اتصال"""
        if not self.db_reader.is_available():
            return None

        if hasattr(self.db_reader, "fetch_user_async"):
            u_data = await self.db_reader.fetch_user_async(username)
        else:
            u_data = self.db_reader.fetch_user(username)

        if not u_data:
            return None

        user = self._apply_user_dict(u_data)
        self.engine._save_state()
        return user

    def sync_all(self) -> int:
        """همگام‌سازی کامل تمام کاربران از دیتابیس پاسارگارد"""
        if not self.db_reader.is_available():
            return 0

        users_data = self.db_reader.fetch_all_users()
        for u in users_data:
            self._apply_user_dict(u)

        if users_data:
            self.engine._save_state()
        self._last_sync_time = time.time()
        logger.info(f"Synced {len(users_data)} users from PasarGuard DB")
        return len(users_data)

    def sync_user(self, username: str) -> Optional[VPNUser]:
        """همگام‌سازی آنی یک کاربر در لحظه درخواست اتصال"""
        if not self.db_reader.is_available():
            return None

        u_data = self.db_reader.fetch_user(username)
        if not u_data:
            return None

        user = self._apply_user_dict(u_data)
        self.engine._save_state()
        return user

    def start_background_sync(self, interval: int = 60) -> None:
        """راه‌اندازی ترد پس‌زمینه سبک برای پولینگ بدون مصرف CPU"""
        if self._thread and self._thread.is_alive():
            return

        def _worker():
            while not self._stop_event.is_set():
                try:
                    self.sync_all()
                except Exception as e:
                    logger.error(f"Background user sync error: {e}")
                self._stop_event.wait(interval)

        self._stop_event.clear()
        self._thread = threading.Thread(target=_worker, daemon=True, name="PGUserSyncWorker")
        self._thread.start()

    def stop_background_sync(self) -> None:
        """توقف ترد همگام‌ساز"""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
