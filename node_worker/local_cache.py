"""
Local Authentication Cache for Worker Nodes
===========================================
Ultra-fast in-memory and optional disk-persisted authentication cache
providing resilience against temporary network blips to the Master panel.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("pasarguard_vpn.local_cache")


class LocalAuthCache:
    """کش محلی سریع با منقضی‌سازی زمانی (TTL) و اعتبارسنجی جفت نام‌کاربری/رمز"""

    def __init__(
        self,
        ttl_seconds: int = 300,
        cache_file: Optional[str] = "/tmp/pg_vpn_auth_cache.json",
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.cache_file = cache_file
        self._lock = threading.Lock()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self.cache_file and os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    now = time.time()
                    self._cache = {
                        u: rec for u, rec in data.items()
                        if now - rec.get("timestamp", 0) < self.ttl_seconds
                    }
            except Exception:
                self._cache = {}

    def _save(self) -> None:
        if not self.cache_file:
            return
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
        except Exception:
            pass

    def get(self, username: str, password: Optional[str] = None) -> Optional[bool]:
        with self._lock:
            rec = self._cache.get(username)
            if not rec:
                return None
            if time.time() - rec["timestamp"] > self.ttl_seconds:
                del self._cache[username]
                return None
            if password is not None and rec.get("password") and rec["password"] != password:
                return None
            return rec["allowed"]

    def set(self, username: str, allowed: bool, password: Optional[str] = None) -> None:
        with self._lock:
            self._cache[username] = {
                "allowed": allowed,
                "password": password,
                "timestamp": time.time(),
            }
            self._save()

    def invalidate(self, username: str) -> None:
        """باطل کردن کش کاربر (مثلاً در زمان اتمام حجم یا اعمال کیل‌سوئیچ)"""
        with self._lock:
            if username in self._cache:
                del self._cache[username]
                self._save()

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._save()
