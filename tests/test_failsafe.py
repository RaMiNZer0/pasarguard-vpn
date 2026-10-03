"""
Tests for Fault-Tolerance, Local Cache, and Circuit Breaker (Phase 4)
"""
import time
import pytest
from unittest.mock import MagicMock
from node_worker.local_cache import LocalAuthCache
from node_worker.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException


def test_local_auth_cache_hit_and_expiry():
    """تست کش محلی احراز هویت و منقضی شدن پس از انقضای TTL"""
    cache = LocalAuthCache(ttl_seconds=1)

    cache.set("user_a", allowed=True)
    assert cache.get("user_a") is True

    # کاربر ثبت‌نشده در کش
    assert cache.get("user_b") is None

    # صبر برای انقضا
    time.sleep(1.1)
    assert cache.get("user_a") is None


def test_circuit_breaker_tripping_and_recovery():
    """تست باز شدن مدار پس از خطاهای متوالی و بازگشت به حالت عادی"""
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.5)

    # تست فراخوانی موفق
    res = cb.call(lambda: "ok")
    assert res == "ok"
    assert cb.state == "CLOSED"

    # دو خطای متوالی
    with pytest.raises(ValueError):
        cb.call(lambda: (_ for _ in ()).throw(ValueError("network error 1")))
    with pytest.raises(ValueError):
        cb.call(lambda: (_ for _ in ()).throw(ValueError("network error 2")))

    # اکنون مدار باید باز شده باشد (OPEN)
    assert cb.state == "OPEN"
    with pytest.raises(CircuitBreakerOpenException):
        cb.call(lambda: "should_not_run")

    # صبر برای ریکاوری (HALF_OPEN)
    time.sleep(0.6)
    res_rec = cb.call(lambda: "recovered")
    assert res_rec == "recovered"
    assert cb.state == "CLOSED"


def test_pg_vpn_hook_with_failsafe_cache(monkeypatch):
    """هنگامی که مستر در دسترس نیست، هوک باید از کش محلی استفاده کند و کلاینت قطع نشود"""
    from node_worker import pg_vpn_hook

    # ماک کردن کش با کاربر معتبر
    hook_cache = LocalAuthCache(ttl_seconds=60)
    hook_cache.set("cached_user", allowed=True)
    monkeypatch.setattr(pg_vpn_hook, "_local_cache", hook_cache)

    # ماک کردن مستر که قطع است
    monkeypatch.setattr(pg_vpn_hook, "_call_master_api", MagicMock(side_effect=Exception("Connection refused")))
    monkeypatch.setattr(pg_vpn_hook, "MASTER_URL", "https://dead.master.example.com")

    # احراز هویت باید به لطف کش محلی موفق شود (کد خروجی 0)
    import tempfile
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("cached_user\nany_password\n")
        f.flush()
        auth_file = f.name

    code = pg_vpn_hook.handle_openvpn_auth_cli(auth_file)
    assert code == 0
