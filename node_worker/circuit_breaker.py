"""
Circuit Breaker Pattern for Worker Node Network Operations
==========================================================
Protects nodes from cascading failures and excessive timeouts when
the Master panel is undergoing maintenance or temporary disconnection.
"""

from __future__ import annotations

import time
from typing import Any, Callable


class CircuitBreakerOpenException(Exception):
    """خطای باز بودن مدار به دلیل خطاهای متوالی شبکه"""
    pass


class CircuitBreaker:
    """مدار شکن خودکار با قابلیت ریکاوری تدریجی (Half-Open)"""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 15.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "CLOSED"  # "CLOSED", "OPEN", "HALF_OPEN"

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        now = time.time()

        if self.state == "OPEN":
            if now - self.last_failure_time >= self.recovery_timeout:
                self.state = "HALF_OPEN"
            else:
                raise CircuitBreakerOpenException("Circuit breaker is OPEN. Master panel unreachable.")

        try:
            result = func(*args, **kwargs)
            # موفقیت در فراخوانی
            self.failure_count = 0
            self.state = "CLOSED"
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = now
            if self.failure_count >= self.failure_threshold or self.state == "HALF_OPEN":
                self.state = "OPEN"
            raise e
