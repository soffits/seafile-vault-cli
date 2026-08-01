from __future__ import annotations

import math

DEFAULT_LOCK_EXPIRES_SECONDS = 3600
MAX_LOCK_EXPIRES_SECONDS = 24 * 3600


def validate_lock_expiry_seconds(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if value > MAX_LOCK_EXPIRES_SECONDS:
        raise ValueError(f"{name} must be <= {MAX_LOCK_EXPIRES_SECONDS}")
    return value
