"""
WebShare Pro - Dashboard Service
통계/디스크 요약 API 공통 서비스
"""

from __future__ import annotations

import shutil
import threading
import time
from datetime import datetime
from typing import Any, Dict

from config import (
    ACTIVE_SESSIONS,
    SERVER_START_TIME,
    STATS,
    conf,
    session_lock,
    stats_lock,
)
from .file_utils import fmt_bytes

try:
    from cachetools import TTLCache
except ImportError:  # pragma: no cover - optional dependency
    TTLCache = None


_CACHE_TTL_SECONDS = 2
_CACHE_MAXSIZE = 128
_cache_lock = threading.Lock()
if TTLCache is not None:
    _cache = TTLCache(maxsize=_CACHE_MAXSIZE, ttl=_CACHE_TTL_SECONDS)
else:
    _cache = {}


def _cache_get(key: str) -> Dict[str, Any] | None:
    with _cache_lock:
        if TTLCache is not None:
            value = _cache.get(key)
            return dict(value) if isinstance(value, dict) else value

        now = time.time()
        cached = _cache.get(key)
        if not cached:
            return None
        payload, expires_at = cached
        if now > expires_at:
            _cache.pop(key, None)
            return None
        return dict(payload)


def _cache_set(key: str, payload: Dict[str, Any]) -> None:
    with _cache_lock:
        if TTLCache is not None:
            _cache[key] = dict(payload)
            return
        _cache[key] = (dict(payload), time.time() + _CACHE_TTL_SECONDS)
        if len(_cache) > _CACHE_MAXSIZE:
            oldest_key = next(iter(_cache))
            _cache.pop(oldest_key, None)


def _uptime_string() -> str:
    uptime = datetime.now() - SERVER_START_TIME
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s"


def _active_session_count() -> int:
    with session_lock:
        return len(ACTIVE_SESSIONS)


def get_metrics_payload() -> Dict[str, Any]:
    with stats_lock:
        stats_copy = STATS.copy()

    active_count = _active_session_count()
    return {
        "uptime": _uptime_string(),
        "requests": stats_copy["requests"],
        "bytes_sent": stats_copy["bytes_sent"],
        "bytes_received": stats_copy["bytes_received"],
        "bytes_sent_fmt": fmt_bytes(stats_copy["bytes_sent"]),
        "bytes_received_fmt": fmt_bytes(stats_copy["bytes_received"]),
        "errors": stats_copy["errors"],
        "active_connections": active_count,
    }


def get_disk_payload() -> Dict[str, Any]:
    cache_key = f"disk:{conf.get('folder')}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    total, used, free = shutil.disk_usage(conf.get("folder"))
    percent = round((used / total) * 100, 1) if total else 0
    payload = {
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
        "total": fmt_bytes(total),
        "used": fmt_bytes(used),
        "free": fmt_bytes(free),
        "total_fmt": fmt_bytes(total),
        "used_fmt": fmt_bytes(used),
        "free_fmt": fmt_bytes(free),
        "percent": percent,
        "threshold": conf.get("disk_warning_threshold", 90),
    }
    payload["warning"] = payload["percent"] >= payload["threshold"]
    _cache_set(cache_key, payload)
    return payload


def get_dashboard_summary_payload() -> Dict[str, Any]:
    cache_key = "dashboard:summary"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    metrics = get_metrics_payload()
    disk = get_disk_payload()
    payload = {
        "timestamp": datetime.now().isoformat(),
        "metrics": metrics,
        "disk": disk,
    }
    _cache_set(cache_key, payload)
    return payload
