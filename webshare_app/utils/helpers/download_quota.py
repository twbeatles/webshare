"""Daily download quota checks, reservations, and tracking."""

from __future__ import annotations
from datetime import datetime
from utils.log_manager import logger




def build_download_tracker_key(session_id: str = "", ip: str = "", *, prefer_session: bool = True) -> str:
    normalized_sid = str(session_id or "").strip()
    normalized_ip = str(ip or "").strip()
    if prefer_session and normalized_sid:
        return f"session:{normalized_sid}"
    return f"ip:{normalized_ip or 'unknown'}"




def check_download_limit(tracker_key: str, count_event: bool = True, projected_bytes: int = 0) -> tuple[bool, str]:
    """Check daily download count/bytes limits for one tracker key."""
    from config import DOWNLOAD_TRACKER, conf, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")
    normalized_key = str(tracker_key or "").strip() or "ip:unknown"

    with download_tracker_lock:
        if normalized_key not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[normalized_key].get("date") != today:
            DOWNLOAD_TRACKER[normalized_key] = {"count": 0, "bytes": 0, "date": today}
            from features.runtime_state import mark_download_tracker_dirty

            mark_download_tracker_dirty()

        tracker = DOWNLOAD_TRACKER[normalized_key]
        limit_count = conf.get("daily_download_limit") or 0
        limit_mb = conf.get("daily_bandwidth_limit_mb") or 0

        if count_event and limit_count > 0 and tracker["count"] >= limit_count:
            return False, f"Daily download limit exceeded ({limit_count})"

        projected_total = tracker["bytes"] + max(0, int(projected_bytes or 0))
        if limit_mb > 0 and projected_total > limit_mb * 1024 * 1024:
            return False, f"Daily bandwidth limit exceeded ({limit_mb}MB)"

    return True, ""




def reserve_download_quota(tracker_key: str, count_event: bool = True, projected_bytes: int = 0) -> tuple[bool, str, dict]:
    """
    Atomically reserve one download quota unit.

    The legacy check function is called first so tests and extensions that
    monkeypatch it still affect quota decisions. The counter is then checked
    and updated under the tracker lock to close concurrent races.
    """
    # Resolve through the public package namespace (not the module global) so
    # monkeypatching `utils.helpers.check_download_limit` keeps working now
    # that this function lives in a submodule.
    from webshare_app.utils import helpers as _helpers_pkg

    allowed, message = _helpers_pkg.check_download_limit(tracker_key, count_event, projected_bytes=projected_bytes)
    if not allowed:
        return False, message, {}

    from config import DOWNLOAD_TRACKER, conf, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")
    normalized_key = str(tracker_key or "").strip() or "ip:unknown"
    reserved_count = 1 if count_event else 0
    reserved_bytes = max(0, int(projected_bytes or 0))

    with download_tracker_lock:
        if normalized_key not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[normalized_key].get("date") != today:
            DOWNLOAD_TRACKER[normalized_key] = {"count": 0, "bytes": 0, "date": today}

        tracker = DOWNLOAD_TRACKER[normalized_key]
        limit_count = conf.get("daily_download_limit") or 0
        limit_mb = conf.get("daily_bandwidth_limit_mb") or 0

        if count_event and limit_count > 0 and tracker["count"] >= limit_count:
            return False, f"Daily download limit exceeded ({limit_count})", {}

        projected_total = tracker["bytes"] + reserved_bytes
        if limit_mb > 0 and projected_total > limit_mb * 1024 * 1024:
            return False, f"Daily bandwidth limit exceeded ({limit_mb}MB)", {}

        tracker["count"] += reserved_count
        tracker["bytes"] += reserved_bytes
        from features.runtime_state import mark_download_tracker_dirty

        mark_download_tracker_dirty()

    return True, "", {"key": normalized_key, "count": reserved_count, "bytes": reserved_bytes, "date": today}




def rollback_download_quota(reservation: dict):
    """Rollback a quota reservation returned by reserve_download_quota."""
    if not reservation:
        return

    from config import DOWNLOAD_TRACKER, download_tracker_lock

    key = str(reservation.get("key", "") or "")
    if not key:
        return
    with download_tracker_lock:
        tracker = DOWNLOAD_TRACKER.get(key)
        if not tracker:
            return
        tracker["count"] = max(0, int(tracker.get("count", 0) or 0) - int(reservation.get("count", 0) or 0))
        tracker["bytes"] = max(0, int(tracker.get("bytes", 0) or 0) - int(reservation.get("bytes", 0) or 0))
        from features.runtime_state import mark_download_tracker_dirty

        mark_download_tracker_dirty()




def track_download(tracker_key: str, file_size: int, count_event: bool = True):
    """Update daily download tracker for one tracker key."""
    from config import DOWNLOAD_TRACKER, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")
    normalized_key = str(tracker_key or "").strip() or "ip:unknown"

    with download_tracker_lock:
        if normalized_key not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[normalized_key].get("date") != today:
            DOWNLOAD_TRACKER[normalized_key] = {"count": 0, "bytes": 0, "date": today}

        if count_event:
            DOWNLOAD_TRACKER[normalized_key]["count"] += 1
        DOWNLOAD_TRACKER[normalized_key]["bytes"] += int(file_size or 0)
        from features.runtime_state import mark_download_tracker_dirty

        mark_download_tracker_dirty()




def cleanup_expired_download_trackers() -> int:
    """Remove stale download tracker entries for previous dates."""
    from config import DOWNLOAD_TRACKER, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")
    expired = []

    with download_tracker_lock:
        for ip, info in list(DOWNLOAD_TRACKER.items()):
            if info.get("date") != today:
                expired.append(ip)

        for ip in expired:
            DOWNLOAD_TRACKER.pop(ip, None)
        if expired:
            from features.runtime_state import mark_download_tracker_dirty

            mark_download_tracker_dirty()

    if expired:
        logger.add(f"Expired download trackers cleaned: {len(expired)}")

    return len(expired)

