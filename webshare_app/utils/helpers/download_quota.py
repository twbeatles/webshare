"""Daily download quota checks, reservations, and tracking."""

from __future__ import annotations
from datetime import datetime
from utils.log_manager import logger


# Quota fairness policy: reservations conservatively hold the full
# projected size up front so concurrent downloads cannot overshoot the
# daily limits. When a stream closes, the reservation is settled down to
# the bytes actually delivered (see settle_download_quota); an aborted
# transfer therefore refunds the unsent remainder. This note is appended
# to limit messages so the policy is visible wherever a 429 surfaces.
# Direct (non-settled) paths use QUOTA_DIRECT_NOTE instead; see _direct_message.
# send_file 단건/미디어 스트림은 스트림 종료 훅이 없어 중단 시에도 전액 예약을
# 유지한다. 이 경로의 429에는 실제 전송 바이트 약속 대신 아래 문구를 쓴다.
QUOTA_DIRECT_NOTE = (
    "Single-file and media-stream downloads hold the full-size reservation"
    " for the transfer; an interrupted download may still count the reserved"
    " amount toward the quota."
)


QUOTA_POLICY_NOTE = (
    "Interrupted downloads are settled by actual bytes transferred;"
    " only delivered bytes count toward the quota."
)


def _limit_message(base: str, *, direct_hold: bool = False) -> str:
    """Append the quota fairness policy note to a limit message."""
    return f"{base}. {(QUOTA_DIRECT_NOTE if direct_hold else QUOTA_POLICY_NOTE)}"


def _direct_message(message: str) -> str:
    """Swap a settled-stream note for the hold-full note on direct paths."""
    if QUOTA_POLICY_NOTE in message:
        return message.replace(QUOTA_POLICY_NOTE, QUOTA_DIRECT_NOTE)
    if QUOTA_DIRECT_NOTE not in message:
        return f"{message}. {QUOTA_DIRECT_NOTE}"
    return message


def build_quota_key_set(session_id: str = "", ip: str = "") -> list:
    """Return the tracker keys (session + ip, deduplicated) for one client."""
    keys = []
    primary = build_download_tracker_key(session_id, ip)
    if primary not in keys:
        keys.append(primary)
    ip_key = build_download_tracker_key("", ip, prefer_session=False)
    if ip_key not in keys:
        keys.append(ip_key)
    return keys


def _combined_usage_locked(keys: list, today: str) -> tuple:
    """Highest count/bytes across the client's keys. Caller must hold download_tracker_lock.

    Every combined reservation charges all keys of the client (session and
    ip), so each key already holds the client's full usage; the maximum is
    the client's usage. A fresh session after re-login starts at zero but
    the ip key still carries the day's usage, so re-login cannot reset the
    daily limit (audit ISSUE-008).
    """
    from config import DOWNLOAD_TRACKER

    max_count = 0
    max_bytes = 0
    for key in keys:
        tracker = DOWNLOAD_TRACKER.get(key)
        if tracker and tracker.get("date") == today:
            max_count = max(max_count, int(tracker.get("count", 0) or 0))
            max_bytes = max(max_bytes, int(tracker.get("bytes", 0) or 0))
    return max_count, max_bytes


def _reservation_keys(reservation: dict) -> list:
    keys = reservation.get("keys")
    if isinstance(keys, (list, tuple)) and keys:
        return [str(k) for k in keys if k]
    key = str(reservation.get("key", "") or "")
    return [key] if key else []


def check_combined_download_limit(session_id: str = "", ip: str = "", count_event: bool = True,
                                 projected_bytes: int = 0, *, direct_hold: bool = False,
                                 prefer_session: bool = True) -> tuple:
    """Check daily limits against the combined session+ip usage.

    A logged-in client downloading through both the authenticated and the
    share-link paths must not get two independent budgets: the sum across
    both buckets is enforced here.
    """
    from webshare_app.utils import helpers as _helpers_pkg

    primary = build_download_tracker_key(session_id, ip, prefer_session=prefer_session)
    allowed, message = _helpers_pkg.check_download_limit(primary, count_event, projected_bytes=projected_bytes)
    if not allowed:
        return False, _direct_message(message) if direct_hold else message

    from config import DOWNLOAD_TRACKER, conf, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")
    reserved_bytes = max(0, int(projected_bytes or 0))
    with download_tracker_lock:
        total_count, total_bytes = _combined_usage_locked(build_quota_key_set(session_id, ip), today)
        limit_count = conf.get("daily_download_limit") or 0
        limit_mb = conf.get("daily_bandwidth_limit_mb") or 0
        if count_event and limit_count > 0 and total_count + 1 > limit_count:
            return False, _limit_message(f"Daily download limit exceeded ({limit_count})", direct_hold=direct_hold)
        if limit_mb > 0 and total_bytes + reserved_bytes > limit_mb * 1024 * 1024:
            return False, _limit_message(f"Daily bandwidth limit exceeded ({limit_mb}MB)", direct_hold=direct_hold)
    return True, ""


def reserve_combined_download_quota(session_id: str = "", ip: str = "", count_event: bool = True,
                                    projected_bytes: int = 0, *, direct_hold: bool = False,
                                 prefer_session: bool = True) -> tuple:
    """Reserve one quota unit on every key of the client (session + ip).

    The cap is checked against the client's usage (the highest key usage,
    see _combined_usage_locked) and the reservation is charged to all keys,
    so neither a re-login nor switching between the authenticated and the
    share-link path opens a fresh daily budget.
    """
    from webshare_app.utils import helpers as _helpers_pkg

    primary = build_download_tracker_key(session_id, ip, prefer_session=prefer_session)
    allowed, message = _helpers_pkg.check_download_limit(primary, count_event, projected_bytes=projected_bytes)
    if not allowed:
        return False, _direct_message(message) if direct_hold else message, {}

    from config import DOWNLOAD_TRACKER, conf, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")
    reserved_count = 1 if count_event else 0
    reserved_bytes = max(0, int(projected_bytes or 0))
    with download_tracker_lock:
        keys = build_quota_key_set(session_id, ip)
        total_count, total_bytes = _combined_usage_locked(keys, today)
        limit_count = conf.get("daily_download_limit") or 0
        limit_mb = conf.get("daily_bandwidth_limit_mb") or 0
        if count_event and limit_count > 0 and total_count + 1 > limit_count:
            return False, _limit_message(f"Daily download limit exceeded ({limit_count})", direct_hold=direct_hold), {}
        if limit_mb > 0 and total_bytes + reserved_bytes > limit_mb * 1024 * 1024:
            return False, _limit_message(f"Daily bandwidth limit exceeded ({limit_mb}MB)", direct_hold=direct_hold), {}

        charged = [primary] + [key for key in keys if key != primary]
        for key in charged:
            if key not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[key].get("date") != today:
                DOWNLOAD_TRACKER[key] = {"count": 0, "bytes": 0, "date": today}
            tracker = DOWNLOAD_TRACKER[key]
            tracker["count"] += reserved_count
            tracker["bytes"] += reserved_bytes
        from features.runtime_state import mark_download_tracker_dirty

        mark_download_tracker_dirty()
    return True, "", {"key": primary, "keys": charged, "count": reserved_count,
                      "bytes": reserved_bytes, "date": today}




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
            return False, _limit_message(f"Daily download limit exceeded ({limit_count})")

        projected_total = tracker["bytes"] + max(0, int(projected_bytes or 0))
        if limit_mb > 0 and projected_total > limit_mb * 1024 * 1024:
            return False, _limit_message(f"Daily bandwidth limit exceeded ({limit_mb}MB)")

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
            return False, _limit_message(f"Daily download limit exceeded ({limit_count})"), {}

        projected_total = tracker["bytes"] + reserved_bytes
        if limit_mb > 0 and projected_total > limit_mb * 1024 * 1024:
            return False, _limit_message(f"Daily bandwidth limit exceeded ({limit_mb}MB)"), {}

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

    keys = _reservation_keys(reservation)
    if not keys:
        return
    with download_tracker_lock:
        changed = False
        for key in keys:
            tracker = DOWNLOAD_TRACKER.get(key)
            if not tracker:
                continue
            tracker["count"] = max(0, int(tracker.get("count", 0) or 0) - int(reservation.get("count", 0) or 0))
            tracker["bytes"] = max(0, int(tracker.get("bytes", 0) or 0) - int(reservation.get("bytes", 0) or 0))
            changed = True
        if changed:
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



def settle_download_quota(reservation: dict, actual_bytes=None):
    """Settle a reservation down to the bytes actually delivered.

    Reservations conservatively hold the full projected size up front.
    Call this from the streaming-close path with the delivered byte
    count to refund the undelivered remainder (range requests, client
    aborts, empty 304/416 answers). The download count is kept because
    the request happened; only bytes are adjusted, and the settlement
    never charges extra when actual exceeds the projection.
    """
    if not reservation or actual_bytes is None:
        return
    try:
        actual = max(0, int(actual_bytes))
    except (TypeError, ValueError):
        return

    from config import DOWNLOAD_TRACKER, download_tracker_lock

    keys = _reservation_keys(reservation)
    if not keys:
        return
    refund = max(0, int(reservation.get("bytes", 0) or 0)) - actual
    if refund <= 0:
        return
    with download_tracker_lock:
        changed = False
        for key in keys:
            tracker = DOWNLOAD_TRACKER.get(key)
            if not tracker:
                continue
            tracker["bytes"] = max(0, int(tracker.get("bytes", 0) or 0) - refund)
            changed = True
        if changed:
            from features.runtime_state import mark_download_tracker_dirty

            mark_download_tracker_dirty()

