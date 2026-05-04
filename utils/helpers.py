"""
WebShare Pro - Helper Functions
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import tempfile
from datetime import datetime

from config import MAX_VERSIONS, RECENT_FILES, VERSION_FOLDER_NAME, conf, recent_files_lock
from utils.log_manager import logger


def build_recent_owner_key(session_id: str = "", role: str = "guest", ip: str = "") -> str:
    owner_sid = str(session_id or "").strip()
    if owner_sid:
        return owner_sid
    return f"{role}:{ip}"


def build_download_tracker_key(session_id: str = "", ip: str = "", *, prefer_session: bool = True) -> str:
    normalized_sid = str(session_id or "").strip()
    normalized_ip = str(ip or "").strip()
    if prefer_session and normalized_sid:
        return f"session:{normalized_sid}"
    return f"ip:{normalized_ip or 'unknown'}"


def add_recent_file(path: str, name: str, file_type: str = "file", owner_key: str = ""):
    """Add a recently accessed file entry for one session/owner."""
    if not owner_key:
        return

    with recent_files_lock:
        owner_entries = RECENT_FILES.setdefault(owner_key, [])

        for index, item in enumerate(owner_entries):
            if item.get("path") == path:
                owner_entries.pop(index)
                break

        owner_entries.insert(
            0,
            {
                "path": path,
                "name": name,
                "type": file_type,
                "accessed": datetime.now().isoformat(),
            },
        )

        while len(owner_entries) > 20:
            owner_entries.pop()


def get_recent_files(owner_key: str) -> list[dict]:
    with recent_files_lock:
        return list(RECENT_FILES.get(owner_key, [])[:20])


def create_file_version(file_path: str):
    """Create an automatic version backup for a file."""
    if not conf.get("enable_versioning"):
        return

    if not os.path.exists(file_path):
        return

    base_dir = conf.get("folder")
    version_dir = os.path.join(base_dir, VERSION_FOLDER_NAME)
    os.makedirs(version_dir, exist_ok=True)

    rel_path = os.path.relpath(file_path, base_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    version_name = build_version_filename(rel_path, timestamp=timestamp)
    version_path = os.path.join(version_dir, version_name)

    try:
        shutil.copy2(file_path, version_path)
        logger.add(f"Version backup created: {rel_path}")
        cleanup_old_versions(version_dir, rel_path)
    except Exception as exc:
        logger.add(f"Version backup failed: {exc}", "ERROR")


def _legacy_version_rel_key(rel_path: str) -> str:
    return rel_path.replace(os.sep, "_").replace("/", "_")


def _encode_version_rel_path(rel_path: str) -> str:
    normalized = rel_path.replace("\\", "/")
    encoded = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _decode_version_rel_path(value: str) -> str | None:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode((value + padding).encode("ascii")).decode("utf-8")
    except Exception:
        return None
    return decoded.replace("\\", "/")


def build_version_filename(rel_path: str, *, timestamp: str | None = None) -> str:
    normalized = rel_path.replace("\\", "/")
    basename = os.path.basename(normalized)
    encoded_rel_path = _encode_version_rel_path(normalized)
    prefix = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}__{encoded_rel_path}__{basename}"


def version_name_matches_rel_path(version_name: str, rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    if "__" in version_name:
        parts = version_name.split("__", 2)
        if len(parts) == 3:
            _, encoded_rel_path, basename = parts
            decoded_rel_path = _decode_version_rel_path(encoded_rel_path)
            return (
                decoded_rel_path == normalized
                and basename == os.path.basename(normalized)
            )

    prefix = f"{version_name[:15]}_"
    if len(version_name) > len(prefix):
        suffix = version_name[len(prefix):]
        return suffix == _legacy_version_rel_key(normalized)
    return False


def cleanup_old_versions(version_dir: str, rel_path: str):
    """Remove old version files beyond MAX_VERSIONS."""
    try:
        normalized = rel_path.replace("\\", "/")
        legacy_name = _legacy_version_rel_key(normalized)
        versions = sorted(
            [
                file_name
                for file_name in os.listdir(version_dir)
                if version_name_matches_rel_path(file_name, normalized)
                or re.match(r"^\d{8}_\d{6}_" + re.escape(legacy_name) + r"$", file_name)
            ],
            reverse=True,
        )

        for old_version in versions[MAX_VERSIONS:]:
            os.remove(os.path.join(version_dir, old_version))
    except Exception:
        pass


def cleanup_expired_sessions() -> int:
    """Remove expired login sessions based on configured timeout."""
    from config import ACTIVE_SESSIONS, conf, session_lock

    now = datetime.now()
    timeout_minutes = conf.get("session_timeout") or 60
    expired = []

    with session_lock:
        for sid, info in list(ACTIVE_SESSIONS.items()):
            last_active = info.get("last_active")
            if not last_active:
                continue

            if isinstance(last_active, str):
                try:
                    last_active = datetime.fromisoformat(last_active)
                except ValueError:
                    expired.append(sid)
                    continue

            age_minutes = (now - last_active).total_seconds() / 60
            if age_minutes > timeout_minutes:
                expired.append(sid)

        for sid in expired:
            ACTIVE_SESSIONS.pop(sid, None)

    if expired:
        logger.add(f"Expired sessions cleaned: {len(expired)}")
    return len(expired)


def cleanup_expired_share_links() -> int:
    """Remove expired share links and persist when changed."""
    from config import SHARE_LINKS, share_links_lock

    now = datetime.now()
    expired = []

    with share_links_lock:
        for token, info in list(SHARE_LINKS.items()):
            expires = info.get("expires")
            if expires and now > expires:
                expired.append(token)

        for token in expired:
            SHARE_LINKS.pop(token, None)

    if expired:
        try:
            from features.share_links_store import save_share_links

            save_share_links()
        except Exception:
            pass
        logger.add(f"Expired share links cleaned: {len(expired)}")

    return len(expired)


def cleanup_upload_temp_dirs(base_dir: str | None = None) -> int:
    """
    Remove stale upload temp directories created by chunk uploads.

    Targets:
    - legacy: .webshare_uploads (under shared root)
    - current: any .upload_temp directory recursively under shared root
    """
    target_root = base_dir or conf.get("folder")
    if not target_root or not os.path.isdir(target_root):
        return 0

    removed_count = 0

    legacy_temp = os.path.join(target_root, ".webshare_uploads")
    if os.path.isdir(legacy_temp):
        shutil.rmtree(legacy_temp, ignore_errors=True)
        removed_count += 1

    for walk_root, dirs, _ in os.walk(target_root):
        if ".upload_temp" not in dirs:
            continue

        temp_dir = os.path.join(walk_root, ".upload_temp")
        shutil.rmtree(temp_dir, ignore_errors=True)
        dirs.remove(".upload_temp")
        removed_count += 1

    if removed_count > 0:
        logger.add(f"Startup upload-temp cleanup: {removed_count} directories")

    return removed_count


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
    allowed, message = check_download_limit(tracker_key, count_event, projected_bytes=projected_bytes)
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


def atomic_write_bytes(path: str, payload: bytes):
    """Write bytes atomically in the destination directory."""
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_write_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def atomic_save_upload(file_storage, path: str):
    """Save a Werkzeug FileStorage object through a same-directory temp file."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_upload_", suffix=".tmp")
    try:
        try:
            file_storage.stream.seek(0, os.SEEK_SET)
        except Exception:
            pass
        with os.fdopen(fd, "wb") as handle:
            shutil.copyfileobj(file_storage.stream, handle, length=1024 * 1024)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def atomic_copy_file(src: str, dst: str):
    """Copy a file to a temp file in the destination directory, then replace."""
    directory = os.path.dirname(dst) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_copy_", suffix=".tmp")
    os.close(fd)
    try:
        shutil.copy2(src, temp_path)
        os.replace(temp_path, dst)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise
