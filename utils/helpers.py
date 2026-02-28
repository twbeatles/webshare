"""
WebShare Pro - Helper Functions
"""

from __future__ import annotations

import os
import re
import shutil
from datetime import datetime

from config import MAX_VERSIONS, RECENT_FILES, VERSION_FOLDER_NAME, conf, recent_files_lock
from utils.log_manager import logger


def add_recent_file(path: str, name: str, file_type: str = "file"):
    """Add a recently accessed file entry (deduplicated, max 20)."""
    with recent_files_lock:
        for index, item in enumerate(RECENT_FILES):
            if item.get("path") == path:
                RECENT_FILES.pop(index)
                break

        RECENT_FILES.insert(
            0,
            {
                "path": path,
                "name": name,
                "type": file_type,
                "accessed": datetime.now().isoformat(),
            },
        )

        while len(RECENT_FILES) > 20:
            RECENT_FILES.pop()


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
    safe_name = rel_path.replace(os.sep, "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    version_name = f"{timestamp}_{safe_name}"
    version_path = os.path.join(version_dir, version_name)

    try:
        shutil.copy2(file_path, version_path)
        logger.add(f"Version backup created: {rel_path}")
        cleanup_old_versions(version_dir, safe_name)
    except Exception as exc:
        logger.add(f"Version backup failed: {exc}", "ERROR")


def cleanup_old_versions(version_dir: str, base_name: str):
    """Remove old version files beyond MAX_VERSIONS."""
    try:
        pattern = re.compile(r"^\d{8}_\d{6}_" + re.escape(base_name) + r"$")
        versions = sorted(
            [file_name for file_name in os.listdir(version_dir) if pattern.match(file_name)],
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


def check_download_limit(ip: str) -> tuple[bool, str]:
    """Check daily download count/bytes limits for an IP."""
    from config import DOWNLOAD_TRACKER, conf, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")

    with download_tracker_lock:
        if ip not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[ip].get("date") != today:
            DOWNLOAD_TRACKER[ip] = {"count": 0, "bytes": 0, "date": today}

        tracker = DOWNLOAD_TRACKER[ip]
        limit_count = conf.get("daily_download_limit") or 0
        limit_mb = conf.get("daily_bandwidth_limit_mb") or 0

        if limit_count > 0 and tracker["count"] >= limit_count:
            return False, f"Daily download limit exceeded ({limit_count})"

        if limit_mb > 0 and tracker["bytes"] >= limit_mb * 1024 * 1024:
            return False, f"Daily bandwidth limit exceeded ({limit_mb}MB)"

    return True, ""


def track_download(ip: str, file_size: int):
    """Update daily download tracker for an IP."""
    from config import DOWNLOAD_TRACKER, download_tracker_lock

    today = datetime.now().strftime("%Y-%m-%d")

    with download_tracker_lock:
        if ip not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[ip].get("date") != today:
            DOWNLOAD_TRACKER[ip] = {"count": 0, "bytes": 0, "date": today}

        DOWNLOAD_TRACKER[ip]["count"] += 1
        DOWNLOAD_TRACKER[ip]["bytes"] += int(file_size or 0)


def cleanup_expired_download_trackers() -> int:
    """Remove per-IP download tracker entries for previous dates."""
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
        logger.add(f"Expired download trackers cleaned: {len(expired)}")

    return len(expired)
