"""Expiry cleanup for sessions, share links, and upload temp dirs."""

from __future__ import annotations
import os
import shutil
from datetime import datetime
from config import conf
from utils.log_manager import logger




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

