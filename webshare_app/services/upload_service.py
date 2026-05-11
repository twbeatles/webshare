"""Chunk upload session state and helpers."""

import os
import secrets
import shutil

from datetime import datetime
from flask import session

from config import upload_session_lock
from utils.file_utils import get_real_ip


# Chunk upload session store
UPLOAD_SESSIONS = {}
DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024
MAX_CHUNK_SIZE = 100 * 1024 * 1024
MAX_ACTIVE_UPLOAD_SESSIONS_PER_OWNER = 5
MAX_PENDING_UPLOAD_BYTES_PER_OWNER = 20 * 1024 * 1024 * 1024
SAVE_IO_CHUNK_SIZE = 1024 * 1024


def _cleanup_upload_session(session_id: str, temp_dir: str = ""):
    if temp_dir:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
    with upload_session_lock:
        UPLOAD_SESSIONS.pop(session_id, None)


def _get_upload_owner_context(role: str = "") -> dict:
    current_role = role or session.get('role', 'guest')
    owner_ip = get_real_ip()
    owner_session_id = session.get('session_id', '') or ''
    owner_key = owner_session_id or f"{current_role}:{owner_ip}"
    return {
        'owner_role': current_role,
        'owner_ip': owner_ip,
        'owner_session_id': owner_session_id,
        'owner_key': owner_key,
    }


def _is_upload_session_owner(upload_session: dict, owner_ctx: dict) -> bool:
    stored_sid = upload_session.get('owner_session_id', '') or ''
    stored_role = upload_session.get('owner_role', '') or ''
    stored_ip = upload_session.get('owner_ip', '') or ''
    stored_key = upload_session.get('owner_key', '') or ''

    current_sid = owner_ctx.get('owner_session_id', '') or ''
    current_role = owner_ctx.get('owner_role', '') or ''
    current_ip = owner_ctx.get('owner_ip', '') or ''
    current_key = owner_ctx.get('owner_key', '') or ''

    if stored_sid:
        return bool(current_sid) and secrets.compare_digest(stored_sid, current_sid) and stored_role == current_role

    if stored_key:
        return secrets.compare_digest(stored_key, current_key)

    return stored_role == current_role and stored_ip == current_ip


def _cleanup_expired_upload_sessions_locked(now: datetime) -> list:
    expired = []
    for sid, data in list(UPLOAD_SESSIONS.items()):
        if now > data.get('expires', now):
            expired.append((sid, data.get('temp_dir', '')))

    for sid, _ in expired:
        UPLOAD_SESSIONS.pop(sid, None)

    return expired


def _get_owner_upload_pressure(owner_key: str) -> tuple[int, int]:
    active_sessions = 0
    pending_bytes = 0

    for session_data in UPLOAD_SESSIONS.values():
        if (session_data.get('owner_key', '') or '') != owner_key:
            continue
        active_sessions += 1
        declared = int(session_data.get('total_size', 0) or 0)
        uploaded = int(session_data.get('uploaded_bytes', 0) or 0)
        pending_bytes += max(declared, uploaded)

    return active_sessions, pending_bytes


def _chunk_entry_size(entry) -> int:
    if isinstance(entry, dict):
        return int(entry.get('size', 0) or 0)
    if isinstance(entry, str) and os.path.exists(entry):
        try:
            return int(os.path.getsize(entry))
        except OSError:
            return 0
    return 0


def _chunk_entry_path(entry) -> str:
    if isinstance(entry, dict):
        return str(entry.get('path', '') or '')
    if isinstance(entry, str):
        return entry
    return ''


def _save_chunk_with_limits(
    chunk_file,
    chunk_path: str,
    max_chunk_size: int,
    max_total_remaining: int,
) -> int:
    """Save one chunk with hard byte limits to prevent disk exhaustion."""
    written = 0
    stream = chunk_file.stream
    try:
        stream.seek(0, os.SEEK_SET)
    except Exception:
        pass
    with open(chunk_path, 'wb') as dst:
        while True:
            data = stream.read(SAVE_IO_CHUNK_SIZE)
            if not data:
                break
            written += len(data)
            if written > max_chunk_size:
                raise ValueError('chunk size exceeds declared chunk_size')
            if written > max_total_remaining:
                raise ValueError('uploaded bytes exceed declared total_size')
            dst.write(data)
    return written
