"""Chunk upload session state and helpers."""

import os
import secrets
import shutil
import threading
import uuid

from datetime import datetime, timedelta
from flask import session

from config import upload_session_lock
from utils.file_utils import get_real_ip


# Chunk upload session store
UPLOAD_SESSIONS = {}
DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024
MAX_CHUNK_SIZE = 100 * 1024 * 1024
MAX_ACTIVE_UPLOAD_SESSIONS_PER_OWNER = 5
MAX_PENDING_UPLOAD_BYTES_PER_OWNER = 20 * 1024 * 1024 * 1024
UPLOAD_FREE_SPACE_BUFFER_BYTES = 100 * 1024 * 1024
SAVE_IO_CHUNK_SIZE = 1024 * 1024
UPLOAD_SESSION_COMPLETED_TTL = timedelta(minutes=30)
UPLOAD_STATUS_ACTIVE = "active"
UPLOAD_STATUS_COMPLETING = "completing"
UPLOAD_STATUS_COMPLETED = "completed"

_disk_reservation_lock = threading.Lock()
_disk_reservations: dict[str, dict[str, str | int]] = {}


def reset_upload_runtime_state():
    with upload_session_lock:
        UPLOAD_SESSIONS.clear()
    with _disk_reservation_lock:
        _disk_reservations.clear()


def _reservation_scope(directory: str) -> str:
    return os.path.abspath(directory or ".")


def _reserved_bytes_for_scope(scope: str) -> int:
    total = 0
    for reservation in _disk_reservations.values():
        if reservation.get("scope") == scope:
            raw_bytes = reservation.get("bytes", 0)
            total += raw_bytes if isinstance(raw_bytes, int) else int(raw_bytes or 0)
    return total


def estimate_file_storage_size(file_storage) -> int:
    content_length = int(getattr(file_storage, "content_length", 0) or 0)
    if content_length > 0:
        return content_length

    stream = getattr(file_storage, "stream", None)
    if stream is None:
        return 0

    try:
        current_pos = stream.tell()
        stream.seek(0, os.SEEK_END)
        end_pos = stream.tell()
        stream.seek(current_pos, os.SEEK_SET)
        return max(0, int(end_pos) - int(current_pos))
    except Exception:
        try:
            stream.seek(0, os.SEEK_SET)
        except Exception:
            pass
    return 0


def reserve_upload_disk_space(directory: str, required_bytes: int, reservation_id: str = "") -> tuple[bool, str, str]:
    required = max(0, int(required_bytes or 0))
    if required <= 0:
        return True, "", ""

    scope = _reservation_scope(directory)
    reservation_key = reservation_id or f"upload-{uuid.uuid4().hex}"
    try:
        free_bytes = int(shutil.disk_usage(scope).free)
    except Exception as exc:
        return False, f"디스크 여유 공간 확인 실패: {exc}", ""

    with _disk_reservation_lock:
        reserved = _reserved_bytes_for_scope(scope)
        needed = required + UPLOAD_FREE_SPACE_BUFFER_BYTES
        if reserved + needed > free_bytes:
            return (
                False,
                "디스크 여유 공간이 부족합니다.",
                "",
            )
        _disk_reservations[reservation_key] = {"scope": scope, "bytes": required}

    return True, "", reservation_key


def release_upload_disk_space(reservation_id: str):
    if not reservation_id:
        return
    with _disk_reservation_lock:
        _disk_reservations.pop(reservation_id, None)


def _finish_upload_session_success(session_id: str, *, temp_dir: str, committed_filename: str):
    reservation_id = ""
    with upload_session_lock:
        upload_session = UPLOAD_SESSIONS.get(session_id)
        if not upload_session:
            return
        upload_session["status"] = UPLOAD_STATUS_COMPLETED
        upload_session["committed_filename"] = committed_filename
        upload_session["expires"] = datetime.now() + UPLOAD_SESSION_COMPLETED_TTL
        upload_session.pop("chunks", None)
        reservation_id = str(upload_session.get("disk_reservation_id", "") or "")
        upload_session.pop("disk_reservation_id", None)
    release_upload_disk_space(reservation_id)
    if temp_dir:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


def _cleanup_upload_session(session_id: str, temp_dir: str = ""):
    if temp_dir:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
    reservation_id = ""
    with upload_session_lock:
        upload_session = UPLOAD_SESSIONS.pop(session_id, None)
        if isinstance(upload_session, dict):
            reservation_id = str(upload_session.get('disk_reservation_id', '') or '')
    release_upload_disk_space(reservation_id)


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
        upload_session = UPLOAD_SESSIONS.pop(sid, None)
        if isinstance(upload_session, dict):
            release_upload_disk_space(str(upload_session.get('disk_reservation_id', '') or ''))

    return expired


def _get_owner_upload_pressure(owner_key: str) -> tuple[int, int]:
    active_sessions = 0
    pending_bytes = 0

    for session_data in UPLOAD_SESSIONS.values():
        if (session_data.get('owner_key', '') or '') != owner_key:
            continue
        if session_data.get("status") == UPLOAD_STATUS_COMPLETED:
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
