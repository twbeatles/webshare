"""
WebShare Pro - Upload Routes
Chunk upload endpoints.
"""

import os
import secrets
import shutil
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, session

from config import conf, upload_session_lock, MAX_CHUNK_UPLOAD_SIZE
from utils.log_manager import logger
from utils.file_utils import validate_path, safe_filename, get_real_ip, fmt_bytes
from utils.request_policy import ensure_path_access, parse_json_body
from security.auth import login_required
from features.audit_log import log_audit

upload_bp = Blueprint('upload', __name__)

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


# ==========================================
# Chunk upload init
# ==========================================

@upload_bp.route('/upload/chunk/init', methods=['POST'])
@login_required()
def init_chunk_upload():
    role = str(session.get('role', 'guest'))
    if role != 'admin' and not conf.get('allow_guest_upload'):
        return jsonify({'success': False, 'error': 'Upload permission denied'}), 403

    data = parse_json_body(request)
    filename = data.get('filename', '')
    total_size = data.get('total_size', 0)
    path = data.get('path', '')
    chunk_size = data.get('chunk_size', DEFAULT_CHUNK_SIZE)
    total_chunks = data.get('total_chunks')

    if not filename:
        return jsonify({'success': False, 'error': 'filename is required'}), 400

    try:
        total_size = int(total_size)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'total_size must be an integer'}), 400

    if total_size < 0:
        return jsonify({'success': False, 'error': 'total_size must be >= 0'}), 400

    if total_size > MAX_CHUNK_UPLOAD_SIZE:
        return jsonify({'success': False, 'error': f'total_size must be <= {MAX_CHUNK_UPLOAD_SIZE} bytes'}), 400

    try:
        chunk_size = int(chunk_size)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'chunk_size must be an integer'}), 400

    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        return jsonify({'success': False, 'error': f'chunk_size must be in 1..{MAX_CHUNK_SIZE}'}), 400

    if total_chunks is None:
        total_chunks = 0 if total_size == 0 else (total_size + chunk_size - 1) // chunk_size
    else:
        try:
            total_chunks = int(total_chunks)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'total_chunks must be an integer'}), 400
        if total_chunks < 0:
            return jsonify({'success': False, 'error': 'total_chunks must be >= 0'}), 400

    if total_size > 0 and total_chunks == 0:
        return jsonify({'success': False, 'error': 'total_chunks is invalid for non-empty upload'}), 400

    ok, message, status_code = ensure_path_access(path, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code

    base_dir = conf.get('folder')
    valid, target_dir, error = validate_path(base_dir, path)
    if not valid:
        return jsonify({'success': False, 'error': error}), 400

    session_id = secrets.token_urlsafe(16)
    owner_ctx = _get_upload_owner_context(role=role)

    with upload_session_lock:
        expired = _cleanup_expired_upload_sessions_locked(datetime.now())

        active_sessions, pending_bytes = _get_owner_upload_pressure(owner_ctx['owner_key'])
        if active_sessions >= MAX_ACTIVE_UPLOAD_SESSIONS_PER_OWNER:
            return jsonify({
                'success': False,
                'error': f'too many active upload sessions (max={MAX_ACTIVE_UPLOAD_SESSIONS_PER_OWNER})',
            }), 429

        if pending_bytes + total_size > MAX_PENDING_UPLOAD_BYTES_PER_OWNER:
            return jsonify({
                'success': False,
                'error': f'pending upload bytes limit exceeded (max={MAX_PENDING_UPLOAD_BYTES_PER_OWNER})',
            }), 429

        temp_dir = os.path.join(target_dir, '.upload_temp', session_id)
        os.makedirs(temp_dir, exist_ok=True)

        UPLOAD_SESSIONS[session_id] = {
            'filename': safe_filename(filename),
            'total_size': total_size,
            'chunk_size': chunk_size,
            'total_chunks': total_chunks,
            'target_dir': target_dir,
            'temp_dir': temp_dir,
            'chunks': {},
            'uploaded_bytes': 0,
            'rejected_bytes': 0,
            'created': datetime.now(),
            'updated_at': datetime.now(),
            'expires': datetime.now() + timedelta(hours=2),
            'owner_role': owner_ctx['owner_role'],
            'owner_ip': owner_ctx['owner_ip'],
            'owner_session_id': owner_ctx['owner_session_id'],
            'owner_key': owner_ctx['owner_key'],
        }

    for _, expired_temp_dir in expired:
        try:
            shutil.rmtree(expired_temp_dir, ignore_errors=True)
        except Exception:
            pass

    return jsonify({
        'success': True,
        'session_id': session_id,
        'chunk_size': chunk_size,
        'total_chunks': total_chunks,
    })


# ==========================================
# Chunk upload
# ==========================================

@upload_bp.route('/upload/chunk/<session_id>', methods=['POST'])
@login_required()
def upload_chunk(session_id):
    expired_temp_dir = ""
    owner_ctx = _get_upload_owner_context()
    temp_dir = ""
    total_chunks = 0
    chunk_size_limit = 0
    declared_total_size = 0
    current_uploaded_bytes = 0
    existing_chunk_size = 0

    with upload_session_lock:
        upload_session = UPLOAD_SESSIONS.get(session_id)
        if not upload_session:
            return jsonify({'success': False, 'error': 'invalid upload session'}), 400

        if not _is_upload_session_owner(upload_session, owner_ctx):
            return jsonify({'success': False, 'error': 'session ownership mismatch'}), 403

        if datetime.now() > upload_session['expires']:
            expired_temp_dir = upload_session.get('temp_dir', '')
        else:
            temp_dir = upload_session.get('temp_dir', '')
            total_chunks = int(upload_session.get('total_chunks', 0) or 0)
            chunk_size_limit = int(upload_session.get('chunk_size', MAX_CHUNK_SIZE) or MAX_CHUNK_SIZE)
            declared_total_size = int(upload_session.get('total_size', 0) or 0)
            current_uploaded_bytes = int(upload_session.get('uploaded_bytes', 0) or 0)

    if expired_temp_dir:
        _cleanup_upload_session(session_id, temp_dir=expired_temp_dir)
        return jsonify({'success': False, 'error': 'upload session expired'}), 400

    chunk_index = request.form.get('index', type=int)
    chunk_file = request.files.get('chunk')

    if chunk_index is None or chunk_index < 0 or not chunk_file:
        return jsonify({'success': False, 'error': 'invalid chunk payload'}), 400

    if total_chunks > 0 and chunk_index >= total_chunks:
        return jsonify({'success': False, 'error': 'chunk index out of range'}), 400

    with upload_session_lock:
        current = UPLOAD_SESSIONS.get(session_id)
        if not current:
            return jsonify({'success': False, 'error': 'invalid upload session'}), 400
        if not _is_upload_session_owner(current, owner_ctx):
            return jsonify({'success': False, 'error': 'session ownership mismatch'}), 403
        existing_entry = current.get('chunks', {}).get(chunk_index)
        existing_chunk_size = _chunk_entry_size(existing_entry)
        chunk_size_limit = int(current.get('chunk_size', chunk_size_limit) or chunk_size_limit)
        declared_total_size = int(current.get('total_size', declared_total_size) or declared_total_size)
        current_uploaded_bytes = int(current.get('uploaded_bytes', current_uploaded_bytes) or current_uploaded_bytes)
        temp_dir = current.get('temp_dir', temp_dir)

    already_accounted = max(0, current_uploaded_bytes - existing_chunk_size)
    max_total_remaining = max(0, declared_total_size - already_accounted)

    chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index:05d}')
    try:
        chunk_size = _save_chunk_with_limits(
            chunk_file=chunk_file,
            chunk_path=chunk_path,
            max_chunk_size=chunk_size_limit,
            max_total_remaining=max_total_remaining,
        )
    except ValueError as exc:
        try:
            if os.path.exists(chunk_path):
                os.remove(chunk_path)
        except Exception:
            pass
        with upload_session_lock:
            current = UPLOAD_SESSIONS.get(session_id)
            if current:
                current['rejected_bytes'] = int(current.get('rejected_bytes', 0) or 0) + max(0, max_total_remaining + 1)
        _cleanup_upload_session(session_id, temp_dir=temp_dir)
        known_error = str(exc)
        if known_error == 'chunk size exceeds declared chunk_size':
            message = 'chunk size exceeds declared chunk_size'
        elif known_error == 'uploaded bytes exceed declared total_size':
            message = 'uploaded bytes exceed declared total_size'
        else:
            message = 'invalid chunk payload'
        return jsonify({'success': False, 'error': message}), 400

    with upload_session_lock:
        current = UPLOAD_SESSIONS.get(session_id)
        if current:
            updated_uploaded = max(0, int(current.get('uploaded_bytes', 0) or 0) - existing_chunk_size + chunk_size)
            current['uploaded_bytes'] = updated_uploaded
            current['updated_at'] = datetime.now()
            current.setdefault('chunks', {})[chunk_index] = {
                'path': chunk_path,
                'size': chunk_size,
            }

    return jsonify({'success': True, 'index': chunk_index})


# ==========================================
# Chunk upload complete
# ==========================================

@upload_bp.route('/upload/chunk/<session_id>/complete', methods=['POST'])
@login_required()
def complete_chunk_upload(session_id):
    owner_ctx = _get_upload_owner_context()

    with upload_session_lock:
        upload_session = UPLOAD_SESSIONS.get(session_id)
        if not upload_session:
            return jsonify({'success': False, 'error': 'invalid upload session'}), 400

        if not _is_upload_session_owner(upload_session, owner_ctx):
            return jsonify({'success': False, 'error': 'session ownership mismatch'}), 403

        filename = upload_session['filename']
        target_dir = upload_session['target_dir']
        temp_dir = upload_session['temp_dir']
        total_size = int(upload_session.get('total_size', 0) or 0)
        total_chunks = int(upload_session.get('total_chunks', 0) or 0)
        chunks = dict(upload_session['chunks'])
        uploaded_bytes = int(upload_session.get('uploaded_bytes', 0) or 0)
        role = owner_ctx.get('owner_role', 'guest')

    target_path = ""
    try:
        if total_size > 0 and not chunks:
            _cleanup_upload_session(session_id, temp_dir=temp_dir)
            return jsonify({'success': False, 'error': 'no uploaded chunks'}), 400

        if total_chunks > 0:
            sorted_indexes = sorted(chunks.keys())
            expected_indexes = list(range(total_chunks))
            if sorted_indexes != expected_indexes:
                _cleanup_upload_session(session_id, temp_dir=temp_dir)
                return jsonify({'success': False, 'error': 'chunk set is incomplete or out of order'}), 400

        if uploaded_bytes != total_size:
            _cleanup_upload_session(session_id, temp_dir=temp_dir)
            return jsonify({
                'success': False,
                'error': f'uploaded size mismatch (expected={total_size}, uploaded={uploaded_bytes})',
            }), 400

        target_path = os.path.join(target_dir, filename)
        rel_target = os.path.relpath(target_path, conf.get('folder')).replace('\\', '/')
        ok, message, status_code = ensure_path_access(rel_target, 'write', role=role)
        if not ok:
            return jsonify({'success': False, 'error': message}), status_code

        if os.path.exists(target_path):
            name, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(target_path):
                target_path = os.path.join(target_dir, f"{name}_{counter}{ext}")
                counter += 1

        with open(target_path, 'wb') as output_file:
            for index, chunk_info in sorted(chunks.items()):
                chunk_path = _chunk_entry_path(chunk_info)
                if not chunk_path or not os.path.exists(chunk_path):
                    _cleanup_upload_session(session_id, temp_dir=temp_dir)
                    if os.path.exists(target_path):
                        os.remove(target_path)
                    return jsonify({'success': False, 'error': f'missing chunk file: {index}'}), 400

                with open(chunk_path, 'rb') as chunk_file:
                    output_file.write(chunk_file.read())

        actual_size = os.path.getsize(target_path)
        if actual_size != total_size:
            if os.path.exists(target_path):
                os.remove(target_path)
            _cleanup_upload_session(session_id, temp_dir=temp_dir)
            return jsonify({
                'success': False,
                'error': f'merged size mismatch (expected={total_size}, actual={actual_size})',
            }), 400

        _cleanup_upload_session(session_id, temp_dir=temp_dir)
        logger.add(f"Chunk upload complete: {filename}")

        log_audit(
            user=session.get('role', 'unknown'),
            action='upload_chunk_complete',
            target=os.path.basename(target_path),
            details=f"size: {fmt_bytes(total_size)}",
            ip=get_real_ip(),
        )

        return jsonify({'success': True, 'filename': os.path.basename(target_path)})

    except Exception as exc:
        if target_path and os.path.exists(target_path):
            try:
                os.remove(target_path)
            except Exception:
                pass
        _cleanup_upload_session(session_id, temp_dir=temp_dir)
        logger.add(f"Chunk complete error: {exc}", "ERROR")
        return jsonify({'success': False, 'error': 'chunk upload merge failed'}), 500


# ==========================================
# Chunk upload cancel
# ==========================================

@upload_bp.route('/upload/chunk/<session_id>/cancel', methods=['POST'])
@login_required()
def cancel_chunk_upload(session_id):
    owner_ctx = _get_upload_owner_context()

    with upload_session_lock:
        upload_session = UPLOAD_SESSIONS.get(session_id)
        if not upload_session:
            return jsonify({'success': True})

        if not _is_upload_session_owner(upload_session, owner_ctx):
            return jsonify({'success': False, 'error': 'session ownership mismatch'}), 403

    _cleanup_upload_session(session_id, temp_dir=upload_session.get('temp_dir', ''))
    return jsonify({'success': True})


def cleanup_expired_upload_sessions():
    now = datetime.now()
    with upload_session_lock:
        expired = _cleanup_expired_upload_sessions_locked(now)

    for _, temp_dir in expired:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    return len(expired)
