"""
WebShare Pro - Upload Routes
Chunk upload endpoints.
"""

import os
import secrets
import shutil
import tempfile
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, session

from config import conf, upload_session_lock, MAX_CHUNK_UPLOAD_SIZE
from utils.log_manager import logger
from utils.file_utils import validate_path, safe_filename, get_real_ip, fmt_bytes
from utils.request_policy import ensure_mutation_allowed, ensure_path_access, parse_json_body
from security.auth import login_required
from features.audit_log import log_audit
from features.search_indexer import indexer

upload_bp = Blueprint('upload', __name__)

from webshare_app.services.upload_service import (
    DEFAULT_CHUNK_SIZE,
    MAX_ACTIVE_UPLOAD_SESSIONS_PER_OWNER,
    MAX_CHUNK_SIZE,
    MAX_PENDING_UPLOAD_BYTES_PER_OWNER,
    SAVE_IO_CHUNK_SIZE,
    UPLOAD_SESSIONS,
    _chunk_entry_path,
    _chunk_entry_size,
    UPLOAD_STATUS_COMPLETED,
    UPLOAD_STATUS_COMPLETING,
    _cleanup_expired_upload_sessions_locked,
    _cleanup_upload_session,
    _finish_upload_session_success,
    _get_owner_upload_pressure,
    _get_upload_owner_context,
    _is_upload_session_owner,
    _save_chunk_with_limits,
    release_upload_disk_space,
    reserve_upload_disk_space,
)

# ==========================================
# Chunk upload init
# ==========================================

@upload_bp.route('/upload/chunk/init', methods=['POST'])
@login_required()
def init_chunk_upload():
    role = str(session.get('role', 'guest'))
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'success': False, 'error': message}), status_code

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

        disk_ok, disk_error, disk_reservation_id = reserve_upload_disk_space(
            target_dir,
            total_size,
            reservation_id=f"chunk:{session_id}",
        )
        if not disk_ok:
            return jsonify({'success': False, 'error': disk_error}), 507

        temp_dir = os.path.join(target_dir, '.upload_temp', session_id)
        try:
            os.makedirs(temp_dir, exist_ok=True)
        except Exception:
            release_upload_disk_space(disk_reservation_id)
            raise

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
            'disk_reservation_id': disk_reservation_id,
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

    allowed, message, status_code = ensure_mutation_allowed(owner_ctx.get('owner_role', 'guest'))
    if not allowed:
        _cleanup_upload_session(session_id, temp_dir=temp_dir)
        return jsonify({'success': False, 'error': message}), status_code

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

        status = str(upload_session.get('status', 'active') or 'active')
        if status == UPLOAD_STATUS_COMPLETED:
            return jsonify({
                'success': True,
                'filename': upload_session.get('committed_filename', upload_session.get('filename', '')),
                'idempotent': True,
            })
        if status == UPLOAD_STATUS_COMPLETING:
            return jsonify({'success': False, 'error': 'upload already completing'}), 409

        upload_session['status'] = UPLOAD_STATUS_COMPLETING

        filename = upload_session['filename']
        target_dir = upload_session['target_dir']
        temp_dir = upload_session['temp_dir']
        total_size = int(upload_session.get('total_size', 0) or 0)
        total_chunks = int(upload_session.get('total_chunks', 0) or 0)
        chunks = dict(upload_session.get('chunks', {}))
        uploaded_bytes = int(upload_session.get('uploaded_bytes', 0) or 0)
        role = owner_ctx.get('owner_role', 'guest')

    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        _cleanup_upload_session(session_id, temp_dir=temp_dir)
        return jsonify({'success': False, 'error': message}), status_code

    target_path = ""
    merge_temp_path = ""
    committed = False
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
            _cleanup_upload_session(session_id, temp_dir=temp_dir)
            return jsonify({'success': False, 'error': message}), status_code

        if os.path.exists(target_path):
            name, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(target_path):
                target_path = os.path.join(target_dir, f"{name}_{counter}{ext}")
                counter += 1

        for index, chunk_info in sorted(chunks.items()):
            chunk_path = _chunk_entry_path(chunk_info)
            if not chunk_path or not os.path.exists(chunk_path):
                _cleanup_upload_session(session_id, temp_dir=temp_dir)
                return jsonify({'success': False, 'error': f'missing chunk file: {index}'}), 400

        fd, merge_temp_path = tempfile.mkstemp(dir=target_dir, prefix=".webshare_merge_", suffix=".tmp")
        with os.fdopen(fd, 'wb') as output_file:
            for index, chunk_info in sorted(chunks.items()):
                chunk_path = _chunk_entry_path(chunk_info)
                if not chunk_path or not os.path.exists(chunk_path):
                    raise FileNotFoundError(f'missing chunk file: {index}')

                with open(chunk_path, 'rb') as chunk_file:
                    shutil.copyfileobj(chunk_file, output_file, length=SAVE_IO_CHUNK_SIZE)

        actual_size = os.path.getsize(merge_temp_path)
        if actual_size != total_size:
            if os.path.exists(merge_temp_path):
                os.remove(merge_temp_path)
            _cleanup_upload_session(session_id, temp_dir=temp_dir)
            return jsonify({
                'success': False,
                'error': f'merged size mismatch (expected={total_size}, actual={actual_size})',
            }), 400

        os.replace(merge_temp_path, target_path)
        committed = True

        committed_name = os.path.basename(target_path)
        _finish_upload_session_success(
            session_id,
            temp_dir=temp_dir,
            committed_filename=committed_name,
        )
        logger.add(f"Chunk upload complete: {filename}")
        try:
            indexer.update_event(conf.get('folder'))
        except Exception as exc:
            logger.add(f"Chunk upload index refresh failed: {exc}", "WARN")

        try:
            log_audit(
                user=session.get('role', 'unknown'),
                action='upload_chunk_complete',
                target=os.path.basename(target_path),
                details=f"size: {fmt_bytes(total_size)}",
                ip=get_real_ip(),
            )
        except Exception as exc:
            logger.add(f"Chunk upload audit log failed: {exc}", "WARN")

        return jsonify({'success': True, 'filename': committed_name})

    except Exception as exc:
        if 'merge_temp_path' in locals() and merge_temp_path and os.path.exists(merge_temp_path):
            try:
                os.remove(merge_temp_path)
            except Exception:
                pass
        if committed:
            logger.add(f"Chunk upload committed before post-processing failure: {target_path}", "WARN")
            _finish_upload_session_success(
                session_id,
                temp_dir=temp_dir,
                committed_filename=os.path.basename(target_path),
            )
        else:
            with upload_session_lock:
                current = UPLOAD_SESSIONS.get(session_id)
                if current and current.get('status') == UPLOAD_STATUS_COMPLETING:
                    current['status'] = 'active'
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

    allowed, message, status_code = ensure_mutation_allowed(owner_ctx.get('owner_role', 'guest'))
    if not allowed:
        return jsonify({'success': False, 'error': message}), status_code

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
