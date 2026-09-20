"""Chunked-upload session initialization."""

import os
import secrets
import shutil
from datetime import datetime, timedelta
from flask import jsonify, request, session
from config import conf, upload_session_lock, MAX_CHUNK_UPLOAD_SIZE
from utils.file_utils import validate_path, safe_filename
from utils.request_policy import ensure_mutation_allowed, ensure_path_access, parse_json_body
from security.auth import login_required
from webshare_app.services.upload_service import DEFAULT_CHUNK_SIZE, MAX_ACTIVE_UPLOAD_SESSIONS_PER_OWNER, MAX_CHUNK_SIZE, MAX_PENDING_UPLOAD_BYTES_PER_OWNER, UPLOAD_SESSIONS, _cleanup_expired_upload_sessions_locked, _get_owner_upload_pressure, _get_upload_owner_context, release_upload_disk_space, reserve_upload_disk_space
from ._common import upload_bp



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

