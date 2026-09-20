"""Chunked-upload chunk reception."""

import os
from datetime import datetime
from flask import jsonify, request
from config import upload_session_lock
from utils.request_policy import ensure_mutation_allowed
from security.auth import login_required
from webshare_app.services.upload_service import MAX_CHUNK_SIZE, UPLOAD_SESSIONS, _chunk_entry_size, _cleanup_upload_session, _get_upload_owner_context, _is_upload_session_owner, _save_chunk_with_limits
from ._common import upload_bp




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

