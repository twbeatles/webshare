"""Chunked-upload completion, cancellation, and expiry cleanup."""

import os
import shutil
import tempfile
from datetime import datetime
from flask import jsonify, session
from config import conf, upload_session_lock
from utils.log_manager import logger
from utils.file_utils import get_real_ip, fmt_bytes
from utils.request_policy import ensure_mutation_allowed, ensure_path_access
from security.auth import login_required
from features.audit_log import log_audit
from features.search_indexer import indexer
from webshare_app.services.upload_service import SAVE_IO_CHUNK_SIZE, UPLOAD_SESSIONS, _chunk_entry_path, UPLOAD_STATUS_COMPLETED, UPLOAD_STATUS_COMPLETING, _cleanup_expired_upload_sessions_locked, _cleanup_upload_session, _finish_upload_session_success, _get_upload_owner_context, _is_upload_session_owner
from ._common import upload_bp




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

