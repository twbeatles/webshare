"""
WebShare Pro - Upload Routes
청크 업로드 시스템
"""

import os
import secrets
import shutil
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, session

from config import conf, upload_session_lock
from utils.log_manager import logger
from utils.file_utils import validate_path, safe_filename, get_real_ip, fmt_bytes
from utils.request_policy import ensure_path_access, parse_json_body
from security.auth import login_required
from features.audit_log import log_audit

upload_bp = Blueprint('upload', __name__)

# 청크 업로드 세션 저장소
UPLOAD_SESSIONS = {}
DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024
MAX_CHUNK_SIZE = 100 * 1024 * 1024


def _cleanup_upload_session(session_id: str, temp_dir: str = ""):
    if temp_dir:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
    with upload_session_lock:
        if session_id in UPLOAD_SESSIONS:
            UPLOAD_SESSIONS.pop(session_id, None)


# ==========================================
# 청크 업로드 시작
# ==========================================

@upload_bp.route('/upload/chunk/init', methods=['POST'])
@login_required()
def init_chunk_upload():
    """청크 업로드 초기화"""
    role = session.get('role')
    if role != 'admin' and not conf.get('allow_guest_upload'):
        return jsonify({'success': False, 'error': '업로드 권한이 없습니다'}), 403
    
    data = parse_json_body(request)
    filename = data.get('filename', '')
    total_size = data.get('total_size', 0)
    path = data.get('path', '')
    chunk_size = data.get('chunk_size', DEFAULT_CHUNK_SIZE)
    total_chunks = data.get('total_chunks')
    
    if not filename:
        return jsonify({'success': False, 'error': '파일명이 필요합니다'}), 400
    try:
        total_size = int(total_size)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'total_size는 정수여야 합니다'}), 400
    if total_size < 0:
        return jsonify({'success': False, 'error': 'total_size는 0 이상이어야 합니다'}), 400

    try:
        chunk_size = int(chunk_size)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'chunk_size는 정수여야 합니다'}), 400
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        return jsonify({'success': False, 'error': f'chunk_size는 1~{MAX_CHUNK_SIZE} 범위여야 합니다'}), 400

    if total_chunks is None:
        total_chunks = 0 if total_size == 0 else (total_size + chunk_size - 1) // chunk_size
    else:
        try:
            total_chunks = int(total_chunks)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'total_chunks는 정수여야 합니다'}), 400
        if total_chunks < 0:
            return jsonify({'success': False, 'error': 'total_chunks는 0 이상이어야 합니다'}), 400
    if total_size > 0 and total_chunks == 0:
        return jsonify({'success': False, 'error': 'total_chunks가 유효하지 않습니다'}), 400

    ok, message, status_code = ensure_path_access(path, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    
    # 경로 검증
    base_dir = conf.get('folder')
    valid, target_dir, error = validate_path(base_dir, path)
    if not valid:
        return jsonify({'success': False, 'error': error}), 400
    
    # 세션 ID 생성
    session_id = secrets.token_urlsafe(16)
    
    # 임시 디렉토리 생성
    temp_dir = os.path.join(target_dir, '.upload_temp', session_id)
    os.makedirs(temp_dir, exist_ok=True)
    
    with upload_session_lock:
        UPLOAD_SESSIONS[session_id] = {
            'filename': safe_filename(filename),
            'total_size': total_size,
            'chunk_size': chunk_size,
            'total_chunks': total_chunks,
            'target_dir': target_dir,
            'temp_dir': temp_dir,
            'chunks': {},
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(hours=2)
        }
    
    return jsonify({
        'success': True,
        'session_id': session_id,
        'chunk_size': chunk_size,
        'total_chunks': total_chunks,
    })


# ==========================================
# 청크 업로드
# ==========================================

@upload_bp.route('/upload/chunk/<session_id>', methods=['POST'])
@login_required()
def upload_chunk(session_id):
    """청크 업로드"""
    # 락 내에서 필요한 정보를 복사 (레이스 컨디션 방지)
    expired_temp_dir = ""
    with upload_session_lock:
        if session_id not in UPLOAD_SESSIONS:
            return jsonify({'success': False, 'error': '유효하지 않은 세션입니다'}), 400
        
        upload_session = UPLOAD_SESSIONS[session_id]
        
        if datetime.now() > upload_session['expires']:
            expired_temp_dir = upload_session.get('temp_dir', '')
        else:
            # 락 외부에서 사용할 정보 복사
            temp_dir = upload_session['temp_dir']
            total_chunks = int(upload_session.get('total_chunks', 0) or 0)
        
    if expired_temp_dir:
        _cleanup_upload_session(session_id, temp_dir=expired_temp_dir)
        return jsonify({'success': False, 'error': '세션이 만료되었습니다'}), 400
    
    chunk_index = request.form.get('index', type=int)
    chunk_file = request.files.get('chunk')
    
    if chunk_index is None or chunk_index < 0 or not chunk_file:
        return jsonify({'success': False, 'error': '유효하지 않은 청크 데이터입니다'}), 400
    if total_chunks > 0 and chunk_index >= total_chunks:
        return jsonify({'success': False, 'error': '청크 인덱스가 범위를 벗어났습니다'}), 400
    
    # 청크 저장 (복사한 temp_dir 사용)
    chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index:05d}')
    chunk_file.save(chunk_path)
    
    with upload_session_lock:
        if session_id in UPLOAD_SESSIONS:
            UPLOAD_SESSIONS[session_id]['chunks'][chunk_index] = chunk_path
    
    return jsonify({
        'success': True,
        'index': chunk_index
    })


# ==========================================
# 청크 업로드 완료
# ==========================================

@upload_bp.route('/upload/chunk/<session_id>/complete', methods=['POST'])
@login_required()
def complete_chunk_upload(session_id):
    """청크 업로드 완료 및 파일 병합"""
    # 락 내에서 필요한 정보를 복사 (레이스 컨디션 방지)
    with upload_session_lock:
        if session_id not in UPLOAD_SESSIONS:
            return jsonify({'success': False, 'error': '유효하지 않은 세션입니다'}), 400
        
        upload_session = UPLOAD_SESSIONS[session_id]
        # 락 외부에서 사용할 정보 복사
        filename = upload_session['filename']
        target_dir = upload_session['target_dir']
        temp_dir = upload_session['temp_dir']
        total_size = int(upload_session.get('total_size', 0) or 0)
        chunk_size = int(upload_session.get('chunk_size', DEFAULT_CHUNK_SIZE) or DEFAULT_CHUNK_SIZE)
        total_chunks = int(upload_session.get('total_chunks', 0) or 0)
        chunks = dict(upload_session['chunks'])  # 딕셔너리 복사
        role = session.get('role', 'guest')
    
    target_path = ""
    try:
        # 청크 무결성 검증
        if total_size > 0 and not chunks:
            _cleanup_upload_session(session_id, temp_dir=temp_dir)
            return jsonify({'success': False, 'error': '업로드된 청크가 없습니다'}), 400

        if total_chunks > 0:
            sorted_indexes = sorted(chunks.keys())
            expected_indexes = list(range(total_chunks))
            if sorted_indexes != expected_indexes:
                _cleanup_upload_session(session_id, temp_dir=temp_dir)
                return jsonify({'success': False, 'error': '청크가 누락되었거나 순서가 잘못되었습니다'}), 400

        # 파일 병합
        target_path = os.path.join(target_dir, filename)
        rel_target = os.path.relpath(target_path, conf.get('folder')).replace('\\', '/')
        ok, message, status_code = ensure_path_access(rel_target, 'write', role=role)
        if not ok:
            return jsonify({'success': False, 'error': message}), status_code
        
        # 동일 파일명 처리
        if os.path.exists(target_path):
            name, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(target_path):
                new_name = f"{name}_{counter}{ext}"
                target_path = os.path.join(target_dir, new_name)
                counter += 1
        
        # 청크 순서대로 병합
        sorted_chunks = sorted(chunks.items())
        
        with open(target_path, 'wb') as output_file:
            for index, chunk_path in sorted_chunks:
                if not os.path.exists(chunk_path):
                    _cleanup_upload_session(session_id, temp_dir=temp_dir)
                    if os.path.exists(target_path):
                        os.remove(target_path)
                    return jsonify({'success': False, 'error': f'누락된 청크 파일: {index}'}), 400
                with open(chunk_path, 'rb') as chunk_file:
                    output_file.write(chunk_file.read())

        # 크기 무결성 검증
        actual_size = os.path.getsize(target_path)
        if total_size >= 0 and actual_size != total_size:
            if os.path.exists(target_path):
                os.remove(target_path)
            _cleanup_upload_session(session_id, temp_dir=temp_dir)
            return jsonify({
                'success': False,
                'error': f'병합된 파일 크기 불일치 (expected={total_size}, actual={actual_size})'
            }), 400
        
        # 임시 파일 정리
        _cleanup_upload_session(session_id, temp_dir=temp_dir)
        
        logger.add(f"청크 업로드 완료: {filename}")
        
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='upload_chunk_complete',
            target=os.path.basename(target_path),
            details=f"크기: {fmt_bytes(total_size)}",
            ip=get_real_ip()
        )
        
        return jsonify({
            'success': True,
            'filename': os.path.basename(target_path)
        })
        
    except Exception as e:
        if target_path and os.path.exists(target_path):
            try:
                os.remove(target_path)
            except Exception:
                pass
        _cleanup_upload_session(session_id, temp_dir=temp_dir)
        logger.add(f"청크 업로드 완료 오류: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==========================================
# 청크 업로드 취소
# ==========================================

@upload_bp.route('/upload/chunk/<session_id>/cancel', methods=['POST'])
@login_required()
def cancel_chunk_upload(session_id):
    """청크 업로드 취소"""
    with upload_session_lock:
        if session_id not in UPLOAD_SESSIONS:
            return jsonify({'success': True})
        
        upload_session = UPLOAD_SESSIONS[session_id]
    
    _cleanup_upload_session(session_id, temp_dir=upload_session.get('temp_dir', ''))
    
    return jsonify({'success': True})


def cleanup_expired_upload_sessions():
    """만료된 업로드 세션 정리"""
    now = datetime.now()
    expired = []
    
    with upload_session_lock:
        for session_id, session_data in UPLOAD_SESSIONS.items():
            if now > session_data['expires']:
                expired.append((session_id, session_data['temp_dir']))
    
        for session_id, temp_dir in expired:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
            if session_id in UPLOAD_SESSIONS:
                del UPLOAD_SESSIONS[session_id]
    
    return len(expired)
