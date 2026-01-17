"""
WebShare Pro - Upload Routes
청크 업로드 시스템
"""

import os
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, session

from ..config import conf, upload_session_lock
from ..utils.log_manager import logger
from ..utils.file_utils import validate_path, safe_filename
from ..security.auth import login_required

upload_bp = Blueprint('upload', __name__)

# 청크 업로드 세션 저장소
UPLOAD_SESSIONS = {}


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
    
    data = request.get_json()
    filename = data.get('filename', '')
    total_size = data.get('total_size', 0)
    path = data.get('path', '')
    
    if not filename:
        return jsonify({'success': False, 'error': '파일명이 필요합니다'}), 400
    
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
            'target_dir': target_dir,
            'temp_dir': temp_dir,
            'chunks': {},
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(hours=2)
        }
    
    return jsonify({
        'success': True,
        'session_id': session_id
    })


# ==========================================
# 청크 업로드
# ==========================================

@upload_bp.route('/upload/chunk/<session_id>', methods=['POST'])
@login_required()
def upload_chunk(session_id):
    """청크 업로드"""
    with upload_session_lock:
        if session_id not in UPLOAD_SESSIONS:
            return jsonify({'success': False, 'error': '유효하지 않은 세션입니다'}), 400
        
        upload_session = UPLOAD_SESSIONS[session_id]
        
        if datetime.now() > upload_session['expires']:
            del UPLOAD_SESSIONS[session_id]
            return jsonify({'success': False, 'error': '세션이 만료되었습니다'}), 400
    
    chunk_index = request.form.get('index', type=int)
    chunk_file = request.files.get('chunk')
    
    if chunk_index is None or not chunk_file:
        return jsonify({'success': False, 'error': '유효하지 않은 청크 데이터입니다'}), 400
    
    # 청크 저장
    chunk_path = os.path.join(upload_session['temp_dir'], f'chunk_{chunk_index:05d}')
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
    with upload_session_lock:
        if session_id not in UPLOAD_SESSIONS:
            return jsonify({'success': False, 'error': '유효하지 않은 세션입니다'}), 400
        
        upload_session = UPLOAD_SESSIONS[session_id]
    
    try:
        # 파일 병합
        target_path = os.path.join(
            upload_session['target_dir'],
            upload_session['filename']
        )
        
        # 동일 파일명 처리
        if os.path.exists(target_path):
            name, ext = os.path.splitext(upload_session['filename'])
            counter = 1
            while os.path.exists(target_path):
                new_name = f"{name}_{counter}{ext}"
                target_path = os.path.join(upload_session['target_dir'], new_name)
                counter += 1
        
        # 청크 순서대로 병합
        sorted_chunks = sorted(upload_session['chunks'].items())
        
        with open(target_path, 'wb') as output_file:
            for index, chunk_path in sorted_chunks:
                with open(chunk_path, 'rb') as chunk_file:
                    output_file.write(chunk_file.read())
        
        # 임시 파일 정리
        import shutil
        shutil.rmtree(upload_session['temp_dir'], ignore_errors=True)
        
        with upload_session_lock:
            if session_id in UPLOAD_SESSIONS:
                del UPLOAD_SESSIONS[session_id]
        
        logger.add(f"청크 업로드 완료: {upload_session['filename']}")
        return jsonify({
            'success': True,
            'filename': os.path.basename(target_path)
        })
        
    except Exception as e:
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
    
    try:
        import shutil
        shutil.rmtree(upload_session['temp_dir'], ignore_errors=True)
    except Exception:
        pass
    
    with upload_session_lock:
        if session_id in UPLOAD_SESSIONS:
            del UPLOAD_SESSIONS[session_id]
    
    return jsonify({'success': True})


def cleanup_expired_upload_sessions():
    """만료된 업로드 세션 정리"""
    import shutil
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
