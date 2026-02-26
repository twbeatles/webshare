"""
WebShare Pro - Security Routes
파일 암호화/복호화
"""

import os
from flask import Blueprint, jsonify, request, session

from config import conf
from utils.log_manager import logger
from utils.file_utils import validate_path, get_real_ip
from utils.request_policy import ensure_path_access, parse_json_body
from security.auth import login_required
from features.crypto import encrypt_file_aes, decrypt_file_aes
from features.audit_log import log_audit

security_bp = Blueprint('security', __name__)


# ==========================================
# 파일 암호화
# ==========================================

@security_bp.route('/encrypt/<path:filepath>', methods=['POST'])
@login_required('admin')
def encrypt_file(filepath):
    """파일 암호화"""
    data = parse_json_body(request)
    password = data.get('password', conf.get('admin_pw'))

    ok, message, status_code = ensure_path_access(filepath, 'write')
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    
    is_valid, full_path, error = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.isfile(full_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'}), 404
    
    if full_path.endswith('.enc'):
        return jsonify({'success': False, 'error': '이미 암호화된 파일입니다.'})
    
    success, result = encrypt_file_aes(full_path, password)
    if success:
        logger.add(f"파일 암호화: {filepath}")
        
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='encrypt',
            target=filepath,
            details=f"결과: {os.path.basename(result)}",
            ip=get_real_ip()
        )
        
        return jsonify({'success': True, 'new_path': os.path.basename(result)})
    return jsonify({'success': False, 'error': result})


# ==========================================
# 파일 복호화
# ==========================================

@security_bp.route('/decrypt/<path:filepath>', methods=['POST'])
@login_required('admin')
def decrypt_file(filepath):
    """파일 복호화"""
    data = parse_json_body(request)
    password = data.get('password', conf.get('admin_pw'))

    ok, message, status_code = ensure_path_access(filepath, 'write')
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    
    is_valid, full_path, error = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.isfile(full_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'}), 404
    
    success, result = decrypt_file_aes(full_path, password)
    if success:
        logger.add(f"파일 복호화: {filepath}")
        
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='decrypt',
            target=filepath,
            details=f"결과: {os.path.basename(result)}",
            ip=get_real_ip()
        )
        
        return jsonify({'success': True, 'new_path': os.path.basename(result)})
    return jsonify({'success': False, 'error': result})

