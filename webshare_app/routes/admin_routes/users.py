"""User account management endpoints and user-file persistence."""

import os
from datetime import datetime
from flask import jsonify, request
from config import AUTH_LOGIN_MODE, USER_API_ENABLED, conf
from utils.log_manager import logger
from utils.api_errors import api_error
from utils.file_utils import get_folder_size
from security.auth import login_required
from ._common import USER_API_NOTICE, USER_API_REASON, _users_file_lock, admin_bp




def get_users_file_path():
    """사용자 파일 경로 반환 (공유 폴더 내부에 저장)"""
    return os.path.join(conf.get('folder'), '.webshare_users.json')




# ==========================================
# 사용자 관리
# ==========================================

def load_users():
    """사용자 목록 로드 (스레드 안전)"""
    import json
    users_file = get_users_file_path()
    with _users_file_lock:
        if os.path.exists(users_file):
            try:
                with open(users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            'users': {
                '_legacy_admin': {
                    'password_hash': conf.get('admin_pw', '1234'),
                    'role': 'admin',
                    'quota_mb': 0,
                    'folders': ['*'],
                    'created': datetime.now().isoformat()
                },
                '_legacy_guest': {
                    'password_hash': conf.get('guest_pw', '0000'),
                    'role': 'guest',
                    'quota_mb': 0,
                    'folders': ['*'],
                    'created': datetime.now().isoformat()
                }
            }
        }




def save_users(users_data):
    """사용자 목록 저장 (스레드 안전)"""
    import json
    import tempfile

    users_file = get_users_file_path()
    with _users_file_lock:
        try:
            base_dir = os.path.dirname(users_file) or '.'
            os.makedirs(base_dir, exist_ok=True)
            fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix='.webshare_users_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(users_data, f, indent=2, ensure_ascii=False)
                os.replace(temp_path, users_file)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
            return True
        except IOError as e:
            logger.add(f"사용자 저장 실패: {e}", "ERROR")
            return False




def get_user_usage(username):
    """사용자 업로드 용량 계산"""
    user_folder = os.path.join(conf.get('folder'), f'_user_{username}')
    if os.path.exists(user_folder):
        return get_folder_size(user_folder)
    return 0




@admin_bp.route('/api/users', methods=['GET', 'POST'])
@login_required('admin')
def manage_users():
    """사용자 목록 조회 및 생성"""
    if request.method == 'GET':
        return jsonify({
            'enabled': USER_API_ENABLED,
            'users': {},
            'login_mode': AUTH_LOGIN_MODE,
            'login_linked': False,
            'notice': USER_API_NOTICE,
            'reason': USER_API_REASON,
        })

    return api_error('USER_API_DISABLED', USER_API_REASON, 409)




@admin_bp.route('/api/users/<username>', methods=['GET', 'PUT', 'DELETE'])
@login_required('admin')
def manage_single_user(username):
    """개별 사용자 관리"""
    return api_error('USER_API_DISABLED', USER_API_REASON, 409)

