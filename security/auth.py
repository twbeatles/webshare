"""
WebShare Pro - Authentication
인증 및 비밀번호 관리
"""

import hashlib
import re
import secrets
from functools import wraps
from flask import session, redirect, url_for, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from utils.log_manager import logger


def hash_password(password: str) -> str:
    """
    비밀번호 해싱 (Werkzeug의 pbkdf2:sha256 사용)
    v7.1: 단순 SHA256에서 솔트가 포함된 안전한 해시로 변경
    """
    return generate_password_hash(password, method='pbkdf2:sha256')


def is_password_hash(value: str | None) -> bool:
    """Return True for the current Werkzeug PBKDF2 password hash format."""
    return bool(value and isinstance(value, str) and value.startswith("pbkdf2:") and "$" in value)


def is_legacy_sha256_hash(value: str | None) -> bool:
    """Return True for the legacy unsalted SHA256 hex hash format."""
    return bool(value and isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value))


def needs_password_rehash(stored_password: str | None) -> bool:
    """Plaintext and legacy SHA256 values should be migrated after a successful login."""
    return bool(stored_password) and not is_password_hash(stored_password)


def verify_password(stored_password: str, provided_password: str) -> bool:
    """비밀번호 검증 (구버전 호환성 포함, 타이밍 공격 방지)"""
    if not stored_password or not provided_password:
        return False
    
    # v7.1+ 신규 해시 형식 (method$salt$hash)
    if '$' in stored_password:
        return check_password_hash(stored_password, provided_password)
    
    # v4~v7.0 SHA256 형식 (64자 hex)
    if len(stored_password) == 64:
        computed = hashlib.sha256(provided_password.encode()).hexdigest()
        return secrets.compare_digest(stored_password, computed)
    
    # v3 이하 평문 비밀번호 (타이밍 공격 방지)
    return secrets.compare_digest(stored_password, provided_password)


def login_required(role='guest'):
    """로그인 필수 데코레이터"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            is_api_request = (
                request.is_json
                or request.path.startswith('/api/')
                or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            )
            if not session.get('logged_in'):
                if is_api_request:
                    return jsonify({'error': '로그인이 필요합니다'}), 401
                return redirect(url_for('main.index'))
            
            # 역할 확인 (admin 필요 시)
            if role == 'admin' and session.get('role') != 'admin':
                if is_api_request:
                    return jsonify({'error': '관리자 권한이 필요합니다'}), 403
                return redirect(url_for('main.index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
