"""
WebShare Pro - CSRF Protection
CSRF 토큰 관리
"""

import secrets
from flask import session, request


def generate_csrf_token() -> str:
    """CSRF 토큰 생성 (세션당 한 번)"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf_token() -> bool:
    """
    CSRF 토큰 검증 (타이밍 공격 방지).
    
    폼 데이터, X-CSRF-Token 헤더, 또는 JSON 본문에서 토큰을 확인합니다.
    session.pop() 대신 session.get()을 사용하여 여러 탭에서의 요청을 지원합니다.
    
    Returns:
        bool: 토큰이 유효하면 True
    """
    token = session.get('_csrf_token')
    if not token:
        return False
    
    # 폼 데이터, 헤더, 또는 JSON 본문에서 토큰 가져오기
    provided_token = (
        request.form.get('csrf_token') or 
        request.headers.get('X-CSRF-Token')
    )
    
    # JSON 요청인 경우 본문에서 토큰 확인
    if not provided_token and request.is_json:
        try:
            json_data = request.get_json(silent=True)
            if json_data:
                provided_token = json_data.get('csrf_token')
        except Exception:
            pass
    
    if not provided_token:
        return False
    
    # 타이밍 공격 방지를 위해 secrets.compare_digest 사용
    return secrets.compare_digest(token, provided_token)
