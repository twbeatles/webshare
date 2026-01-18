"""
WebShare Pro - Share Routes
공유 링크 생성 및 관리
"""

import os
import io
import secrets
import threading
import zipfile
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, session, send_file, send_from_directory, render_template_string

from ..config import (
    conf, SHARE_LINKS, share_links_lock,
    MAX_LOGIN_ATTEMPTS, LOGIN_BLOCK_MINUTES
)
from ..utils.log_manager import logger
from ..utils.file_utils import validate_path, get_real_ip
from ..features.audit_log import log_audit
from ..security.auth import login_required, hash_password, verify_password
from .templates import SHARE_PASSWORD_TEMPLATE, SHARE_EXPIRED_TEMPLATE

share_bp = Blueprint('share', __name__)

# ==========================================
# 공유 링크 비밀번호 브루트포스 방지 (v7.2.4)
# ==========================================
_share_password_attempts_lock = threading.Lock()
_share_password_attempts = {}  # {(ip, token): {'attempts': int, 'blocked_until': datetime}}


def check_share_password_blocked(ip: str, token: str) -> tuple:
    """공유 링크 비밀번호 시도 차단 상태 확인. (차단여부, 남은시간(분))"""
    key = (ip, token)
    with _share_password_attempts_lock:
        if key not in _share_password_attempts:
            return False, 0
        
        info = _share_password_attempts[key]
        blocked_until = info.get('blocked_until')
        
        if blocked_until:
            if datetime.now() < blocked_until:
                remaining = (blocked_until - datetime.now()).total_seconds() / 60
                return True, round(remaining)
            else:
                # 차단 해제
                del _share_password_attempts[key]
                return False, 0
        
        return False, 0


def record_share_password_attempt(ip: str, token: str, success: bool):
    """공유 링크 비밀번호 시도 기록 (스레드 안전)"""
    key = (ip, token)
    with _share_password_attempts_lock:
        if success:
            # 성공 시 기록 삭제
            if key in _share_password_attempts:
                del _share_password_attempts[key]
            return
        
        # 실패 기록
        now = datetime.now()
        if key not in _share_password_attempts:
            _share_password_attempts[key] = {'attempts': 0}
        
        _share_password_attempts[key]['attempts'] += 1
        _share_password_attempts[key]['last_attempt'] = now
        
        # 최대 횟수 초과 시 차단
        if _share_password_attempts[key]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            _share_password_attempts[key]['blocked_until'] = now + timedelta(minutes=LOGIN_BLOCK_MINUTES)
            logger.add(f"공유 링크 비밀번호 시도 차단: {ip} (토큰: {token[:8]}...)", "WARN")


# ==========================================
# 공유 링크 생성
# ==========================================

@share_bp.route('/share/create', methods=['POST'])
@login_required('admin')
def create_share_link():
    """임시 공유 링크 생성 (비밀번호, 다운로드 제한 지원)"""
    data = request.get_json()
    path = data.get('path', '')
    hours = data.get('hours', 24)
    password = data.get('password', '')
    max_downloads = data.get('max_downloads', 0)
    
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'success': False, 'error': '유효하지 않은 경로입니다.'}), 400
    
    # 토큰 생성
    token = secrets.token_urlsafe(16)
    expires = datetime.now() + timedelta(hours=hours)
    
    with share_links_lock:
        SHARE_LINKS[token] = {
            'path': path,
            'expires': expires,
            'created_by': session.get('role', 'unknown'),
            'is_dir': os.path.isdir(full_path),
            'password_hash': hash_password(password) if password else None,
            'max_downloads': max_downloads,
            'download_count': 0,
            'created_at': datetime.now().isoformat()
        }
    
    features = []
    if password: features.append('비밀번호')
    if max_downloads > 0: features.append(f'최대 {max_downloads}회')
    feature_str = f" [{', '.join(features)}]" if features else ""
    
    logger.add(f"공유 링크 생성: {path} ({hours}시간){feature_str}")
    
    # 감사 로그 기록
    log_audit(
        user=session.get('role', 'unknown'),
        action='share_create',
        target=path,
        details=f"{hours}시간, 토큰: {token[:8]}...",
        ip=get_real_ip()
    )
    
    return jsonify({
        'success': True,
        'token': token,
        'expires': expires.isoformat(),
        'link': f"/share/{token}",
        'has_password': bool(password),
        'max_downloads': max_downloads
    })


# ==========================================
# 공유 링크 접근
# ==========================================

@share_bp.route('/share/<token>', methods=['GET', 'POST'])
def access_share_link(token):
    """공유 링크로 파일 접근"""
    # 락 내에서 검증만 수행하고 필요한 정보 복사
    with share_links_lock:
        if token not in SHARE_LINKS:
            return render_template_string(SHARE_EXPIRED_TEMPLATE, message="링크를 찾을 수 없습니다."), 404
        
        share_info = SHARE_LINKS[token]
        
        # 만료 확인
        if datetime.now() > share_info['expires']:
            del SHARE_LINKS[token]
            return render_template_string(SHARE_EXPIRED_TEMPLATE, message="링크가 만료되었습니다."), 410
        
        # 다운로드 횟수 제한 확인
        max_downloads = share_info.get('max_downloads', 0)
        if max_downloads > 0 and share_info.get('download_count', 0) >= max_downloads:
            return render_template_string(SHARE_EXPIRED_TEMPLATE, message="다운로드 횟수가 초과되었습니다.")
        
        # 락 외부에서 사용할 정보 복사
        path = share_info['path']
        is_dir = share_info['is_dir']
        password_hash = share_info.get('password_hash')
    
    # 비밀번호 확인 (락 외부)
    if password_hash:
        ip = get_real_ip()
        
        # 브루트포스 차단 확인
        is_blocked, remaining_min = check_share_password_blocked(ip, token)
        if is_blocked:
            return render_template_string(SHARE_PASSWORD_TEMPLATE, 
                token=token, error=f"너무 많은 시도로 {remaining_min}분간 차단되었습니다."), 429
        
        if request.method == 'POST':
            entered_password = request.form.get('password', '')
            if not verify_password(password_hash, entered_password):
                record_share_password_attempt(ip, token, success=False)
                return render_template_string(SHARE_PASSWORD_TEMPLATE, 
                    token=token, error="비밀번호가 올바르지 않습니다.")
            else:
                record_share_password_attempt(ip, token, success=True)
        else:
            return render_template_string(SHARE_PASSWORD_TEMPLATE, token=token, error=None)
    
    # 경로 검증 (락 외부)
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return render_template_string(SHARE_EXPIRED_TEMPLATE, message="파일을 찾을 수 없습니다."), 404
    
    # 다운로드 횟수 증가 (짧은 락)
    with share_links_lock:
        if token in SHARE_LINKS:
            SHARE_LINKS[token]['download_count'] = SHARE_LINKS[token].get('download_count', 0) + 1
    
    # 파일 전송 (락 외부)
    if is_dir:
        # 폴더인 경우 ZIP으로 다운로드
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zf.write(file_path, os.path.relpath(file_path, full_path))
        mem_zip.seek(0)
        return send_file(mem_zip, download_name=f"{os.path.basename(full_path)}.zip", as_attachment=True)
    else:
        return send_from_directory(conf.get('folder'), path)


# ==========================================
# 공유 링크 목록
# ==========================================

@share_bp.route('/share/list')
@login_required('admin')
def list_share_links():
    """활성 공유 링크 목록"""
    now = datetime.now()
    active_links = []
    expired_tokens = []
    
    with share_links_lock:
        for token, info in SHARE_LINKS.items():
            if now > info['expires']:
                expired_tokens.append(token)
            else:
                active_links.append({
                    'token': token,
                    'path': info['path'],
                    'expires': info['expires'].isoformat(),
                    'is_dir': info['is_dir'],
                    'download_count': info.get('download_count', 0),
                    'max_downloads': info.get('max_downloads', 0),
                    'has_password': info.get('password_hash') is not None
                })
        
        for token in expired_tokens:
            del SHARE_LINKS[token]
    
    return jsonify({'links': active_links})


# ==========================================
# 공유 링크 삭제
# ==========================================

@share_bp.route('/share/delete/<token>', methods=['POST'])
@login_required('admin')
def delete_share_link(token):
    """공유 링크 삭제"""
    with share_links_lock:
        if token in SHARE_LINKS:
            path = SHARE_LINKS[token].get('path', 'unknown')
            del SHARE_LINKS[token]
            logger.add(f"공유 링크 삭제: {token}")
            
            # 감사 로그 기록
            log_audit(
                user=session.get('role', 'unknown'),
                action='share_delete',
                target=path,
                details=f"토큰: {token[:8]}...",
                ip=get_real_ip()
            )
            
            return jsonify({'success': True})
    return jsonify({'success': False, 'error': '링크를 찾을 수 없습니다.'})
