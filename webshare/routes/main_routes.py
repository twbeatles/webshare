"""
WebShare Pro - Main Routes
메인 페이지, 로그인, 파일 브라우징 라우트
"""

import os
from flask import Blueprint, render_template_string, request, session, redirect, url_for, jsonify
from datetime import datetime

from ..config import conf, STATS, ACTIVE_SESSIONS, session_lock, stats_lock
from ..utils.log_manager import logger
from ..utils.file_utils import validate_path, fmt_bytes, get_folder_size
from ..security.auth import verify_password, login_required
from ..security.csrf import generate_csrf_token, validate_csrf_token
from ..security.ip_blocker import check_ip_blocked, record_login_attempt, check_ip_whitelist
from ..i18n import get_text
from ..features.audit_log import log_audit

# 템플릿 import (별도 파일로 분리됨)
# HTML_TEMPLATE은 로그인과 브라우징을 통합한 템플릿 (logged_in 변수로 분기)
from .templates import HTML_TEMPLATE, SHARE_PASSWORD_TEMPLATE, SHARE_EXPIRED_TEMPLATE


main_bp = Blueprint('main', __name__)


@main_bp.before_request
def before_request():
    """모든 요청 전 처리"""
    # 통계 업데이트
    with stats_lock:
        STATS['requests'] += 1
    
    # IP 화이트리스트 확인
    client_ip = request.remote_addr
    if not check_ip_whitelist(client_ip):
        return jsonify({'error': get_text('ip_blocked')}), 403
    
    # IP 차단 확인
    blocked, remaining = check_ip_blocked(client_ip)
    if blocked:
        return jsonify({'error': f'IP 차단됨 (남은 시간: {remaining}분)'}), 403
    
    # CSRF 검증 (POST 요청)
    if request.method == 'POST':
        if not validate_csrf_token():
            return jsonify({'error': 'CSRF 토큰 검증 실패'}), 403
    
    # 세션 활동 시간 갱신
    if session.get('logged_in') and session.get('session_id'):
        sid = session['session_id']
        with session_lock:
            if sid in ACTIVE_SESSIONS:
                ACTIVE_SESSIONS[sid]['last_active'] = datetime.now()


@main_bp.route('/', methods=['GET', 'POST'])
def index():
    """메인 페이지 / 로그인"""
    error = None
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        client_ip = request.remote_addr
        
        # 관리자 비밀번호 확인
        admin_pw = conf.get('admin_pw')
        guest_pw = conf.get('guest_pw')
        
        if verify_password(admin_pw, password):
            session['logged_in'] = True
            session['role'] = 'admin'
            session['session_id'] = os.urandom(16).hex()
            record_login_attempt(client_ip, True)
            log_audit('admin', 'login', '/', ip=client_ip)
            
            # 활성 세션 추가
            with session_lock:
                ACTIVE_SESSIONS[session['session_id']] = {
                    'ip': client_ip,
                    'role': 'admin',
                    'login_time': datetime.now(),
                    'last_active': datetime.now()
                }
            
            logger.add(f"관리자 로그인: {client_ip}")
            return redirect('/browse/')
            
        elif verify_password(guest_pw, password):
            session['logged_in'] = True
            session['role'] = 'guest'
            session['session_id'] = os.urandom(16).hex()
            record_login_attempt(client_ip, True)
            log_audit('guest', 'login', '/', ip=client_ip)
            
            with session_lock:
                ACTIVE_SESSIONS[session['session_id']] = {
                    'ip': client_ip,
                    'role': 'guest',
                    'login_time': datetime.now(),
                    'last_active': datetime.now()
                }
            
            logger.add(f"게스트 로그인: {client_ip}")
            return redirect('/browse/')
        else:
            record_login_attempt(client_ip, False)
            error = "비밀번호가 올바르지 않습니다"
            logger.add(f"로그인 실패: {client_ip}", "WARN")
    
    # 이미 로그인된 경우
    if session.get('logged_in'):
        return redirect('/browse/')
    
    return render_template_string(HTML_TEMPLATE, logged_in=False, error=error)


@main_bp.route('/browse/')
@main_bp.route('/browse/<path:subpath>')
@login_required()
def browse(subpath=''):
    """파일 브라우징"""
    base_dir = conf.get('folder')
    
    # 경로 검증
    valid, full_path, error = validate_path(base_dir, subpath)
    if not valid:
        return jsonify({'error': error}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': '경로를 찾을 수 없습니다'}), 404
    
    if not os.path.isdir(full_path):
        return redirect(f'/download/{subpath}')
    
    # 폴더 내용 읽기
    items = []
    try:
        for name in sorted(os.listdir(full_path)):
            # 숨김 파일 제외
            if name.startswith('.'):
                continue
            
            item_path = os.path.join(full_path, name)
            rel_path = os.path.join(subpath, name).replace('\\', '/')
            ext = os.path.splitext(name)[1].lower()
            
            # 파일 타입 결정
            if os.path.isdir(item_path):
                file_type = 'folder'
            elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg']:
                file_type = 'image'
            elif ext in ['.mp4', '.webm', '.avi', '.mov', '.mkv']:
                file_type = 'video'
            elif ext in ['.mp3', '.wav', '.flac', '.ogg', '.aac', '.m4a']:
                file_type = 'audio'
            elif ext in ['.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml', '.yaml', '.yml', '.sh', '.bat', '.log', '.ini', '.cfg']:
                file_type = 'text'
            elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
                file_type = 'archive'
            else:
                file_type = 'file'
            
            if os.path.isdir(item_path):
                items.append({
                    'name': name,
                    'type': 'folder',
                    'is_dir': True,
                    'rel_path': rel_path,
                    'href': f'/browse/{rel_path}',
                    'size': '',
                    'raw_size': 0,
                    'raw_mtime': os.path.getmtime(item_path),
                    'mod_time': datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M'),
                    'ext': ''
                })
            else:
                try:
                    size = os.path.getsize(item_path)
                    mtime = os.path.getmtime(item_path)
                except OSError:
                    size = 0
                    mtime = 0
                items.append({
                    'name': name,
                    'type': file_type,
                    'is_dir': False,
                    'rel_path': rel_path,
                    'href': f'/download/{rel_path}',
                    'size': fmt_bytes(size),
                    'raw_size': size,
                    'raw_mtime': mtime,
                    'mod_time': datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M') if mtime else '',
                    'ext': ext
                })
    except PermissionError:
        return jsonify({'error': '접근 권한이 없습니다'}), 403
    
    # Breadcrumb 생성
    breadcrumbs = []
    if subpath:
        parts = subpath.split('/')
        current = ''
        for part in parts:
            if part:
                current = f"{current}/{part}" if current else part
                breadcrumbs.append({'name': part, 'path': current})
    
    # 권한 결정 (admin이거나 게스트 업로드 허용)
    can_modify = session.get('role') == 'admin' or conf.get('allow_guest_upload', False)
    
    return render_template_string(
        HTML_TEMPLATE,
        logged_in=True,
        items=items,
        current_path=subpath,
        breadcrumbs=breadcrumbs,
        role=session.get('role', 'guest'),
        can_modify=can_modify
    )


@main_bp.route('/logout')
def logout():
    """로그아웃"""
    session_id = session.get('session_id')
    if session_id:
        with session_lock:
            if session_id in ACTIVE_SESSIONS:
                del ACTIVE_SESSIONS[session_id]
    
    log_audit(session.get('role', 'unknown'), 'logout', '/', ip=request.remote_addr)
    session.clear()
    return redirect('/')


@main_bp.route('/set_language/<lang>')
def set_language(lang):
    """언어 변경"""
    if lang in ['ko', 'en']:
        session['language'] = lang
        conf.set('language', lang)
        conf.save()
    return redirect(request.referrer or '/')
