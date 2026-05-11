"""
WebShare Pro - Main Routes
메인 페이지, 로그인, 파일 브라우징 라우트
"""

import os
import json
from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify
from datetime import datetime

from config import AUTH_LOGIN_MODE, USER_API_ENABLED, conf, ACTIVE_SESSIONS, session_lock
from utils.log_manager import logger, log_access
from utils.file_utils import validate_path, get_real_ip
from utils.listing import list_directory_page, to_template_items
from security.auth import hash_password, needs_password_rehash, verify_password, login_required
from security.ip_blocker import record_login_attempt
from i18n import get_text, get_all_translations
from features.audit_log import log_audit
from utils.request_policy import build_path_capabilities, ensure_path_access, parse_json_body, role_can_mutate

# 템플릿 파일 사용 (templates/index.html)


main_bp = Blueprint('main', __name__)


def _migrate_password_if_needed(config_key: str, stored_password: str, provided_password: str):
    """Upgrade plaintext/legacy SHA256 password config after a successful login."""
    if needs_password_rehash(stored_password):
        conf.set(config_key, hash_password(provided_password))
        conf.save()


@main_bp.route('/', methods=['GET', 'POST'])
def index():
    """메인 페이지 / 로그인"""
    error = None

    if request.method == 'POST':
        password = request.form.get('password', '')
        client_ip = get_real_ip()  # 프록시 환경 지원

        # 관리자 비밀번호 확인
        admin_pw = conf.get('admin_pw')
        guest_pw = conf.get('guest_pw')

        if verify_password(admin_pw, password):
            _migrate_password_if_needed('admin_pw', admin_pw, password)
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
            log_access(client_ip, 'login', 'admin')
            return redirect('/browse/')

        elif verify_password(guest_pw, password):
            _migrate_password_if_needed('guest_pw', guest_pw, password)
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
            log_access(client_ip, 'login', 'guest')
            return redirect('/browse/')
        else:
            record_login_attempt(client_ip, False)
            lang = session.get('language', conf.get('language', 'ko'))
            t = get_all_translations(lang)
            error = t.get('invalid_password', 'Invalid password')
            logger.add(f"로그인 실패: {client_ip}", "WARN")
            log_access(client_ip, 'login_failed', 'Invalid password')

    # 이미 로그인된 경우
    if session.get('logged_in'):
        return redirect('/browse/')

    # 번역 데이터 준비
    lang = session.get('language', conf.get('language', 'ko'))
    t = get_all_translations(lang)

    return render_template(
        'index.html',
        logged_in=False,
        error=error,
        t=t,
        translations_json=json.dumps(t, ensure_ascii=False),
        current_lang=lang,
        user_api_enabled=USER_API_ENABLED,
        login_mode=AUTH_LOGIN_MODE,
    )


@main_bp.route('/browse/')
@main_bp.route('/browse/<path:subpath>')
@login_required()
def browse(subpath=''):
    """파일 브라우징"""
    base_dir = conf.get('folder')
    ok, message, status_code = ensure_path_access(subpath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    # 경로 검증
    valid, full_path, error = validate_path(base_dir, subpath)
    if not valid:
        return jsonify({'error': error}), 400

    if not os.path.exists(full_path):
        return jsonify({'error': '경로를 찾을 수 없습니다'}), 404

    if not os.path.isdir(full_path):
        return redirect(f'/download/{subpath}')

    page = request.args.get('page', default=1, type=int)
    page_size = request.args.get('page_size', default=200, type=int)
    sort_by = request.args.get('sort', default='name', type=str)
    order = request.args.get('order', default='asc', type=str)
    query = request.args.get('q', default='', type=str)
    current_role = session.get('role', 'guest')

    def _access_filter(rel_path: str, action: str) -> bool:
        allowed, _, _ = ensure_path_access(rel_path, action, role=current_role)
        return allowed

    def _capability_resolver(rel_path: str, is_dir: bool, item_type: str) -> dict:
        return build_path_capabilities(rel_path, current_role, is_dir=is_dir, item_type=item_type)

    listing = list_directory_page(
        base_dir=base_dir,
        subpath=subpath,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        order=order,
        query=query,
        access_filter=_access_filter,
        capability_resolver=_capability_resolver,
        cache_scope=f"role:{current_role}",
    )
    if not listing.get('success'):
        return jsonify({'error': listing.get('error', get_text('access_denied'))}), listing.get('status_code', 500)

    items = to_template_items(listing.get('items', []))
    pagination = listing.get('pagination', {})

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
    current_capabilities = build_path_capabilities(subpath, current_role, is_dir=True, item_type="folder")
    can_modify = bool(current_capabilities.get('write')) and role_can_mutate(current_role)

    # 번역 데이터 준비
    lang = session.get('language', conf.get('language', 'ko'))
    t = get_all_translations(lang)

    return render_template(
        'index.html',
        logged_in=True,
        items=items,
        current_path=subpath,
        breadcrumbs=breadcrumbs,
        list_page=pagination.get('page', page),
        list_page_size=pagination.get('page_size', page_size),
        list_total_count=pagination.get('total_count', len(items)),
        list_total_pages=pagination.get('total_pages', 1),
        list_has_next=pagination.get('has_next', False),
        list_has_prev=pagination.get('has_prev', False),
        list_sort=listing.get('sort', {'by': sort_by, 'order': order}),
        list_query=listing.get('query', query),
        current_capabilities=current_capabilities,
        role=session.get('role', 'guest'),
        can_modify=can_modify,
        t=t,
        translations_json=json.dumps(t, ensure_ascii=False),
        current_lang=lang,
        user_api_enabled=USER_API_ENABLED,
        login_mode=AUTH_LOGIN_MODE,
    )


@main_bp.route('/logout')
def logout():
    """로그아웃"""
    session_id = session.get('session_id')
    if session_id:
        with session_lock:
            if session_id in ACTIVE_SESSIONS:
                del ACTIVE_SESSIONS[session_id]

    client_ip = get_real_ip()  # 프록시 환경 지원
    log_audit(session.get('role', 'unknown'), 'logout', '/', ip=client_ip)
    log_access(client_ip, 'logout', session.get('role', 'unknown'))
    session.clear()
    return redirect('/')


def _set_language_session(lang: str):
    """세션 언어 설정 공통 로직"""
    if lang in ['ko', 'en']:
        session['language'] = lang
        return jsonify({'success': True, 'language': lang})
    return jsonify({'success': False, 'error': 'Invalid language'}), 400


@main_bp.route('/set_language', methods=['POST'])
@login_required()
def set_language_post():
    """언어 변경 표준 API (POST, 세션 단위)"""
    data = parse_json_body(request)
    lang = data.get('lang') or request.form.get('lang', '')
    return _set_language_session(lang)


@main_bp.route('/set_language/<lang>')
def set_language_legacy(lang):
    """레거시 언어 변경 API (GET, 호환 래퍼)"""
    response = _set_language_session(lang)
    if isinstance(response, tuple):
        payload, status = response
        payload.headers['Deprecation'] = 'true'
        payload.headers['Sunset'] = '2026-08-31'
        return payload, status
    response.headers['Deprecation'] = 'true'
    response.headers['Sunset'] = '2026-08-31'
    logger.add(f"Deprecated 언어 변경 API 호출: /set_language/{lang} ({get_real_ip()})", "WARN")
    return response
