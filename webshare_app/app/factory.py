"""Flask application factory and request lifecycle hooks."""

from pathlib import Path
import logging
import sys

from flask import Flask
from werkzeug.exceptions import HTTPException

from config import conf
from utils.log_manager import logger


log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


def _asset_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path.cwd()))
    return Path(__file__).resolve().parents[2]


def create_app():
    """Flask 앱 팩토리 함수"""
    app = Flask(__name__, static_folder=str(_asset_root() / 'static'), template_folder=str(_asset_root() / 'templates'))

    # 선택 의존성 orjson 사용 시 JSON 직렬화 가속
    try:
        import orjson
        from flask.json.provider import DefaultJSONProvider

        class OrjsonProvider(DefaultJSONProvider):
            def dumps(self, obj, **kwargs):
                option = 0
                if kwargs.get("sort_keys"):
                    option |= orjson.OPT_SORT_KEYS
                return orjson.dumps(obj, option=option).decode("utf-8")

            def loads(self, s, **kwargs):
                return orjson.loads(s)

        app.json = OrjsonProvider(app)
        logger.add("orjson JSON provider enabled")
    except Exception:
        pass

    # 보안 설정 — secret_key는 앱 설정 디렉터리에 영속화됨
    try:
        from webshare_app.core.app_paths import ensure_config_secret_key

        ensure_config_secret_key(conf)
    except Exception as exc:
        logger.add(f"secret_key 로드 실패: {exc}", "WARN")
    app.secret_key = str(conf.get('secret_key') or '')
    if not app.secret_key:
        from webshare_app.core.app_paths import get_or_create_secret_key

        app.secret_key = get_or_create_secret_key()
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB
    app.config['SESSION_COOKIE_SECURE'] = bool(conf.get('use_https', False))
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600

    # 선택 의존성 gzip 압축 전송
    try:
        from flask_compress import Compress

        app.config['COMPRESS_LEVEL'] = 5
        app.config['COMPRESS_MIN_SIZE'] = 1024
        Compress(app)
    except Exception:
        pass

    # CSRF 토큰 Jinja2 함수 등록
    from security.csrf import generate_csrf_token
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    from utils.api_errors import (
        api_error,
        api_request_id,
        normalize_error_response_payload,
    )

    def _is_json_error_response_candidate() -> bool:
        from flask import request

        if request.path.startswith('/api/'):
            return True
        if request.path.startswith('/healthz') or request.path.startswith('/readyz'):
            return True
        if request.is_json:
            return True
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return True
        if 'application/json' in (request.headers.get('Accept', '') or ''):
            return True
        return False

    @app.before_request
    def _global_before_request():
        import time
        from datetime import datetime
        from flask import g, request, session, redirect

        from config import STATS, ACTIVE_SESSIONS, session_lock, stats_lock
        from i18n import get_text
        from security.csrf import validate_csrf_token
        from security.ip_blocker import check_ip_blocked, check_ip_whitelist
        from utils.file_utils import get_real_ip
        from utils.request_policy import STATE_CHANGING_METHODS

        g.start_time = time.time()
        api_request_id()

        with stats_lock:
            STATS['requests'] += 1
            STATS['active_connections'] += 1

        client_ip = get_real_ip()

        if not check_ip_whitelist(client_ip):
            return api_error('IP_WHITELIST_BLOCKED', get_text('ip_blocked'), 403)

        blocked, remaining = check_ip_blocked(client_ip)
        if blocked:
            return api_error('IP_BLOCKED', f'IP 차단됨 (남은 시간: {remaining}분)', 403)

        if session.get('logged_in'):
            last_active = session.get('last_active')
            if last_active:
                timeout = conf.get('session_timeout') or 60
                if datetime.now().timestamp() - last_active > timeout * 60:
                    session.clear()
                    logger.add(f"세션 만료: {client_ip}")
                    is_ajax = request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                    if is_ajax or request.path.startswith('/api/'):
                        return api_error('SESSION_EXPIRED', '세션이 만료되었습니다.', 401, extra={'redirect': '/'})
                    return redirect('/')

            session['last_active'] = datetime.now().timestamp()
            sid = session.get('session_id')
            if sid:
                with session_lock:
                    if sid in ACTIVE_SESSIONS:
                        ACTIVE_SESSIONS[sid]['last_active'] = datetime.now()

        if request.method in STATE_CHANGING_METHODS and session.get('logged_in'):
            # 로그인 POST와 공유 링크 비밀번호 POST는 예외
            endpoint = request.endpoint or ''
            if endpoint not in {'main.index', 'share.access_share_link'}:
                if not validate_csrf_token():
                    logger.add(f"CSRF 검증 실패: {client_ip}", "WARN")
                    return api_error('CSRF_INVALID', 'CSRF 토큰 검증 실패', 403)

    @app.after_request
    def _global_after_request(response):
        from config import STATS, stats_lock
        from flask import request

        try:
            response.headers['X-Request-ID'] = api_request_id()
        except Exception:
            pass

        if request.path.startswith('/api/') or (response.mimetype == 'text/html' and request.path != '/offline.html'):
            response.headers['Cache-Control'] = 'no-store'

        # JSON 응답이 에러 성격이면 공통 스키마를 채운다.
        if response.is_json:
            try:
                payload = response.get_json(silent=True)
                normalized = normalize_error_response_payload(payload, response.status_code)
                if isinstance(normalized, dict) and normalized != payload:
                    response.set_data(app.json.dumps(normalized))
                    response.mimetype = 'application/json'
            except Exception:
                pass

        with stats_lock:
            # bytes_sent는 기본적으로 응답 Content-Length 기반으로 누적 집계한다.
            # ZIP/HLS 등 길이 미정 스트림은 라우트에서 수동 집계한다.
            if response.content_length:
                STATS['bytes_sent'] += response.content_length
            STATS['active_connections'] = max(0, STATS['active_connections'] - 1)
        return response

    @app.errorhandler(HTTPException)
    def _handle_http_exception(exc):
        if _is_json_error_response_candidate():
            code = str(exc.name or "HTTP_ERROR").upper().replace(" ", "_")
            message = str(exc.description or exc.name or "Request failed")
            return api_error(code, message, int(exc.code or 500))
        return exc

    @app.errorhandler(Exception)
    def _handle_unexpected_exception(exc):
        logger.add(f"Unhandled exception: {exc}", "ERROR")
        if _is_json_error_response_candidate():
            return api_error('INTERNAL_ERROR', '서버 내부 오류가 발생했습니다.', 500)
        raise exc

    # 라우트 등록
    from routes import register_routes
    register_routes(app)

    return app
