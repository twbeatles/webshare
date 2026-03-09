"""
WebShare Pro - Server Module
Flask 서버 및 ServerThread 클래스
"""

import threading
import logging
from flask import Flask
from werkzeug.exceptions import HTTPException
from werkzeug.serving import make_server

from config import conf, APP_TITLE
from utils.log_manager import logger


# Flask 로거 설정 (콘솔 출력 억제)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


# ==========================================
# 주기 정리 스케줄러
# ==========================================
_cleanup_timer = None
_runtime_init_lock = threading.Lock()
_runtime_initialized = False


def ensure_runtime_initialized():
    """
    런타임 데이터 로드/초기화 (중복 실행 방지)
    - 메타데이터
    - 감사 로그
    - 권한
    - 클라우드 설정
    - 중복 스캔 결과
    """
    global _runtime_initialized
    with _runtime_init_lock:
        if _runtime_initialized:
            return

        from features.metadata import load_metadata
        from features.audit_log import load_audit_log
        from features.cloud_sync import load_cloud_config
        from features.share_links_store import load_share_links
        from security.permissions import load_permissions
        from features.duplicates import load_duplicate_results

        load_metadata()
        load_audit_log()
        load_share_links()
        load_permissions()
        load_cloud_config()
        load_duplicate_results()
        _runtime_initialized = True
        logger.add("런타임 초기화 완료")


def is_runtime_initialized() -> bool:
    """런타임 초기화 완료 여부"""
    return _runtime_initialized


def start_periodic_cleanup():
    """v7.1: 5분 간격 주기 정리 시작"""
    global _cleanup_timer
    
    def do_cleanup():
        global _cleanup_timer
        try:
            from features.trash import auto_cleanup_trash
            from utils.helpers import cleanup_expired_sessions, cleanup_expired_share_links, cleanup_expired_download_trackers
            from security.ip_blocker import cleanup_expired_login_attempts
            from features.audit_log import flush_audit_log_if_dirty
            
            # 세션 정리
            sessions_cleaned = cleanup_expired_sessions()
            
            # 공유 링크 정리
            links_cleaned = cleanup_expired_share_links()
            
            # 업로드 세션 정리
            from routes.upload_routes import cleanup_expired_upload_sessions
            uploads_cleaned = cleanup_expired_upload_sessions()
            
            # 트랜스코더 세션 정리 (v7.2.3)
            from features.transcoder import cleanup_sessions as cleanup_transcode_sessions
            cleanup_transcode_sessions()
            
            # 휴지통 정리
            trash_cleaned = auto_cleanup_trash()
            
            # 로그인 시도 기록 정리 (메모리 누수 방지)
            login_attempts_cleaned = cleanup_expired_login_attempts()
            
            # 다운로드 트래커 정리 (당일 데이터만 유지)
            download_trackers_cleaned = cleanup_expired_download_trackers()

            # 감사 로그 flush (dirty 상태일 때만)
            flush_audit_log_if_dirty(force=False, min_interval_seconds=5)
            
            total = sessions_cleaned + links_cleaned + uploads_cleaned + trash_cleaned + login_attempts_cleaned + download_trackers_cleaned
            if total > 0:
                logger.add(f"주기 정리 완료: 세션 {sessions_cleaned}, 링크 {links_cleaned}, 업로드 {uploads_cleaned}, 휴지통 {trash_cleaned}, 로그인시도 {login_attempts_cleaned}, 다운로드트래커 {download_trackers_cleaned}")
        except Exception as e:
            logger.add(f"주기 정리 오류: {e}", "ERROR")
        
        # 5분 뒤 다시 실행
        _cleanup_timer = threading.Timer(300, do_cleanup)
        _cleanup_timer.daemon = True
        _cleanup_timer.start()
    
    # 첫 실행: 서버 시작 1분 후
    _cleanup_timer = threading.Timer(60, do_cleanup)
    _cleanup_timer.daemon = True
    _cleanup_timer.start()
    logger.add("주기 정리 스케줄러 시작됨 (5분 간격)")


def stop_periodic_cleanup():
    """v7.1: 주기 정리 중지"""
    global _cleanup_timer
    if _cleanup_timer:
        _cleanup_timer.cancel()
        _cleanup_timer = None








# ==========================================
# Flask 앱 팩토리
# ==========================================
def create_app():
    """Flask 앱 팩토리 함수"""
    app = Flask(__name__, 
                static_folder='static',
                template_folder='templates')

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
    
    # 보안 설정
    # secret_key: 설정에서 로드하거나 랜덤 생성 (재시작 시 세션 무효화됨)
    import os as _os
    app.secret_key = conf.get('secret_key') or _os.urandom(24).hex()
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

        try:
            response.headers['X-Request-ID'] = api_request_id()
        except Exception:
            pass

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


def build_composed_wsgi_app(flask_app=None):
    """
    Build the final WSGI app.
    - base: Flask app
    - optional: mount WebDAV at /webdav via DispatcherMiddleware
    """
    app = flask_app or create_app()
    wsgi_app = app

    try:
        from werkzeug.middleware.dispatcher import DispatcherMiddleware
        from features.webdav_server import create_webdav_app

        webdav_app = create_webdav_app()
        if webdav_app:
            wsgi_app = DispatcherMiddleware(app, {
                '/webdav': webdav_app
            })
            logger.add("WebDAV 엔드포인트 마운트됨: /webdav")
    except ImportError:
        logger.add("WebDAV 모듈을 찾을 수 없습니다 (WsgiDAV 미설치)", "WARN")
    except Exception as e:
        logger.add(f"WebDAV 마운트 실패: {e}", "ERROR")

    return app, wsgi_app


# ==========================================
# 서버 스레드 (Aggressive Shutdown)
# ==========================================
class ServerThread(threading.Thread):
    """Flask 서버를 백그라운드 스레드에서 실행"""
    
    def __init__(self, use_https=False):
        threading.Thread.__init__(self)
        self.server = None
        self.daemon = True
        self.use_https = use_https
        self.port = int(conf.get('port', 5000))
        self._shutdown_event = threading.Event()
    
    def run(self):
        """서버 시작"""
        try:
            # HTTPS 설정
            ssl_ctx = None
            proto = "http"
            if self.use_https:
                try:
                    ssl_ctx = 'adhoc'
                    proto = "https"
                except Exception as e:
                    logger.add(f"HTTPS(adhoc) 설정 실패: {e}\nHTTP로 전환합니다.", "ERROR")
                    self.use_https = False
                    ssl_ctx = None
                    proto = "http"
            
            # server creation (Flask app -> optional WebDAV wrap -> make_server)
            import werkzeug.serving
            if hasattr(werkzeug.serving, 'make_server'):
                host = conf.get('display_host', '0.0.0.0')
                self.app, self.wsgi_app = build_composed_wsgi_app()
                self.server = make_server(
                    host,
                    self.port,
                    self.wsgi_app,
                    threaded=True,
                    ssl_context=ssl_ctx
                )
            else:
                logger.add("Werkzeug 버전 호환성 경고: make_server를 찾을 수 없습니다.", "WARN")
                return

            logger.add(f"서버 시작: {proto}://{host}:{self.port}")

            # 런타임 데이터 초기화 (중복 방지)
            ensure_runtime_initialized()

            # 검색 인덱스 빌드 (v7.2.3)
            from features.search_indexer import indexer
            threading.Thread(target=indexer.build_index, args=(conf.get('folder'),), daemon=True).start()
            
            # 주기 정리 시작
            start_periodic_cleanup()
            
            # serve_forever 실행 (shutdown 중 socket error가 날 수 있으므로 예외 처리)
            try:
                self.server.serve_forever()
            except OSError:
                pass  # 서버 소켓을 강제 종료하면 발생하는 정상적인 현상
            except Exception as e:
                logger.add(f"서버 실행 중 오류: {e}", "ERROR")
            
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Address already in use
                logger.add(f"포트 {self.port}가 이미 사용 중입니다.", "ERROR")
            else:
                logger.add(f"서버 시작 오류: {e}", "ERROR")
        except Exception as e:
            logger.add(f"서버 치명적 오류: {e}", "ERROR")
    
    def shutdown(self):
        """서버 종료 (강력한 종료 로직)"""
        self._shutdown_event.set()
        
        # 주기 정리 중지
        stop_periodic_cleanup()
        
        # 트랜스코더 모두 정지 (v7.2.3)
        try:
            from features.transcoder import stop_all_transcoders
            stop_all_transcoders()
        except ImportError:
            pass
        
        if self.server:
            try:
                logger.add("서버 종료 신호 전송 중...")
                
                # 1. 종료 플래그 설정 (모든 가능성 고려)
                if hasattr(self.server, '_BaseServer__shutdown_request'):
                    setattr(self.server, '_BaseServer__shutdown_request', True)
                if hasattr(self.server, '_shutdown_request'):
                    setattr(self.server, '_shutdown_request', True)
                
                # 2. 소켓 강제 종료 (블로킹 해제 유도)
                if hasattr(self.server, 'socket') and self.server.socket:
                    try:
                        import socket
                        self.server.socket.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        self.server.socket.close()
                    except Exception:
                        pass
                
                # 3. 공식 shutdown 호출
                try:
                    self.server.shutdown()
                except Exception:
                    pass
                
                try:
                    self.server.server_close()
                except Exception:
                    pass
                
                logger.add("Server stopped cleanly")
            except Exception as e:
                logger.add(f"Exception during shutdown (ignored): {e}", "WARN")
            finally:
                try:
                    from features.audit_log import flush_audit_log_if_dirty
                    flush_audit_log_if_dirty(force=True)
                except Exception:
                    pass


# 전역 서버 스레드 (GUI에서 참조)
server_thread = None


def start_server(use_https=False):
    """서버 시작 래퍼 함수"""
    global server_thread
    if server_thread and server_thread.is_alive():
        logger.add("서버가 이미 실행 중입니다", "WARN")
        return False
    
    server_thread = ServerThread(use_https)
    server_thread.start()
    return True


def stop_server(timeout=2.0):
    """서버 종료 래퍼 함수 (타임아웃 지원)"""
    global server_thread
    if server_thread and server_thread.is_alive():
        server_thread.shutdown()
        server_thread.join(timeout=timeout)  # 최대 timeout초 대기
        server_thread = None
        return True
    return False


def is_server_running():
    """서버 실행 상태 확인"""
    return server_thread is not None and server_thread.is_alive()
