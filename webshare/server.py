"""
WebShare Pro - Server Module
Flask 서버 및 ServerThread 클래스
"""

import threading
import logging
from flask import Flask
from werkzeug.serving import make_server

from .config import conf, APP_TITLE
from .utils.log_manager import logger


# Flask 로깅 설정 (콘솔 출력 억제)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


# ==========================================
# 주기적 정리 스케줄러
# ==========================================
_cleanup_timer = None


def start_periodic_cleanup():
    """v7.1: 5분 간격 주기적 정리 시작"""
    global _cleanup_timer
    
    def do_cleanup():
        global _cleanup_timer
        try:
            from .features.trash import auto_cleanup_trash
            from .utils.helpers import cleanup_expired_sessions, cleanup_expired_share_links, cleanup_expired_download_trackers
            from .security.ip_blocker import cleanup_expired_login_attempts
            
            # 세션 정리
            sessions_cleaned = cleanup_expired_sessions()
            
            # 공유 링크 정리
            links_cleaned = cleanup_expired_share_links()
            
            # 업로드 세션 정리
            from .routes.upload_routes import cleanup_expired_upload_sessions
            uploads_cleaned = cleanup_expired_upload_sessions()
            
            # 트랜스코딩 세션 정리 (v7.2.3)
            from .features.transcoder import cleanup_sessions as cleanup_transcode_sessions
            cleanup_transcode_sessions()
            
            # 휴지통 정리
            trash_cleaned = auto_cleanup_trash()
            
            # 로그인 시도 기록 정리 (메모리 누수 방지)
            login_attempts_cleaned = cleanup_expired_login_attempts()
            
            # 다운로드 트래커 정리 (전날 데이터 삭제)
            download_trackers_cleaned = cleanup_expired_download_trackers()
            
            total = sessions_cleaned + links_cleaned + uploads_cleaned + trash_cleaned + login_attempts_cleaned + download_trackers_cleaned
            if total > 0:
                logger.add(f"주기적 정리 완료: 세션 {sessions_cleaned}, 링크 {links_cleaned}, 업로드 {uploads_cleaned}, 휴지통 {trash_cleaned}, 로그인시도 {login_attempts_cleaned}, 다운로드트래커 {download_trackers_cleaned}")
        except Exception as e:
            logger.add(f"주기적 정리 오류: {e}", "ERROR")
        
        # 5분 후 다시 실행
        _cleanup_timer = threading.Timer(300, do_cleanup)
        _cleanup_timer.daemon = True
        _cleanup_timer.start()
    
    # 첫 실행: 서버 시작 1분 후
    _cleanup_timer = threading.Timer(60, do_cleanup)
    _cleanup_timer.daemon = True
    _cleanup_timer.start()
    logger.add("주기적 정리 스케줄러 시작됨 (5분 간격)")


def stop_periodic_cleanup():
    """v7.1: 주기적 정리 중지"""
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
    
    # 보안 설정
    # secret_key: 설정에서 로드하거나 랜덤 생성 (재시작 시 세션 무효화됨)
    import os as _os
    app.secret_key = conf.get('secret_key') or _os.urandom(24).hex()
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # CSRF 토큰 Jinja2 함수 등록
    from .security.csrf import generate_csrf_token
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    
    # 라우트 등록
    from .routes import register_routes
    register_routes(app)
    
    return app


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
            
            # 서버 생성
            import werkzeug.serving
            if hasattr(werkzeug.serving, 'make_server'):
                host = conf.get('display_host', '0.0.0.0')
                self.app = create_app()
                self.server = make_server(
                    host,
                    self.port,
                    self.app,
                    threaded=True,
                    ssl_context=ssl_ctx
                )
            else:
                logger.add("Werkzeug 버전 호환성 경고: make_server를 찾을 수 없습니다.", "WARN")
                return
            
            # WebDAV 앱 마운트 (v7.2.3)
            try:
                from werkzeug.middleware.dispatcher import DispatcherMiddleware
                from .features.webdav_server import create_webdav_app
                
                webdav_app = create_webdav_app()
                if webdav_app:
                    self.app = DispatcherMiddleware(self.app, {
                        '/webdav': webdav_app
                    })
                    logger.add("WebDAV 엔드포인트 마운트됨: /webdav")
            except ImportError:
                logger.add("WebDAV 모듈을 찾을 수 없습니다 (WsgiDAV 미설치)", "WARN")
            except Exception as e:
                logger.add(f"WebDAV 마운트 실패: {e}", "ERROR")

            logger.add(f"서버 시작: {proto}://{host}:{self.port}")
            
            # 메타데이터 로드 (태그, 메모, 북마크, 즐겨찾기)
            from .features.metadata import load_metadata
            load_metadata()
            
            # 폴더 권한 로드
            from .security.permissions import load_permissions
            load_permissions()
            
            # 중복 스캔 결과 로드 (서버 재시작 시 복원)
            from .features.duplicates import load_duplicate_results
            load_duplicate_results()

            # 검색 인덱스 빌드 (v7.2.3)
            from .features.search_indexer import indexer
            threading.Thread(target=indexer.build_index, args=(conf.get('folder'),), daemon=True).start()
            
            # 주기적 정리 시작
            start_periodic_cleanup()
            
            # serve_forever 실행 (shutdown 시 socket error가 날 수 있으므로 예외 처리)
            try:
                self.server.serve_forever()
            except OSError:
                pass  # 서버 소켓이 강제 종료되면 발생하는 정상적인 현상
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
        
        # 주기적 정리 중지
        stop_periodic_cleanup()
        
        # 트랜스코더 모두 정지 (v7.2.3)
        try:
            from .features.transcoder import stop_all_transcoders
            stop_all_transcoders()
        except ImportError:
            pass
        
        if self.server:
            try:
                logger.add("서버 종료 신호 전송 중...")
                
                # 1. 종료 플래그 설정 (모든 가능성 고려)
                if hasattr(self.server, '_BaseServer__shutdown_request'):
                    self.server._BaseServer__shutdown_request = True
                if hasattr(self.server, '_shutdown_request'):
                    self.server._shutdown_request = True
                
                # 2. 소켓 강제 종료 (블로킹 해제 핵심)
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
                
                logger.add("서버가 정상 종료되었습니다")
            except Exception as e:
                logger.add(f"서버 종료 중 예외 (무시됨): {e}", "WARN")


# 전역 서버 스레드 (GUI에서 참조)
server_thread = None


def start_server(use_https=False):
    """서버 시작 헬퍼 함수"""
    global server_thread
    if server_thread and server_thread.is_alive():
        logger.add("서버가 이미 실행 중입니다", "WARN")
        return False
    
    server_thread = ServerThread(use_https)
    server_thread.start()
    return True


def stop_server(timeout=2.0):
    """서버 종료 헬퍼 함수 (타임아웃 지원)"""
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
