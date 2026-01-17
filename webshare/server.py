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


def create_app():
    """Flask 앱 팩토리 함수"""
    app = Flask(__name__, 
                static_folder=None,
                template_folder=None)
    
    # 보안 설정
    app.secret_key = 'webshare_pro_secret_key_change_in_production'
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


class ServerThread(threading.Thread):
    """Flask 서버를 백그라운드 스레드에서 실행"""
    
    def __init__(self, use_https=False):
        super().__init__(daemon=True)
        self.app = create_app()
        self.use_https = use_https
        self.server = None
        self._shutdown_event = threading.Event()
    
    def run(self):
        """서버 시작"""
        port = conf.get('port', 5000)
        host = '0.0.0.0'
        
        try:
            self.server = make_server(host, port, self.app, threaded=True)
            self.server.timeout = 1  # shutdown 체크 주기
            
            logger.add(f"서버 시작: http://{host}:{port}")
            
            while not self._shutdown_event.is_set():
                self.server.handle_request()
                
        except Exception as e:
            logger.add(f"서버 오류: {e}", "ERROR")
    
    def shutdown(self):
        """서버 종료"""
        self._shutdown_event.set()
        if self.server:
            try:
                self.server.shutdown()
                logger.add("서버가 정상 종료되었습니다")
            except Exception as e:
                logger.add(f"서버 종료 오류: {e}", "ERROR")


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


def stop_server():
    """서버 종료 헬퍼 함수"""
    global server_thread
    if server_thread and server_thread.is_alive():
        server_thread.shutdown()
        server_thread = None
        return True
    return False


def is_server_running():
    """서버 실행 상태 확인"""
    return server_thread is not None and server_thread.is_alive()
