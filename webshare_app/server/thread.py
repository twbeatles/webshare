"""Background Werkzeug server thread."""

import threading
import time

from config import conf
from utils.log_manager import logger
from .bootstrap import ensure_runtime_initialized
from .cleanup import start_periodic_cleanup, stop_periodic_cleanup


class ServerThread(threading.Thread):
    """Flask 서버를 백그라운드 스레드에서 실행"""

    def __init__(self, use_https=False):
        threading.Thread.__init__(self)
        self.server = None
        self.daemon = True
        self.use_https = use_https
        self.port = int(conf.get('port', 5000))
        self._shutdown_event = threading.Event()
        self.ready_event = threading.Event()
        self.failed_event = threading.Event()
        self.startup_error = ""
        self.bound_host = ""
        self.bound_proto = "http"

    def _mark_ready(self, host: str, proto: str):
        self.bound_host = host
        self.bound_proto = proto
        self.failed_event.clear()
        self.startup_error = ""
        self.ready_event.set()

    def _mark_failed(self, message: str):
        self.startup_error = message
        self.ready_event.clear()
        self.failed_event.set()

    def wait_until_ready(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.1, float(timeout))
        while time.monotonic() < deadline:
            if self.ready_event.is_set():
                return True
            if self.failed_event.is_set():
                return False
            if not self.is_alive():
                return self.ready_event.is_set()
            time.sleep(0.05)
        return self.ready_event.is_set()

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
            import server as public_server
            if hasattr(public_server, 'make_server'):
                host = conf.get('display_host', '0.0.0.0')
                self.app, self.wsgi_app = public_server.build_composed_wsgi_app()
                self.server = public_server.make_server(
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
            indexer.start_watcher(conf.get('folder'))
            threading.Thread(target=indexer.build_index, args=(conf.get('folder'),), daemon=True).start()

            # 주기 정리 시작
            start_periodic_cleanup()
            self._mark_ready(host, proto)

            # serve_forever 실행 (shutdown 중 socket error가 날 수 있으므로 예외 처리)
            try:
                self.server.serve_forever()
            except OSError:
                pass  # 서버 소켓을 강제 종료하면 발생하는 정상적인 현상
            except Exception as e:
                logger.add(f"서버 실행 중 오류: {e}", "ERROR")
            finally:
                self.ready_event.clear()

        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Address already in use
                message = f"포트 {self.port}가 이미 사용 중입니다."
                logger.add(message, "ERROR")
                self._mark_failed(message)
            else:
                message = f"서버 시작 오류: {e}"
                logger.add(message, "ERROR")
                self._mark_failed(message)
        except Exception as e:
            message = f"서버 치명적 오류: {e}"
            logger.add(message, "ERROR")
            self._mark_failed(message)

    def shutdown(self):
        """서버 종료 (강력한 종료 로직)"""
        self._shutdown_event.set()
        self.ready_event.clear()

        # 주기 정리 중지
        stop_periodic_cleanup()

        # 트랜스코더 모두 정지 (v7.2.3)
        try:
            from features.transcoder import stop_all_transcoders
            stop_all_transcoders()
        except ImportError:
            pass

        try:
            from features.search_indexer import indexer
            indexer.stop_watcher()
        except Exception:
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
                try:
                    from features.runtime_state import flush_runtime_state_if_dirty
                    flush_runtime_state_if_dirty(force=True)
                except Exception:
                    pass
                try:
                    from routes.share_routes import flush_share_password_attempts_if_dirty
                    flush_share_password_attempts_if_dirty(force=True)
                except Exception:
                    pass
