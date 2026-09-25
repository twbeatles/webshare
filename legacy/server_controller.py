"""Public server lifecycle controller."""

from utils.log_manager import logger
from .thread import ServerThread

server_thread = None
_server_startup_error = ""

def start_server(use_https=False, wait_ready=False, timeout=5.0):
    """서버 시작 래퍼 함수"""
    global server_thread, _server_startup_error
    if server_thread and server_thread.is_alive():
        logger.add("서버가 이미 실행 중입니다", "WARN")
        _server_startup_error = "서버가 이미 실행 중입니다."
        return False

    server_thread = ServerThread(use_https)
    server_thread.start()
    if wait_ready:
        ready = server_thread.wait_until_ready(timeout=timeout)
        if not ready:
            _server_startup_error = server_thread.startup_error or f"서버 준비 대기 시간이 초과되었습니다. ({timeout}초)"
            if not server_thread.is_alive():
                server_thread = None
            return False
    _server_startup_error = ""
    return True

def stop_server(timeout=2.0):
    """서버 종료 래퍼 함수 (타임아웃 지원)"""
    global server_thread, _server_startup_error
    if server_thread and server_thread.is_alive():
        server_thread.shutdown()
        server_thread.join(timeout=timeout)  # 최대 timeout초 대기
        server_thread = None
        _server_startup_error = ""
        return True
    return False

def is_server_running():
    """서버 실행 상태 확인"""
    return server_thread is not None and server_thread.is_alive()

def get_server_startup_error():
    """가장 최근 서버 시작 오류 메시지 반환"""
    return _server_startup_error or (server_thread.startup_error if server_thread else "")
