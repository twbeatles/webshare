"""Server public API compatibility surface."""

from werkzeug.serving import make_server

from webshare_app.app.factory import create_app
from webshare_app.app.wsgi import build_composed_wsgi_app
from . import bootstrap as _bootstrap
from .bootstrap import ensure_runtime_initialized, is_runtime_initialized
from .cleanup import start_periodic_cleanup, stop_periodic_cleanup
from .thread import ServerThread


server_thread = None
_server_startup_error = ""
_runtime_initialized = _bootstrap._runtime_initialized


def start_server(use_https=False, wait_ready=False, timeout=5.0):
    """Start the background server thread."""
    global server_thread, _server_startup_error
    if server_thread and server_thread.is_alive():
        from utils.log_manager import logger

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
    """Stop the background server thread."""
    global server_thread, _server_startup_error
    if server_thread and server_thread.is_alive():
        server_thread.shutdown()
        server_thread.join(timeout=timeout)
        server_thread = None
        _server_startup_error = ""
        return True
    return False


def is_server_running():
    """Return whether the background server is alive."""
    return server_thread is not None and server_thread.is_alive()


def get_server_startup_error():
    """Return the latest server startup error."""
    return _server_startup_error or (server_thread.startup_error if server_thread else "")

__all__ = [
    "create_app",
    "build_composed_wsgi_app",
    "ensure_runtime_initialized",
    "is_runtime_initialized",
    "start_periodic_cleanup",
    "stop_periodic_cleanup",
    "ServerThread",
    "start_server",
    "stop_server",
    "is_server_running",
    "get_server_startup_error",
    "make_server",
    "server_thread",
]
