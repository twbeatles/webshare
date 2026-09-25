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
_go_process = None


def _use_go_backend():
    from .go_process import backend_name

    return backend_name() == "go"


def _go_singleton():
    global _go_process
    if _go_process is None:
        from .go_process import GoServerProcess

        _go_process = GoServerProcess()
    return _go_process


def _start_python_thread(use_https, wait_ready, timeout):
    """Start the legacy Python backend thread (fallback path)."""
    global server_thread, _server_startup_error
    from utils.log_manager import logger

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


def start_server(use_https=False, wait_ready=False, timeout=5.0):
    """Start the background server (Go subprocess or python thread).

    GUI-facing semantics are identical for both backends. Backend selection
    is ``WEBSHARE_SERVER_BACKEND`` (``go`` default since Milestone J,
    ``python`` legacy fallback); no caller branches on the backend.
    When Go fails to start, the Python backend starts instead (§58 rollback:
    no config/data/frontend conversion needed).
    """
    global server_thread, _server_startup_error
    if _use_go_backend():
        from config import conf
        from utils.log_manager import logger

        go = _go_singleton()
        ok = go.start(
            host="127.0.0.1",
            port=int(conf.get("port", 5000)),
            timeout=timeout if wait_ready else 15.0,
        )
        if ok:
            _server_startup_error = ""
            return True
        logger.add(f"Go 백엔드 시작 실패, Python으로 폴백: {go.startup_error}", "ERROR")
        return _start_python_thread(use_https, wait_ready, timeout)
    return _start_python_thread(use_https, wait_ready, timeout)


def stop_server(timeout=2.0):
    """Stop the background server (either backend)."""
    global server_thread, _server_startup_error
    if _use_go_backend() or _go_process is not None:
        ok = _go_singleton().shutdown(timeout=timeout if timeout else 10.0)
        _server_startup_error = ""
        return ok
    if server_thread and server_thread.is_alive():
        server_thread.shutdown()
        server_thread.join(timeout=timeout)
        server_thread = None
        _server_startup_error = ""
        return True
    return False


def is_server_running():
    """Return whether the background server is alive (either backend)."""
    if _go_process is not None:
        return _go_singleton().is_alive()
    return server_thread is not None and server_thread.is_alive()


def get_server_startup_error():
    """Return the latest server startup error (either backend)."""
    if _go_process is not None and not _server_startup_error:
        return _go_singleton().startup_error
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
