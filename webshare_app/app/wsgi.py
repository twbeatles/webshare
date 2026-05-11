"""WSGI app composition helpers."""

from utils.log_manager import logger

from .factory import create_app


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
