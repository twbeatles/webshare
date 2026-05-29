#!/usr/bin/env python3
"""
WebShare Docker Entrypoint
"""

import atexit
import os
import threading

from werkzeug.serving import make_server

from webshare_app.core.config import conf
from webshare_app.server import (
    build_composed_wsgi_app,
    ensure_runtime_initialized,
    start_periodic_cleanup,
    stop_periodic_cleanup,
)
from webshare_app.utils.helpers import cleanup_upload_temp_dirs
from webshare_app.core.log_manager import logger


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def main():
    folder = os.getenv("WEBSHARE_FOLDER", "/data")
    host = os.getenv("WEBSHARE_HOST", "0.0.0.0")
    port = _env_int("WEBSHARE_PORT", 5000)
    admin_password = os.getenv("WEBSHARE_ADMIN_PASSWORD", "")
    guest_password = os.getenv("WEBSHARE_GUEST_PASSWORD", "")
    secret_key = os.getenv("WEBSHARE_SECRET_KEY", "")

    conf.set("folder", folder)
    conf.set("display_host", host)
    conf.set("port", port)
    if admin_password:
        conf.set("admin_pw", admin_password)
    if guest_password:
        conf.set("guest_pw", guest_password)
    if secret_key:
        conf.set("secret_key", secret_key)
    elif host == "0.0.0.0":
        from webshare_app.security.auth import verify_password

        if verify_password(str(conf.get("admin_pw")), "1234") or verify_password(str(conf.get("guest_pw")), "0000"):
            logger.add(
                "Docker is bound to 0.0.0.0 with a default password. Set WEBSHARE_ADMIN_PASSWORD/WEBSHARE_GUEST_PASSWORD.",
                "WARN",
            )

    cleanup_upload_temp_dirs(folder)
    ensure_runtime_initialized()

    # Build search index in background.
    try:
        from webshare_app.features.search_indexer import indexer

        indexer.start_watcher(conf.get("folder"))
        threading.Thread(
            target=indexer.build_index,
            args=(conf.get("folder"),),
            daemon=True,
        ).start()
    except Exception as exc:
        logger.add(f"Docker indexer start failed: {exc}", "WARN")

    start_periodic_cleanup()
    atexit.register(stop_periodic_cleanup)
    try:
        from webshare_app.features.search_indexer import indexer

        atexit.register(indexer.stop_watcher)
    except Exception:
        pass

    _, wsgi_app = build_composed_wsgi_app()
    logger.add(f"Docker server start: http://{host}:{port}")

    http_server = make_server(host, port, wsgi_app, threaded=True)
    atexit.register(http_server.server_close)
    http_server.serve_forever()


if __name__ == "__main__":
    main()
