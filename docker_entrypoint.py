#!/usr/bin/env python3
"""
WebShare Docker Entrypoint
"""

import atexit
import os
import threading

from werkzeug.serving import make_server

from config import conf
from server import (
    build_composed_wsgi_app,
    ensure_runtime_initialized,
    start_periodic_cleanup,
    stop_periodic_cleanup,
)
from utils.helpers import cleanup_upload_temp_dirs
from utils.log_manager import logger


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

    conf.set("folder", folder)
    conf.set("display_host", host)
    conf.set("port", port)

    cleanup_upload_temp_dirs(folder)
    ensure_runtime_initialized()

    # Build search index in background.
    try:
        from features.search_indexer import indexer

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
        from features.search_indexer import indexer

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
