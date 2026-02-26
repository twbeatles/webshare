#!/usr/bin/env python3
"""
WebShare Docker Entrypoint
헤드리스 컨테이너 실행용 엔트리포인트
"""

import atexit
import os
import threading

from config import conf
from server import create_app, ensure_runtime_initialized, start_periodic_cleanup, stop_periodic_cleanup
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

    ensure_runtime_initialized()

    # 검색 인덱스 백그라운드 빌드
    try:
        from features.search_indexer import indexer

        threading.Thread(
            target=indexer.build_index,
            args=(conf.get("folder"),),
            daemon=True,
        ).start()
    except Exception as exc:
        logger.add(f"Docker 인덱서 시작 실패: {exc}", "WARN")

    start_periodic_cleanup()
    atexit.register(stop_periodic_cleanup)

    app = create_app()
    logger.add(f"Docker 서버 시작: http://{host}:{port}")
    app.run(host=host, port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()

