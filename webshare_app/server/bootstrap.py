"""Runtime state bootstrap for WebShare Pro."""

import threading

from config import conf
from utils.log_manager import logger

_runtime_init_lock = threading.Lock()
_runtime_initialized = False


def ensure_runtime_initialized():
    """
    런타임 데이터 로드/초기화 (중복 실행 방지)
    - 메타데이터
    - 감사 로그
    - 권한
    - 클라우드 설정
    - 중복 스캔 결과
    - 작업 ledger
    - 검색 인덱스 스냅샷
    """
    global _runtime_initialized
    with _runtime_init_lock:
        if _runtime_initialized:
            return

        from features.metadata import load_metadata
        from features.audit_log import load_audit_log
        from features.cloud_sync import load_cloud_config
        from features.cloud_sync import load_cloud_runtime_state
        from features.job_store import load_jobs, mark_incomplete_jobs
        from features.share_links_store import load_share_links
        from features.runtime_state import load_download_tracker, load_login_attempts
        from routes.share_routes import load_share_password_attempts
        from features.search_indexer import indexer
        from security.permissions import load_permissions
        from features.duplicates import load_duplicate_results

        load_metadata()
        load_audit_log()
        load_share_links()
        load_share_password_attempts()
        load_login_attempts()
        load_download_tracker()
        load_permissions()
        load_cloud_config()
        load_duplicate_results()
        load_jobs()
        load_cloud_runtime_state()
        mark_incomplete_jobs(
            kind="duplicate_scan",
            state="cancelled",
            error="duplicate scan interrupted by restart",
        )
        indexer.load_snapshot(conf.get('folder'))
        _runtime_initialized = True
        logger.add("런타임 초기화 완료")


def is_runtime_initialized() -> bool:
    """런타임 초기화 완료 여부"""
    return _runtime_initialized
