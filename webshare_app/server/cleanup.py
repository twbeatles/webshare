"""Periodic cleanup scheduler for WebShare Pro."""

import threading

from utils.log_manager import logger

_cleanup_timer = None


def start_periodic_cleanup():
    """v7.1: 5분 간격 주기 정리 시작"""
    global _cleanup_timer

    def do_cleanup():
        global _cleanup_timer
        try:
            from features.trash import auto_cleanup_trash
            from utils.helpers import cleanup_expired_sessions, cleanup_expired_share_links, cleanup_expired_download_trackers
            from security.ip_blocker import cleanup_expired_login_attempts
            from features.audit_log import flush_audit_log_if_dirty
            from features.runtime_state import flush_runtime_state_if_dirty
            from routes.share_routes import flush_share_password_attempts_if_dirty

            # 세션 정리
            sessions_cleaned = cleanup_expired_sessions()

            # 공유 링크 정리
            links_cleaned = cleanup_expired_share_links()

            # 업로드 세션 정리
            from routes.upload_routes import cleanup_expired_upload_sessions
            uploads_cleaned = cleanup_expired_upload_sessions()

            # 트랜스코더 세션 정리 (v7.2.3)
            from features.transcoder import cleanup_sessions as cleanup_transcode_sessions
            cleanup_transcode_sessions()

            # 휴지통 정리
            trash_cleaned = auto_cleanup_trash()

            # 로그인 시도 기록 정리 (메모리 누수 방지)
            login_attempts_cleaned = cleanup_expired_login_attempts()

            # 다운로드 트래커 정리 (당일 데이터만 유지)
            download_trackers_cleaned = cleanup_expired_download_trackers()

            # 감사 로그 flush (dirty 상태일 때만)
            flush_audit_log_if_dirty(force=False, min_interval_seconds=5)
            flush_runtime_state_if_dirty(force=False)
            flush_share_password_attempts_if_dirty(force=False)

            total = sessions_cleaned + links_cleaned + uploads_cleaned + trash_cleaned + login_attempts_cleaned + download_trackers_cleaned
            if total > 0:
                logger.add(f"주기 정리 완료: 세션 {sessions_cleaned}, 링크 {links_cleaned}, 업로드 {uploads_cleaned}, 휴지통 {trash_cleaned}, 로그인시도 {login_attempts_cleaned}, 다운로드트래커 {download_trackers_cleaned}")
        except Exception as e:
            logger.add(f"주기 정리 오류: {e}", "ERROR")

        # 5분 뒤 다시 실행
        _cleanup_timer = threading.Timer(300, do_cleanup)
        _cleanup_timer.daemon = True
        _cleanup_timer.start()

    # 첫 실행: 서버 시작 1분 후
    _cleanup_timer = threading.Timer(60, do_cleanup)
    _cleanup_timer.daemon = True
    _cleanup_timer.start()
    logger.add("주기 정리 스케줄러 시작됨 (5분 간격)")


def stop_periodic_cleanup():
    """v7.1: 주기 정리 중지"""
    global _cleanup_timer
    if _cleanup_timer:
        _cleanup_timer.cancel()
        _cleanup_timer = None
