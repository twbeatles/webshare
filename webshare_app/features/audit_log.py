"""
WebShare Pro - Audit Log (v7.2)
감사 로그 관리
"""

import os
import json
import time
from datetime import datetime

from config import (
    conf, audit_lock, AUDIT_LOG, MAX_AUDIT_LOG, AUDIT_LOG_FILE
)
from utils.log_manager import logger
from webshare_app.core.persistence import persist_json_snapshot

AUDIT_PERSIST_KEY = "audit_log"

_AUDIT_DIRTY = False
_AUDIT_LAST_FLUSH_TS = 0.0


def log_audit(
    user: str,
    action: str,
    target: str,
    details: str = "",
    result: str = "success",
    ip: str | None = None,
):
    """감사 로그 기록 (스레드 안전)"""
    global _AUDIT_DIRTY
    entry = {
        'timestamp': datetime.now().isoformat(),
        'user': user or 'anonymous',
        'ip': ip or 'unknown',
        'action': action,
        'target': target,
        'details': details,
        'result': result
    }

    with audit_lock:
        AUDIT_LOG.append(entry)
        # 최대 개수 제한 (in-place 수정으로 참조 유지)
        # MAX_AUDIT_LOG가 0 이하이면 삭제하지 않음 (안전 장치)
        if MAX_AUDIT_LOG > 0 and len(AUDIT_LOG) > MAX_AUDIT_LOG:
            # 가장 오래된 항목들 삭제 (최신 MAX_AUDIT_LOG개 유지)
            del AUDIT_LOG[:len(AUDIT_LOG) - MAX_AUDIT_LOG]
        _AUDIT_DIRTY = True


def save_audit_log():
    """감사 로그 파일로 저장 (원자적 쓰기)"""
    global _AUDIT_DIRTY, _AUDIT_LAST_FLUSH_TS
    base_dir = conf.get('folder')
    audit_path = os.path.join(base_dir, AUDIT_LOG_FILE)

    def _build_payload():
        return list(AUDIT_LOG)

    try:
        persist_json_snapshot(AUDIT_PERSIST_KEY, audit_path, audit_lock, _build_payload)
        _AUDIT_DIRTY = False
        _AUDIT_LAST_FLUSH_TS = time.time()
    except Exception as e:
        logger.add(f"감사 로그 저장 실패: {e}", "ERROR")


def flush_audit_log_if_dirty(force: bool = False, min_interval_seconds: int = 5) -> bool:
    """Dirty 상태일 때만 감사 로그 저장"""
    with audit_lock:
        dirty = _AUDIT_DIRTY
        elapsed = time.time() - _AUDIT_LAST_FLUSH_TS
        should_flush = dirty and (force or elapsed >= max(1, int(min_interval_seconds)))
    if not should_flush:
        return False
    save_audit_log()
    return True


def load_audit_log():
    """감사 로그 파일에서 로드"""
    global _AUDIT_DIRTY, _AUDIT_LAST_FLUSH_TS
    base_dir = conf.get('folder')
    audit_path = os.path.join(base_dir, AUDIT_LOG_FILE)

    if not os.path.exists(audit_path):
        return

    with audit_lock:
        try:
            with open(audit_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                AUDIT_LOG.clear()
                AUDIT_LOG.extend(loaded)
                _AUDIT_DIRTY = False
                _AUDIT_LAST_FLUSH_TS = time.time()
            logger.add(f"감사 로그 로드: {len(AUDIT_LOG)}개 항목")
        except Exception as e:
            logger.add(f"감사 로그 로드 실패: {e}", "ERROR")
