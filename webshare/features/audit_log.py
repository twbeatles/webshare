"""
WebShare Pro - Audit Log (v7.2)
감사 로그 관리
"""

import os
import json
import tempfile
from datetime import datetime

from ..config import (
    conf, audit_lock, AUDIT_LOG, MAX_AUDIT_LOG, AUDIT_LOG_FILE
)
from ..utils.log_manager import logger


def log_audit(user: str, action: str, target: str, details: str = "", result: str = "success", ip: str = None):
    """감사 로그 기록 (스레드 안전)"""
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


def save_audit_log():
    """감사 로그 파일로 저장 (원자적 쓰기)"""
    base_dir = conf.get('folder')
    audit_path = os.path.join(base_dir, AUDIT_LOG_FILE)
    
    with audit_lock:
        try:
            # 원자적 쓰기: 임시 파일에 쓴 후 rename
            fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix='.webshare_audit_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(AUDIT_LOG, f, ensure_ascii=False, indent=2)
                if os.path.exists(audit_path):
                    os.remove(audit_path)
                os.rename(temp_path, audit_path)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        except Exception as e:
            logger.add(f"감사 로그 저장 실패: {e}", "ERROR")


def load_audit_log():
    """감사 로그 파일에서 로드"""
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
            logger.add(f"감사 로그 로드: {len(AUDIT_LOG)}개 항목")
        except Exception as e:
            logger.add(f"감사 로그 로드 실패: {e}", "ERROR")
