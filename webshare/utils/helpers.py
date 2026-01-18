"""
WebShare Pro - Helper Functions
기타 헬퍼 함수
"""

import os
import re
import shutil
from datetime import datetime

from .log_manager import logger
from ..config import (
    conf, recent_files_lock, RECENT_FILES, 
    VERSION_FOLDER_NAME, MAX_VERSIONS
)


# get_text는 webshare.i18n.get_text를 직접 사용하세요 (중복 제거됨)


def add_recent_file(path: str, name: str, file_type: str = 'file'):
    """최근 파일 목록에 추가"""
    with recent_files_lock:
        # 중복 제거
        for i, item in enumerate(RECENT_FILES):
            if item.get('path') == path:
                RECENT_FILES.pop(i)
                break
        
        # 맨 앞에 추가
        RECENT_FILES.insert(0, {
            'path': path,
            'name': name,
            'type': file_type,
            'accessed': datetime.now().isoformat()
        })
        
        # 최대 20개 유지
        while len(RECENT_FILES) > 20:
            RECENT_FILES.pop()


def create_file_version(file_path: str):
    """파일 수정 전 버전 자동 백업"""
    if not conf.get('enable_versioning'):
        return
    
    if not os.path.exists(file_path):
        return
    
    base_dir = conf.get('folder')
    version_dir = os.path.join(base_dir, VERSION_FOLDER_NAME)
    os.makedirs(version_dir, exist_ok=True)
    
    # 상대 경로를 이용해 버전 파일명 생성
    rel_path = os.path.relpath(file_path, base_dir)
    safe_name = rel_path.replace(os.sep, '_').replace('/', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    version_name = f"{timestamp}_{safe_name}"
    version_path = os.path.join(version_dir, version_name)
    
    try:
        shutil.copy2(file_path, version_path)
        logger.add(f"버전 백업: {rel_path}")
        
        # 오래된 버전 정리
        cleanup_old_versions(version_dir, safe_name)
    except Exception as e:
        logger.add(f"버전 백업 실패: {e}", "ERROR")


def cleanup_old_versions(version_dir: str, base_name: str):
    """오래된 버전 파일 정리"""
    try:
        # 정확한 패턴 매칭: YYYYMMDD_HHMMSS_base_name 형식
        # base_name 앞에 timestamp가 있어야 해당 파일의 버전임
        pattern = re.compile(r'^\d{8}_\d{6}_' + re.escape(base_name) + '$')
        versions = sorted([
            f for f in os.listdir(version_dir)
            if pattern.match(f)
        ], reverse=True)
        
        # MAX_VERSIONS 초과 시 삭제
        for old_version in versions[MAX_VERSIONS:]:
            os.remove(os.path.join(version_dir, old_version))
    except Exception:
        pass


def cleanup_expired_sessions() -> int:
    """만료된 세션 정리"""
    from ..config import session_lock, ACTIVE_SESSIONS, conf
    
    now = datetime.now()
    timeout_minutes = conf.get('session_timeout') or 60
    expired = []
    
    with session_lock:
        for sid, info in list(ACTIVE_SESSIONS.items()):
            last_active = info.get('last_active')
            if last_active:
                # 문자열인 경우 datetime으로 변환
                if isinstance(last_active, str):
                    try:
                        last_active = datetime.fromisoformat(last_active)
                    except ValueError:
                        expired.append(sid)  # 파싱 불가 시 만료 처리
                        continue
                
                age_minutes = (now - last_active).total_seconds() / 60
                if age_minutes > timeout_minutes:
                    expired.append(sid)
        
        for sid in expired:
            del ACTIVE_SESSIONS[sid]
    
    if expired:
        logger.add(f"만료 세션 정리: {len(expired)}개")
    return len(expired)


def cleanup_expired_share_links() -> int:
    """만료된 공유 링크 정리"""
    from ..config import share_links_lock, SHARE_LINKS
    
    now = datetime.now()
    expired = []
    
    with share_links_lock:
        for token, info in list(SHARE_LINKS.items()):
            expires = info.get('expires')
            if expires and now > expires:
                expired.append(token)
        
        for token in expired:
            del SHARE_LINKS[token]
    
    if expired:
        logger.add(f"만료 공유 링크 정리: {len(expired)}개")
    return len(expired)


def check_download_limit(ip: str) -> tuple:
    """
    일일 다운로드 제한 확인 (v5.1)
    
    Args:
        ip: 클라이언트 IP 주소
        
    Returns:
        tuple: (허용여부: bool, 메시지: str)
    """
    from ..config import conf, download_tracker_lock, DOWNLOAD_TRACKER
    
    today = datetime.now().strftime('%Y-%m-%d')
    
    with download_tracker_lock:
        # 기존 트래커 확인
        if ip not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[ip].get('date') != today:
            DOWNLOAD_TRACKER[ip] = {'count': 0, 'bytes': 0, 'date': today}
        
        tracker = DOWNLOAD_TRACKER[ip]
        limit_count = conf.get('daily_download_limit') or 0
        limit_mb = conf.get('daily_bandwidth_limit_mb') or 0
        
        if limit_count > 0 and tracker['count'] >= limit_count:
            return (False, f"일일 다운로드 횟수 초과 ({limit_count}회)")
        
        if limit_mb > 0 and tracker['bytes'] >= limit_mb * 1024 * 1024:
            return (False, f"일일 대역폭 초과 ({limit_mb}MB)")
    
    return (True, "")


def track_download(ip: str, file_size: int):
    """
    다운로드 기록 추적 (v5.1)
    
    Args:
        ip: 클라이언트 IP 주소
        file_size: 다운로드 파일 크기 (바이트)
    """
    from ..config import download_tracker_lock, DOWNLOAD_TRACKER
    
    today = datetime.now().strftime('%Y-%m-%d')
    
    with download_tracker_lock:
        if ip not in DOWNLOAD_TRACKER or DOWNLOAD_TRACKER[ip].get('date') != today:
            DOWNLOAD_TRACKER[ip] = {'count': 0, 'bytes': 0, 'date': today}
        
        DOWNLOAD_TRACKER[ip]['count'] += 1
        DOWNLOAD_TRACKER[ip]['bytes'] += file_size


def cleanup_expired_download_trackers() -> int:
    """
    만료된 다운로드 트래커 정리 (전날 데이터 삭제)
    
    메모리 누수 방지를 위해 전날 데이터를 자동으로 정리합니다.
    """
    from ..config import download_tracker_lock, DOWNLOAD_TRACKER
    
    today = datetime.now().strftime('%Y-%m-%d')
    expired = []
    
    with download_tracker_lock:
        for ip, info in list(DOWNLOAD_TRACKER.items()):
            if info.get('date') != today:
                expired.append(ip)
        
        for ip in expired:
            del DOWNLOAD_TRACKER[ip]
    
    if expired:
        logger.add(f"만료 다운로드 트래커 정리: {len(expired)}개")
    return len(expired)

