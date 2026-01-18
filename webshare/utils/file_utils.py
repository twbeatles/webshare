"""
WebShare Pro - File Utilities
파일 관련 유틸리티 함수
"""

import os
import re
import time
import threading
import unicodedata
from flask import request


# ==========================================
# 폴더 크기 캐시 (TTL 기반)
# ==========================================
_folder_size_cache = {}
_folder_size_cache_lock = threading.Lock()
FOLDER_SIZE_CACHE_TTL = 60  # 60초


def get_real_ip():
    """클라이언트 실제 IP 주소 반환 (프록시/로드밸런서 환경 지원)"""
    # X-Forwarded-For 헤더 확인 (프록시 환경)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    # X-Real-IP 헤더 확인 (Nginx)
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr


def safe_filename(filename: str) -> str:
    """
    Werkzeug의 secure_filename은 한글을 모두 삭제하므로,
    한글을 지원하는 안전한 파일명 변환 함수를 구현합니다.
    
    Windows 예약어 및 특수 문자 처리 포함.
    """
    if not filename:
        return 'unnamed'
    
    # Windows 예약어 목록
    WINDOWS_RESERVED_NAMES = {
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }
    
    # 유니코드 정규화
    filename = unicodedata.normalize('NFC', filename)
    
    # 위험한 문자 대체
    filename = filename.replace('/', '_').replace('\\', '_')
    filename = filename.replace(':', '_').replace('*', '_')
    filename = filename.replace('?', '_').replace('"', '_')
    filename = filename.replace('<', '_').replace('>', '_')
    filename = filename.replace('|', '_')
    
    # 연속된 언더스코어 정리
    filename = re.sub(r'_+', '_', filename)
    
    # 앞뒤 공백/언더스코어 제거
    filename = filename.strip().strip('_')
    
    # Windows에서 문제되는 파일명 끝 공백/점 제거
    filename = filename.rstrip('. ')
    
    # 숨김 파일 방지
    if filename.startswith('.'):
        filename = '_' + filename
    
    # 빈 파일명 처리
    if not filename:
        return 'unnamed'
    
    # Windows 예약어 처리 (확장자 분리 후 체크)
    name, ext = os.path.splitext(filename)
    if name.upper() in WINDOWS_RESERVED_NAMES:
        filename = f"_{name}{ext}"
    
    # 최대 길이 제한
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200 - len(ext)] + ext
    
    return filename


def validate_path(base_dir: str, path: str) -> tuple:
    """
    경로 탐색 공격을 방지하기 위한 경로 검증 함수.
    
    심볼릭 링크도 해석하여 실제 경로가 base_dir 내부인지 확인합니다.

    Args:
        base_dir: 기본 허용 디렉토리
        path: 검증할 상대 경로

    Returns:
        tuple: (is_valid: bool, full_path: str, error_msg: str)
    """
    if not path:
        return True, base_dir, ""
    
    # 경로 정규화 및 심볼릭 링크 해석
    full_path = os.path.normpath(os.path.join(base_dir, path))
    
    # 심볼릭 링크 해석 (존재하는 경로만)
    if os.path.exists(full_path):
        full_path = os.path.realpath(full_path)
    
    base_dir_real = os.path.realpath(os.path.normpath(base_dir))
    
    # base_dir 내부인지 확인
    # full_path가 base_dir과 정확히 같거나, base_dir + os.sep으로 시작해야 함
    # 이렇게 해야 "/base_malicious" 같은 경로가 "/base"의 하위로 인식되지 않음
    if full_path != base_dir_real and not full_path.startswith(base_dir_real + os.sep):
        return False, "", "접근 권한이 없습니다"
    
    return True, full_path, ""


def fmt_bytes(b: int) -> str:
    """바이트를 읽기 좋은 형식으로 변환"""
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    if b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    return f"{b / 1024 / 1024 / 1024:.2f} GB"


def get_folder_size(folder_path: str, use_cache: bool = True) -> int:
    """
    폴더 크기 계산 (바이트) - TTL 캐시 지원
    
    Args:
        folder_path: 폴더 경로
        use_cache: 캐시 사용 여부 (기본값: True)
        
    Returns:
        폴더 크기 (바이트)
    """
    now = time.time()
    cache_key = os.path.normpath(folder_path)
    
    # 캐시 확인
    if use_cache:
        with _folder_size_cache_lock:
            if cache_key in _folder_size_cache:
                cached_size, cached_time = _folder_size_cache[cache_key]
                if now - cached_time < FOLDER_SIZE_CACHE_TTL:
                    return cached_size
    
    # 폴더 크기 계산
    total = 0
    try:
        for dirpath, _, filenames in os.walk(folder_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
    except Exception:
        pass
    
    # 캐시 저장
    with _folder_size_cache_lock:
        _folder_size_cache[cache_key] = (total, now)
        
        # 캐시 크기 제한 (최대 100개)
        if len(_folder_size_cache) > 100:
            # 가장 오래된 항목 삭제
            oldest_key = min(_folder_size_cache, key=lambda k: _folder_size_cache[k][1])
            del _folder_size_cache[oldest_key]
    
    return total


def invalidate_folder_size_cache(folder_path: str = None):
    """
    폴더 크기 캐시 무효화
    
    Args:
        folder_path: 특정 폴더 경로 (None이면 전체 캐시 삭제)
    """
    with _folder_size_cache_lock:
        if folder_path is None:
            _folder_size_cache.clear()
        else:
            cache_key = os.path.normpath(folder_path)
            # 해당 경로와 하위 경로 모두 삭제
            keys_to_delete = [k for k in _folder_size_cache if k.startswith(cache_key)]
            for k in keys_to_delete:
                del _folder_size_cache[k]


def get_file_type(ext: str) -> str:
    """확장자로 파일 타입 반환"""
    from ..config import IMAGE_EXTENSIONS, VIDEO_EXTENSIONS, AUDIO_EXTENSIONS, TEXT_EXTENSIONS, ARCHIVE_EXTENSIONS
    
    ext = ext.lower()
    if ext in IMAGE_EXTENSIONS:
        return 'image'
    if ext in VIDEO_EXTENSIONS:
        return 'video'
    if ext in AUDIO_EXTENSIONS:
        return 'audio'
    if ext in TEXT_EXTENSIONS:
        return 'text'
    if ext in ARCHIVE_EXTENSIONS:
        return 'archive'
    return 'file'
