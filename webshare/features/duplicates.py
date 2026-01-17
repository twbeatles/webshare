"""
WebShare Pro - Duplicate File Detection (v7.2)
중복 파일 검사
"""

import os
import hashlib

from ..config import conf, duplicate_scan_lock, DUPLICATE_SCAN_PROGRESS
from ..utils.log_manager import logger


def calculate_file_hash(filepath: str, chunk_size: int = 8192) -> str:
    """SHA256 해시 계산"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return ""


def cancel_duplicate_scan() -> bool:
    """중복 스캔 취소 요청"""
    with duplicate_scan_lock:
        if DUPLICATE_SCAN_PROGRESS.get('running'):
            DUPLICATE_SCAN_PROGRESS['cancelled'] = True
            logger.add("중복 스캔 취소 요청됨")
            return True
        return False


def is_scan_cancelled() -> bool:
    """스캔 취소 여부 확인 (락 없이 빠른 확인용)"""
    return DUPLICATE_SCAN_PROGRESS.get('cancelled', False)


def scan_duplicates(base_dir: str, min_size: int = 1024) -> dict:
    """중복 파일 스캔 (해시 기반) - 백그라운드 실행용"""
    # 취소 플래그 초기화
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['cancelled'] = False
        DUPLICATE_SCAN_PROGRESS['running'] = True
    
    # 파일 크기별 그룹화 (빠른 필터링)
    size_groups = {}
    file_list = []
    
    # 1단계: 파일 목록 수집
    for root, dirs, files in os.walk(base_dir):
        # 취소 확인
        if is_scan_cancelled():
            logger.add("중복 스캔 취소됨 (파일 목록 수집 중)")
            with duplicate_scan_lock:
                DUPLICATE_SCAN_PROGRESS['running'] = False
            return {}
        
        # 시스템 폴더 제외
        dirs[:] = [d for d in dirs if not d.startswith('.webshare')]
        
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                size = os.path.getsize(filepath)
                if size >= min_size:
                    file_list.append((filepath, size))
                    size_groups.setdefault(size, []).append(filepath)
            except OSError:
                continue
    
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['total'] = len(file_list)
        DUPLICATE_SCAN_PROGRESS['progress'] = 0
    
    # 2단계: 동일 크기 파일만 해시 계산
    hash_groups = {}
    progress = 0
    
    for size, filepaths in size_groups.items():
        # 취소 확인
        if is_scan_cancelled():
            logger.add("중복 스캔 취소됨 (해시 계산 중)")
            with duplicate_scan_lock:
                DUPLICATE_SCAN_PROGRESS['running'] = False
            return {}
        
        if len(filepaths) < 2:
            progress += len(filepaths)
            continue
        
        for filepath in filepaths:
            # 취소 확인 (파일마다)
            if is_scan_cancelled():
                logger.add("중복 스캔 취소됨 (해시 계산 중)")
                with duplicate_scan_lock:
                    DUPLICATE_SCAN_PROGRESS['running'] = False
                return {}
            
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                hash_groups.setdefault(file_hash, []).append({
                    'path': os.path.relpath(filepath, base_dir).replace('\\', '/'),
                    'size': size,
                    'name': os.path.basename(filepath)
                })
            
            progress += 1
            with duplicate_scan_lock:
                DUPLICATE_SCAN_PROGRESS['progress'] = progress
    
    # 3단계: 중복 파일만 필터링
    duplicates = {h: files for h, files in hash_groups.items() if len(files) > 1}
    
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['running'] = False
        DUPLICATE_SCAN_PROGRESS['results'] = list(duplicates.values())
    
    logger.add(f"중복 스캔 완료: {len(duplicates)}개 그룹 발견")
    return duplicates
