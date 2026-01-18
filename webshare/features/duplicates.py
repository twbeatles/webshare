"""
WebShare Pro - Duplicate File Detection (v7.2)
중복 파일 검사
"""

import os
import json
import hashlib
from datetime import datetime

from ..config import conf, duplicate_scan_lock, DUPLICATE_SCAN_PROGRESS
from ..utils.log_manager import logger


DUPLICATES_FILE = '.webshare_duplicates.json'


def get_duplicates_file_path():
    """중복 스캔 결과 파일 경로 반환"""
    return os.path.join(conf.get('folder'), DUPLICATES_FILE)


def save_duplicate_results():
    """중복 스캔 결과 파일로 저장 (영속성)"""
    results_path = get_duplicates_file_path()
    
    with duplicate_scan_lock:
        results = DUPLICATE_SCAN_PROGRESS.get('results', [])
        if not results:
            return
        
        data = {
            'results': results,
            'scanned_at': datetime.now().isoformat(),
            'total_groups': len(results)
        }
    
    try:
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.add(f"중복 스캔 결과 저장 완료: {len(results)}개 그룹")
    except Exception as e:
        logger.add(f"중복 스캔 결과 저장 실패: {e}", "ERROR")


def load_duplicate_results():
    """중복 스캔 결과 파일에서 로드 (서버 재시작 시 복원)"""
    results_path = get_duplicates_file_path()
    
    if not os.path.exists(results_path):
        return
    
    try:
        with open(results_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        with duplicate_scan_lock:
            DUPLICATE_SCAN_PROGRESS['results'] = data.get('results', [])
            DUPLICATE_SCAN_PROGRESS['last_scan'] = data.get('scanned_at', '')
        
        logger.add(f"중복 스캔 결과 로드 완료: {len(data.get('results', []))}개 그룹")
    except Exception as e:
        logger.add(f"중복 스캔 결과 로드 실패: {e}", "ERROR")


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
        DUPLICATE_SCAN_PROGRESS['last_scan'] = datetime.now().isoformat()
    
    # 결과 영속화 (서버 재시작 시에도 유지)
    save_duplicate_results()
    
    logger.add(f"중복 스캔 완료: {len(duplicates)}개 그룹 발견")
    return duplicates

