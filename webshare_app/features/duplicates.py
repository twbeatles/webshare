"""
WebShare Pro - Duplicate File Detection (v7.2)
중복 파일 검사
"""

import os
import json
import hashlib
import tempfile
from datetime import datetime

from config import conf, duplicate_scan_lock, DUPLICATE_SCAN_PROGRESS
from features.job_store import update_job
from utils.log_manager import logger
from webshare_app.core.persistence import persist_json_snapshot


DUPLICATES_FILE = '.webshare_duplicates.json'
DUPLICATE_SCAN_JOB_KIND = "duplicate_scan"


def get_duplicates_file_path():
    """중복 스캔 결과 파일 경로 반환"""
    return os.path.join(conf.get('folder'), DUPLICATES_FILE)


def save_duplicate_results():
    """중복 스캔 결과 파일로 저장 (영속성)"""
    results_path = get_duplicates_file_path()

    def _build_payload():
        results = DUPLICATE_SCAN_PROGRESS.get('results', [])
        if not results:
            return None
        return {
            'results': results,
            'scanned_at': datetime.now().isoformat(),
            'total_groups': len(results),
            'schema_version': 2,
        }

    try:
        with duplicate_scan_lock:
            payload = _build_payload()
        if payload is None:
            return
        from webshare_app.core.persistence import persist_json_value

        persist_json_value("duplicate_results", results_path, payload)
        logger.add(f"중복 스캔 결과 저장 완료: {payload['total_groups']}개 그룹")
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

        loaded_results = data.get('results', [])
        # v1 호환: [[{path,size,name}, ...]] 형식 -> v2 그룹 형식으로 변환
        if loaded_results and isinstance(loaded_results, list) and isinstance(loaded_results[0], list):
            converted = []
            for i, files in enumerate(loaded_results):
                if not files:
                    continue
                converted.append({
                    'hash': f'legacy-{i}',
                    'size': files[0].get('size', 0),
                    'files': files,
                })
            loaded_results = converted

        with duplicate_scan_lock:
            DUPLICATE_SCAN_PROGRESS['results'] = loaded_results
            DUPLICATE_SCAN_PROGRESS['last_scan'] = data.get('scanned_at', '')

        logger.add(f"중복 스캔 결과 로드 완료: {len(loaded_results)}개 그룹")
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


def _update_duplicate_job(job_id: str, *, persist: bool = False, **updates):
    if not job_id:
        return
    update_job(job_id, persist=persist, **updates)


def cancel_duplicate_scan() -> bool:
    """중복 스캔 취소 요청"""
    with duplicate_scan_lock:
        if DUPLICATE_SCAN_PROGRESS.get('running'):
            DUPLICATE_SCAN_PROGRESS['cancelled'] = True
            DUPLICATE_SCAN_PROGRESS['phase'] = 'cancelling'
            job_id = str(DUPLICATE_SCAN_PROGRESS.get('job_id', '') or '')
            logger.add("중복 스캔 취소 요청됨")
            _update_duplicate_job(job_id, persist=True, phase='cancelling', cancelled=True)
            return True
        return False


def is_scan_cancelled() -> bool:
    """스캔 취소 여부 확인 (락 없이 빠른 확인용)"""
    return DUPLICATE_SCAN_PROGRESS.get('cancelled', False)


def scan_duplicates(base_dir: str, min_size: int = 1024, job_id: str = "") -> dict:
    """중복 파일 스캔 (해시 기반) - 백그라운드 실행용"""
    # 취소 플래그 초기화
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['cancelled'] = False
        DUPLICATE_SCAN_PROGRESS['running'] = True
        DUPLICATE_SCAN_PROGRESS['job_id'] = job_id
        DUPLICATE_SCAN_PROGRESS['phase'] = 'collecting'
        DUPLICATE_SCAN_PROGRESS['progress'] = 0
        DUPLICATE_SCAN_PROGRESS['total'] = 0

    _update_duplicate_job(
        job_id,
        persist=True,
        state='running',
        phase='collecting',
        cancelled=False,
        progress=0,
        error=None,
        started_at=datetime.now().isoformat(),
    )

    def _cancelled(phase: str) -> dict:
        logger.add(f"중복 스캔 취소됨 ({phase})")
        with duplicate_scan_lock:
            DUPLICATE_SCAN_PROGRESS['running'] = False
            DUPLICATE_SCAN_PROGRESS['cancelled'] = True
            DUPLICATE_SCAN_PROGRESS['phase'] = phase
        _update_duplicate_job(
            job_id,
            persist=True,
            state='cancelled',
            phase=phase,
            cancelled=True,
            finished_at=datetime.now().isoformat(),
            error='duplicate scan cancelled',
        )
        return {}

    # 파일 크기별 그룹화 (빠른 필터링)
    size_groups = {}
    file_list = []

    # 1단계: 파일 목록 수집
    for root, dirs, files in os.walk(base_dir):
        # 취소 확인
        if is_scan_cancelled():
            return _cancelled('collecting')

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
        DUPLICATE_SCAN_PROGRESS['phase'] = 'hashing'
    _update_duplicate_job(job_id, persist=True, phase='hashing', total=len(file_list), progress=0)

    # 2단계: 동일 크기 파일만 해시 계산
    hash_groups = {}
    progress = 0

    for size, filepaths in size_groups.items():
        # 취소 확인
        if is_scan_cancelled():
            return _cancelled('hashing')

        if len(filepaths) < 2:
            progress += len(filepaths)
            continue

        for filepath in filepaths:
            # 취소 확인 (파일마다)
            if is_scan_cancelled():
                return _cancelled('hashing')

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
            if DUPLICATE_SCAN_PROGRESS.get('total', 0):
                percent = int((progress / max(1, int(DUPLICATE_SCAN_PROGRESS.get('total', 1)))) * 100)
                _update_duplicate_job(
                    job_id,
                    persist=(percent % 10 == 0),
                    progress=percent,
                    phase='hashing',
                )

    # 3단계: 중복 파일만 필터링
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['phase'] = 'finalizing'
    _update_duplicate_job(job_id, persist=True, phase='finalizing')
    groups = []
    for file_hash, files in hash_groups.items():
        if len(files) < 2:
            continue
        groups.append({
            'hash': file_hash,
            'size': files[0].get('size', 0),
            'files': files,
        })
    groups.sort(key=lambda g: g.get('size', 0), reverse=True)

    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['running'] = False
        DUPLICATE_SCAN_PROGRESS['cancelled'] = False
        DUPLICATE_SCAN_PROGRESS['results'] = groups
        DUPLICATE_SCAN_PROGRESS['last_scan'] = datetime.now().isoformat()
        DUPLICATE_SCAN_PROGRESS['phase'] = 'completed'

    # 결과 영속화 (서버 재시작 시에도 유지)
    save_duplicate_results()
    _update_duplicate_job(
        job_id,
        persist=True,
        state='completed',
        phase='completed',
        cancelled=False,
        progress=100,
        finished_at=datetime.now().isoformat(),
        stats={'groups': len(groups), 'files': len(file_list)},
    )

    logger.add(f"중복 스캔 완료: {len(groups)}개 그룹 발견")
    return {'groups': groups}
