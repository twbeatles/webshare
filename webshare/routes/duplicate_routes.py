"""
WebShare Pro - Duplicate Routes
중복 파일 검사 API
"""

import os
import hashlib
import threading
from flask import Blueprint, jsonify, request, session

from ..config import (
    conf, duplicate_scan_lock, DUPLICATE_SCAN_PROGRESS
)
from ..utils.log_manager import logger
from ..utils.file_utils import validate_path
from ..security.auth import login_required
from ..features.audit_log import log_audit

duplicate_bp = Blueprint('duplicate', __name__)


def scan_duplicates(base_dir, min_size=1024):
    """중복 파일 스캔 (백그라운드)"""
    global DUPLICATE_SCAN_PROGRESS
    
    # 파일 크기별로 그룹화
    size_groups = {}
    all_files = []
    
    for root, dirs, files in os.walk(base_dir):
        # 숨김 폴더 제외
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for f in files:
            all_files.append((root, f))
    
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['total'] = len(all_files)
    
    for i, (root, filename) in enumerate(all_files):
        file_path = os.path.join(root, filename)
        try:
            size = os.path.getsize(file_path)
            if size >= min_size:
                if size not in size_groups:
                    size_groups[size] = []
                size_groups[size].append(file_path)
        except OSError:
            continue
        
        with duplicate_scan_lock:
            DUPLICATE_SCAN_PROGRESS['progress'] = i + 1
    
    # 크기가 같은 파일들만 해시 비교
    hash_groups = {}
    files_to_hash = [paths for paths in size_groups.values() if len(paths) > 1]
    
    for paths in files_to_hash:
        for path in paths:
            try:
                file_hash = hashlib.md5()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        file_hash.update(chunk)
                h = file_hash.hexdigest()
                
                if h not in hash_groups:
                    hash_groups[h] = []
                
                rel_path = os.path.relpath(path, base_dir)
                hash_groups[h].append({
                    'path': rel_path.replace('\\', '/'),
                    'size': os.path.getsize(path)
                })
            except Exception:
                continue
    
    # 중복 그룹만 반환
    results = [
        {'hash': h, 'files': files}
        for h, files in hash_groups.items()
        if len(files) > 1
    ]
    
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS['running'] = False
        DUPLICATE_SCAN_PROGRESS['results'] = results


@duplicate_bp.route('/api/duplicates', methods=['GET'])
@login_required('admin')
def get_duplicates():
    """중복 파일 검사 결과 조회"""
    with duplicate_scan_lock:
        return jsonify({
            'running': DUPLICATE_SCAN_PROGRESS['running'],
            'progress': DUPLICATE_SCAN_PROGRESS['progress'],
            'total': DUPLICATE_SCAN_PROGRESS['total'],
            'results': DUPLICATE_SCAN_PROGRESS['results']
        })


@duplicate_bp.route('/api/duplicates/scan', methods=['POST'])
@login_required('admin')
def start_duplicate_scan():
    """중복 파일 스캔 시작"""
    with duplicate_scan_lock:
        if DUPLICATE_SCAN_PROGRESS['running']:
            return jsonify({'error': '이미 스캔 중입니다.'}), 400
        
        DUPLICATE_SCAN_PROGRESS['running'] = True
        DUPLICATE_SCAN_PROGRESS['progress'] = 0
        DUPLICATE_SCAN_PROGRESS['total'] = 0
        DUPLICATE_SCAN_PROGRESS['results'] = []
    
    data = request.get_json() if request.is_json else {}
    min_size = data.get('min_size', 1024)
    
    # 백그라운드 스레드에서 실행
    thread = threading.Thread(
        target=scan_duplicates,
        args=(conf.get('folder'), min_size),
        daemon=True
    )
    thread.start()
    
    return jsonify({'success': True, 'message': '스캔이 시작되었습니다.'})


@duplicate_bp.route('/api/duplicates/delete', methods=['POST'])
@login_required('admin')
def delete_duplicates():
    """중복 파일 삭제 (휴지통으로 이동)"""
    from ..features.trash import move_to_trash
    from ..utils.file_utils import get_real_ip
    
    data = request.get_json()
    files_to_delete = data.get('files', [])
    
    deleted = 0
    base_dir = conf.get('folder')
    
    for file_path in files_to_delete:
        is_valid, full_path, _ = validate_path(base_dir, file_path)
        if is_valid and os.path.isfile(full_path):
            # 휴지통으로 이동
            success, result = move_to_trash(full_path)
            if success:
                deleted += 1
                log_audit(
                    session.get('role', 'admin'),
                    'delete_duplicate',
                    file_path,
                    details="휴지통 이동",
                    ip=get_real_ip()
                )
            else:
                logger.add(f"중복 파일 삭제 실패: {file_path} - {result}", "ERROR")
    
    return jsonify({'success': True, 'deleted': deleted})

