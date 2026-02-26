"""
WebShare Pro - Duplicate Routes
중복 파일 검사 API
"""

import os
import threading
from flask import Blueprint, jsonify, request, session

from config import conf, duplicate_scan_lock, DUPLICATE_SCAN_PROGRESS
from utils.log_manager import logger
from utils.file_utils import validate_path
from utils.request_policy import ensure_path_access, parse_json_body
from security.auth import login_required
from features.audit_log import log_audit
from features.duplicates import scan_duplicates

duplicate_bp = Blueprint('duplicate', __name__)


@duplicate_bp.route('/api/duplicates', methods=['GET'])
@login_required('admin')
def get_duplicates():
    """중복 파일 검사 결과 조회"""
    with duplicate_scan_lock:
        return jsonify({
            'running': DUPLICATE_SCAN_PROGRESS.get('running', False),
            'progress': DUPLICATE_SCAN_PROGRESS.get('progress', 0),
            'total': DUPLICATE_SCAN_PROGRESS.get('total', 0),
            'results': DUPLICATE_SCAN_PROGRESS.get('results', []),
            'last_scan': DUPLICATE_SCAN_PROGRESS.get('last_scan', ''),
        })


@duplicate_bp.route('/api/duplicates/scan', methods=['POST'])
@login_required('admin')
def start_duplicate_scan():
    """중복 파일 스캔 시작"""
    with duplicate_scan_lock:
        if DUPLICATE_SCAN_PROGRESS.get('running'):
            return jsonify({'error': '이미 스캔 중입니다.'}), 400
        DUPLICATE_SCAN_PROGRESS['running'] = True
        DUPLICATE_SCAN_PROGRESS['progress'] = 0
        DUPLICATE_SCAN_PROGRESS['total'] = 0

    data = parse_json_body(request)
    min_size = data.get('min_size', 1024)
    try:
        min_size = int(min_size)
    except (TypeError, ValueError):
        min_size = 1024

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
    from features.trash import move_to_trash
    from utils.file_utils import get_real_ip

    data = parse_json_body(request)
    files_to_delete = data.get('files', [])

    deleted = 0
    base_dir = conf.get('folder')

    for file_path in files_to_delete:
        ok, _, _ = ensure_path_access(file_path, 'delete')
        if not ok:
            continue
        is_valid, full_path, _ = validate_path(base_dir, file_path)
        if is_valid and os.path.isfile(full_path):
            success, result = move_to_trash(full_path)
            if success:
                deleted += 1
                log_audit(
                    session.get('role', 'admin'),
                    'delete_duplicate',
                    file_path,
                    details='휴지통 이동',
                    ip=get_real_ip()
                )
            else:
                logger.add(f"중복 파일 삭제 실패: {file_path} - {result}", "ERROR")

    return jsonify({'success': True, 'deleted': deleted})
