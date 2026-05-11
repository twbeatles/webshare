"""
WebShare Pro - Trash Routes
휴지통 기능
"""

import os
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, request, session

from config import (
    conf, TRASH_FOLDER_NAME
)
from utils.api_errors import api_exception
from utils.log_manager import logger
from utils.file_utils import validate_path, safe_filename, get_real_ip
from utils.request_policy import ensure_mutation_allowed, ensure_path_access, parse_json_body
from security.auth import login_required
from features.trash import TRASH_METADATA_FILE, extract_original_name_from_trash, get_trash_metadata_entry
from features.audit_log import log_audit
from features.search_indexer import indexer

trash_bp = Blueprint('trash', __name__)


# ==========================================
# 휴지통으로 이동
# ==========================================

@trash_bp.route('/trash', methods=['POST'])
@login_required()
def move_to_trash():
    """파일을 휴지통으로 이동"""
    from features.trash import move_to_trash as move_to_trash_feature

    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'success': False, 'error': message}), status_code

    data = parse_json_body(request)
    path = data.get('path', '')

    ok, message, status_code = ensure_path_access(path, 'delete', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'}), 404

    try:
        success, result = move_to_trash_feature(full_path)
        if not success:
            return jsonify({'success': False, 'error': result}), 500
        logger.add(f"휴지통 이동: {path}")

        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='trash_move',
            target=path,
            details=f"Trash name: {result}",
            ip=get_real_ip()
        )
        indexer.update_event(conf.get('folder'))

        return jsonify({'success': True, 'trash_name': result})
    except Exception as exc:
        return api_exception('휴지통 이동 오류', exc, extra={'success': False})


# ==========================================
# 휴지통 목록
# ==========================================

@trash_bp.route('/trash/list')
@login_required('admin')
def list_trash():
    """휴지통 목록"""
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    if not os.path.exists(trash_dir):
        return jsonify({'items': []})

    items = []
    for name in os.listdir(trash_dir):
        full_path = os.path.join(trash_dir, name)
        try:
            stat = os.stat(full_path)
            metadata = get_trash_metadata_entry(name)
            items.append({
                'name': name,
                'original_name': os.path.basename(metadata.get('original_rel_path', '')) if metadata else extract_original_name_from_trash(name),
                'original_path': metadata.get('original_rel_path', '') if metadata else '',
                'id': metadata.get('id', '') if metadata else '',
                'is_dir': os.path.isdir(full_path),
                'size': stat.st_size,
                'deleted_at': metadata.get('deleted_at', '') if metadata else datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        except OSError:
            continue

    return jsonify({'items': items})


# ==========================================
# 휴지통 복원
# ==========================================

@trash_bp.route('/trash/restore', methods=['POST'])
@login_required('admin')
def restore_from_trash():
    """휴지통에서 복원"""
    from features.trash import restore_from_trash as restore_feature

    data = parse_json_body(request)
    name = data.get('name', '')

    success, result = restore_feature(name)

    if success:
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='trash_restore',
            target=name,
            details=f"Restored to: {os.path.basename(result)}",
            ip=get_real_ip()
        )
        indexer.update_event(conf.get('folder'))
        return jsonify({'success': True, 'restored_name': os.path.basename(result)})
    else:
        return jsonify({'success': False, 'error': result})


# ==========================================
# 휴지통 비우기
# ==========================================

@trash_bp.route('/trash/empty', methods=['POST'])
@login_required('admin')
def empty_trash():
    """휴지통 비우기"""
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    if os.path.exists(trash_dir):
        try:
            # 삭제 전 파일 수 계산
            item_count = len(os.listdir(trash_dir))
            shutil.rmtree(trash_dir)
            metadata_path = os.path.join(conf.get('folder'), TRASH_METADATA_FILE)
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            logger.add("휴지통 비움")

            # 감사 로그 기록
            log_audit(
                user=session.get('role', 'unknown'),
                action='trash_empty',
                target=TRASH_FOLDER_NAME,
                details=f"{item_count}개 항목 영구 삭제",
                ip=get_real_ip()
            )
            indexer.update_event(conf.get('folder'))

            return jsonify({'success': True})
        except Exception as exc:
            return api_exception('휴지통 비우기 오류', exc, extra={'success': False})
    return jsonify({'success': True})
