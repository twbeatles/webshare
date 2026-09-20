"""Permission management endpoints."""

from flask import jsonify, request
from config import FOLDER_PERMISSIONS, permissions_lock
from utils.log_manager import logger
from security.auth import login_required
from security.permissions import normalize_permission_entry, normalize_permission_path, save_permissions
from utils.request_policy import parse_json_body
from ._common import admin_bp




# ==========================================
# 폴더 권한 관리
# ==========================================

@admin_bp.route('/api/permissions', methods=['GET', 'POST'])
@login_required('admin')
def manage_permissions():
    """폴더 권한 관리"""
    if request.method == 'GET':
        with permissions_lock:
            return jsonify({'permissions': FOLDER_PERMISSIONS.copy()})

    elif request.method == 'POST':
        data = parse_json_body(request)
        path = data.get('path', '')
        read_users = data.get('read', ['*'])
        write_users = data.get('write', ['*'])
        delete_users = data.get('delete', ['admin'])

        try:
            path, normalized_entry = normalize_permission_entry(path, {
                'read': read_users,
                'write': write_users,
                'delete': delete_users
            })
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400

        with permissions_lock:
            FOLDER_PERMISSIONS[path] = normalized_entry
        save_permissions()

        logger.add(f"폴더 권한 설정: {path}")
        return jsonify({'success': True})

    return jsonify({'success': False, 'error': '지원하지 않는 메서드입니다.'}), 405




@admin_bp.route('/api/permissions/<path:path>', methods=['GET', 'PUT', 'DELETE'])
@login_required('admin')
def manage_folder_permission(path):
    """특정 폴더 권한 관리"""
    try:
        path = normalize_permission_path(path)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    if request.method == 'GET':
        with permissions_lock:
            perm = FOLDER_PERMISSIONS.get(path, {})
        return jsonify({'path': path, 'permission': perm})

    elif request.method == 'PUT':
        data = parse_json_body(request)
        try:
            _, normalized_entry = normalize_permission_entry(path, data)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        with permissions_lock:
            if path not in FOLDER_PERMISSIONS:
                FOLDER_PERMISSIONS[path] = {}
            FOLDER_PERMISSIONS[path].update(normalized_entry)
        save_permissions()
        logger.add(f"폴더 권한 수정: {path}")
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        with permissions_lock:
            if path in FOLDER_PERMISSIONS:
                del FOLDER_PERMISSIONS[path]
                save_permissions()
                logger.add(f"폴더 권한 삭제: {path}")
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': '권한을 찾을 수 없습니다.'})

    return jsonify({'success': False, 'error': '지원하지 않는 메서드입니다.'}), 405

