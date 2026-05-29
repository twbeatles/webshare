"""
WebShare Pro - Metadata Routes
태그, 즐겨찾기, 메모, 북마크, 버전 관리
"""

import os
import re
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, request, session

from config import (
    conf, FILE_TAGS, FAVORITE_FOLDERS, FILE_MEMOS, BOOKMARKS,
    metadata_lock, VERSION_FOLDER_NAME
)
from utils.api_errors import api_exception
from utils.log_manager import logger
from utils.file_utils import validate_path, get_real_ip
from utils.request_policy import ensure_path_access, parse_json_body
from security.auth import login_required
from features.metadata import save_metadata
from features.audit_log import log_audit
from utils.helpers import create_file_version, version_name_matches_rel_path

metadata_bp = Blueprint('metadata', __name__)

MAX_TAG_LENGTH = 64
MAX_MEMO_LENGTH = 10000
MAX_METADATA_NAME_LENGTH = 200
TAG_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _bounded_text(value, max_length: int) -> str:
    text = str(value or "").strip()
    if len(text) > max_length:
        raise ValueError(f"value too long (max={max_length})")
    return text


def _can_read_path(path: str) -> bool:
    ok, _, _ = ensure_path_access(path, 'read')
    return ok


# ==========================================
# 파일 태그 관리
# ==========================================

@metadata_bp.route('/api/tags', methods=['GET', 'POST', 'DELETE'])
@login_required()
def api_file_tags():
    """파일 태그 관리"""
    global FILE_TAGS

    if request.method == 'GET':
        path = request.args.get('path', '')
        if path:
            ok, message, status_code = ensure_path_access(path, 'read')
            if not ok:
                return jsonify({'error': message}), status_code
            with metadata_lock:
                return jsonify({'tags': FILE_TAGS.get(path, [])})
        with metadata_lock:
            filtered = {p: tags for p, tags in FILE_TAGS.items() if _can_read_path(p)}
            return jsonify({'all_tags': filtered})

    data = parse_json_body(request)
    path = data.get('path', '')
    ok, message, status_code = ensure_path_access(path, 'write')
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code

    if request.method == 'POST':
        try:
            tag = _bounded_text(data.get('tag', ''), MAX_TAG_LENGTH)
            color = str(data.get('color', '#6366f1') or '#6366f1')
            if not TAG_COLOR_RE.fullmatch(color):
                raise ValueError("invalid tag color")
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

        if not path or not tag:
            return jsonify({'success': False, 'error': '경로와 태그가 필요합니다.'})

        with metadata_lock:
            if path not in FILE_TAGS:
                FILE_TAGS[path] = []

            if any(t['tag'] == tag for t in FILE_TAGS[path]):
                return jsonify({'success': False, 'error': '이미 존재하는 태그입니다.'})

            FILE_TAGS[path].append({'tag': tag, 'color': color})
        save_metadata()
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        try:
            tag = _bounded_text(data.get('tag', ''), MAX_TAG_LENGTH)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        with metadata_lock:
            if path in FILE_TAGS:
                FILE_TAGS[path] = [t for t in FILE_TAGS[path] if t['tag'] != tag]
                if not FILE_TAGS[path]:
                    del FILE_TAGS[path]
        save_metadata()
        return jsonify({'success': True})

    return jsonify({'success': False, 'error': '지원하지 않는 메서드입니다.'}), 405


# ==========================================
# 즐겨찾기 관리
# ==========================================

@metadata_bp.route('/api/favorites', methods=['GET', 'POST', 'DELETE'])
@login_required()
def api_favorites():
    """즐겨찾기 폴더 관리"""
    global FAVORITE_FOLDERS

    if request.method == 'GET':
        with metadata_lock:
            filtered = [item for item in FAVORITE_FOLDERS if _can_read_path(item.get('path', ''))]
            return jsonify({'favorites': filtered})

    data = parse_json_body(request)
    path = data.get('path', '')
    try:
        name = _bounded_text(data.get('name', os.path.basename(path) if path else ''), MAX_METADATA_NAME_LENGTH)
    except ValueError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    if request.method == 'POST':
        if not path:
            return jsonify({'success': False, 'error': '경로가 필요합니다.'})
        ok, message, status_code = ensure_path_access(path, 'read')
        if not ok:
            return jsonify({'success': False, 'error': message}), status_code

        with metadata_lock:
            if any(f['path'] == path for f in FAVORITE_FOLDERS):
                return jsonify({'success': False, 'error': '이미 즐겨찾기에 추가되어 있습니다.'})

            FAVORITE_FOLDERS.append({
                'path': path,
                'name': name,
                'added': datetime.now().isoformat()
            })
        save_metadata()
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        if path:
            ok, message, status_code = ensure_path_access(path, 'read')
            if not ok:
                return jsonify({'success': False, 'error': message}), status_code
        with metadata_lock:
            FAVORITE_FOLDERS[:] = [f for f in FAVORITE_FOLDERS if f['path'] != path]
        save_metadata()
        return jsonify({'success': True})

    return jsonify({'success': False, 'error': '지원하지 않는 메서드입니다.'}), 405


# ==========================================
# 파일 메모 관리
# ==========================================

@metadata_bp.route('/api/memo/<path:filepath>', methods=['GET', 'POST', 'DELETE'])
@login_required()
def api_file_memo(filepath):
    """파일 메모 관리"""
    global FILE_MEMOS

    action = 'read' if request.method == 'GET' else 'write'
    ok, message, status_code = ensure_path_access(filepath, action)
    if not ok:
        return jsonify({'error': message}), status_code

    if request.method == 'GET':
        with metadata_lock:
            memo = FILE_MEMOS.get(filepath, {})
        return jsonify({'memo': memo.get('memo', ''), 'updated': memo.get('updated', '')})

    if request.method == 'POST':
        data = parse_json_body(request)
        try:
            memo_text = _bounded_text(data.get('memo', ''), MAX_MEMO_LENGTH)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

        with metadata_lock:
            FILE_MEMOS[filepath] = {
                'memo': memo_text,
                'updated': datetime.now().isoformat()
            }
        save_metadata()
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        with metadata_lock:
            if filepath in FILE_MEMOS:
                del FILE_MEMOS[filepath]
        save_metadata()
        return jsonify({'success': True})

    return jsonify({'success': False, 'error': '지원하지 않는 메서드입니다.'}), 405


# ==========================================
# 북마크 관리
# ==========================================

@metadata_bp.route('/bookmarks', methods=['GET', 'POST', 'DELETE'])
@login_required()
def handle_bookmarks():
    """북마크 관리"""
    global BOOKMARKS

    if request.method == 'GET':
        with metadata_lock:
            filtered = [item for item in BOOKMARKS if _can_read_path(item.get('path', ''))]
            return jsonify({'bookmarks': filtered})

    elif request.method == 'POST':
        data = parse_json_body(request)
        path = data.get('path', '')
        try:
            name = _bounded_text(data.get('name', os.path.basename(path)), MAX_METADATA_NAME_LENGTH)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        ok, message, status_code = ensure_path_access(path, 'read')
        if not ok:
            return jsonify({'success': False, 'error': message}), status_code

        with metadata_lock:
            if any(b['path'] == path for b in BOOKMARKS):
                return jsonify({'success': False, 'error': '이미 북마크되어 있습니다.'})

            BOOKMARKS.append({'path': path, 'name': name, 'added': datetime.now().isoformat()})
        save_metadata()
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        data = parse_json_body(request)
        path = data.get('path', '')
        if path:
            ok, message, status_code = ensure_path_access(path, 'read')
            if not ok:
                return jsonify({'success': False, 'error': message}), status_code
        with metadata_lock:
            BOOKMARKS[:] = [b for b in BOOKMARKS if b['path'] != path]
        save_metadata()
        return jsonify({'success': True})

    return jsonify({'success': False, 'error': '지원하지 않는 메서드입니다.'}), 405


# ==========================================
# 파일 버전 관리
# ==========================================

@metadata_bp.route('/versions/<path:filepath>')
@login_required('admin')
def list_versions(filepath):
    """파일 버전 목록 조회"""
    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    rel_path = filepath.replace('\\', '/')
    version_dir = os.path.join(conf.get('folder'), VERSION_FOLDER_NAME)
    if not os.path.exists(version_dir):
        return jsonify({'versions': []})
    versions = []
    for f in os.listdir(version_dir):
        if version_name_matches_rel_path(f, rel_path):
            full_path = os.path.join(version_dir, f)
            versions.append({
                'name': f,
                'timestamp': f[:15],
                'size': os.path.getsize(full_path)
            })
    versions.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'versions': versions})


@metadata_bp.route('/versions/restore', methods=['POST'])
@login_required('admin')
def restore_version():
    """파일 버전 복원"""
    data = parse_json_body(request)
    version_name = data.get('version', '')
    target_path = data.get('target', '')
    ok, message, status_code = ensure_path_access(target_path, 'write')
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    version_dir = os.path.join(conf.get('folder'), VERSION_FOLDER_NAME)
    normalized_target = target_path.replace('\\', '/')
    safe_version_name = os.path.basename(str(version_name))
    is_valid, full_target, _ = validate_path(conf.get('folder'), target_path)
    if safe_version_name != version_name or not version_name_matches_rel_path(safe_version_name, normalized_target):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'})
    version_path = os.path.join(version_dir, safe_version_name)
    if not os.path.exists(version_path) or not is_valid:
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'})
    try:
        create_file_version(full_target)
        shutil.copy2(version_path, full_target)
        logger.add(f"버전 복원: {version_name} -> {target_path}")

        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='version_restore',
            target=target_path,
            details=f"버전: {version_name}",
            ip=get_real_ip()
        )

        return jsonify({'success': True})
    except Exception as exc:
        return api_exception('버전 복원 오류', exc, extra={'success': False})
