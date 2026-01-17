"""
WebShare Pro - Metadata Routes
태그, 즐겨찾기, 메모, 북마크, 버전 관리
"""

import os
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, request

from ..config import (
    conf, FILE_TAGS, FAVORITE_FOLDERS, FILE_MEMOS, BOOKMARKS,
    metadata_lock, VERSION_FOLDER_NAME
)
from ..utils.log_manager import logger
from ..utils.file_utils import validate_path, safe_filename
from ..security.auth import login_required
from ..features.metadata import save_metadata

metadata_bp = Blueprint('metadata', __name__)


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
            with metadata_lock:
                return jsonify({'tags': FILE_TAGS.get(path, [])})
        with metadata_lock:
            return jsonify({'all_tags': FILE_TAGS.copy()})
    
    data = request.get_json()
    path = data.get('path', '')
    
    if request.method == 'POST':
        tag = data.get('tag', '')
        color = data.get('color', '#6366f1')
        
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
        tag = data.get('tag', '')
        with metadata_lock:
            if path in FILE_TAGS:
                FILE_TAGS[path] = [t for t in FILE_TAGS[path] if t['tag'] != tag]
                if not FILE_TAGS[path]:
                    del FILE_TAGS[path]
        save_metadata()
        return jsonify({'success': True})


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
            return jsonify({'favorites': list(FAVORITE_FOLDERS)})
    
    data = request.get_json()
    path = data.get('path', '')
    name = data.get('name', os.path.basename(path) if path else '')
    
    if request.method == 'POST':
        if not path:
            return jsonify({'success': False, 'error': '경로가 필요합니다.'})
        
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
        with metadata_lock:
            FAVORITE_FOLDERS[:] = [f for f in FAVORITE_FOLDERS if f['path'] != path]
        save_metadata()
        return jsonify({'success': True})


# ==========================================
# 파일 메모 관리
# ==========================================

@metadata_bp.route('/api/memo/<path:filepath>', methods=['GET', 'POST', 'DELETE'])
@login_required()
def api_file_memo(filepath):
    """파일 메모 관리"""
    global FILE_MEMOS
    
    if request.method == 'GET':
        with metadata_lock:
            memo = FILE_MEMOS.get(filepath, {})
        return jsonify({'memo': memo.get('memo', ''), 'updated': memo.get('updated', '')})
    
    if request.method == 'POST':
        data = request.get_json()
        memo_text = data.get('memo', '')
        
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
            return jsonify({'bookmarks': list(BOOKMARKS)})
    
    elif request.method == 'POST':
        data = request.get_json()
        path = data.get('path', '')
        name = data.get('name', os.path.basename(path))
        
        with metadata_lock:
            if any(b['path'] == path for b in BOOKMARKS):
                return jsonify({'success': False, 'error': '이미 북마크되어 있습니다.'})
            
            BOOKMARKS.append({'path': path, 'name': name, 'added': datetime.now().isoformat()})
        save_metadata()
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        data = request.get_json()
        path = data.get('path', '')
        with metadata_lock:
            BOOKMARKS[:] = [b for b in BOOKMARKS if b['path'] != path]
        save_metadata()
        return jsonify({'success': True})


# ==========================================
# 파일 버전 관리
# ==========================================

@metadata_bp.route('/versions/<path:filepath>')
@login_required('admin')
def list_versions(filepath):
    """파일 버전 목록 조회"""
    filename = os.path.basename(filepath)
    version_dir = os.path.join(conf.get('folder'), VERSION_FOLDER_NAME)
    if not os.path.exists(version_dir):
        return jsonify({'versions': []})
    versions = []
    for f in os.listdir(version_dir):
        if f.endswith(f'_{filename}'):
            full_path = os.path.join(version_dir, f)
            versions.append({
                'name': f, 
                'timestamp': f.rsplit('_', 1)[0], 
                'size': os.path.getsize(full_path)
            })
    versions.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'versions': versions})


@metadata_bp.route('/versions/restore', methods=['POST'])
@login_required('admin')
def restore_version():
    """파일 버전 복원"""
    data = request.get_json()
    version_name = data.get('version', '')
    target_path = data.get('target', '')
    version_dir = os.path.join(conf.get('folder'), VERSION_FOLDER_NAME)
    version_path = os.path.join(version_dir, safe_filename(version_name))
    is_valid, full_target, _ = validate_path(conf.get('folder'), target_path)
    if not os.path.exists(version_path) or not is_valid:
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'})
    try:
        shutil.copy2(version_path, full_target)
        logger.add(f"버전 복원: {version_name} -> {target_path}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
