"""File browsing endpoints (search, info, clipboard, zip preview)."""

import os
import zipfile
import hashlib
import mimetypes
from datetime import datetime
from flask import request, jsonify, session
from config import conf
from utils.api_errors import api_exception
from utils.log_manager import logger
from utils.file_utils import validate_path, fmt_bytes, get_real_ip
from utils.request_policy import ensure_path_access, parse_json_body
from security.auth import login_required
from features.search_indexer import indexer
from webshare_app.services.file_service import _search_files_fallback
from ._common import MAX_CLIPBOARD_CONTENT_BYTES, MAX_CLIPBOARD_ENTRIES, _clipboard_lock, _clipboard_store, file_bp




# ==========================================
# 파일 검색
# ==========================================

@file_bp.route('/search')
@login_required()
def search_files():
    """서버 전체 파일 검색"""
    query = request.args.get('q', '').lower().strip()
    if not query or len(query) < 2:
        return jsonify({'results': [], 'error': '검색어는 2자 이상이어야 합니다.', 'indexing': False, 'search_mode': 'index'})

    base_dir = conf.get('folder')
    max_results = 100
    role = session.get('role', 'guest')
    index_results = []

    try:
        index_results = indexer.search(query, max_results)
    except Exception as e:
        logger.add(f"검색 오류: {e}", "ERROR")

    status = indexer.get_status()
    indexing = bool(status.get('is_indexing') or status.get('pending_update') or not status.get('last_indexed'))
    filtered = []
    seen_paths = set()

    for item in index_results:
        path = item.get('path', '')
        ok, _, _ = ensure_path_access(path, 'read', role=role)
        if not ok or path in seen_paths:
            continue
        filtered.append(item)
        seen_paths.add(path)
        if len(filtered) >= max_results:
            break

    search_mode = 'index'
    if indexing:
        fallback_results = _search_files_fallback(base_dir, query, role, max_results=max_results)
        if filtered:
            for item in fallback_results:
                path = item.get('path', '')
                if path in seen_paths:
                    continue
                filtered.append(item)
                seen_paths.add(path)
                if len(filtered) >= max_results:
                    break
            search_mode = 'hybrid'
        else:
            filtered = fallback_results
            search_mode = 'fallback'

    return jsonify({'results': filtered, 'count': len(filtered), 'indexing': indexing, 'search_mode': search_mode})




# ==========================================
# 파일 정보
# ==========================================

@file_bp.route('/file_info/<path:path>')
@login_required()
def get_file_info(path):
    """파일 상세 정보 조회"""
    ok, message, status_code = ensure_path_access(path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다.'}), 404

    stat = os.stat(full_path)
    info = {
        'name': os.path.basename(full_path),
        'path': path,
        'is_dir': os.path.isdir(full_path),
        'size': stat.st_size,
        'size_fmt': fmt_bytes(stat.st_size),
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
    }

    if not info['is_dir']:
        # 10MB 이하 파일 해시 계산
        if stat.st_size < 10 * 1024 * 1024:
            try:
                md5_hash = hashlib.md5()
                with open(full_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        md5_hash.update(chunk)
                info['md5'] = md5_hash.hexdigest()
            except Exception:
                pass

        mime_type, _ = mimetypes.guess_type(full_path)
        info['mime_type'] = mime_type or 'application/octet-stream'
    else:
        try:
            items = os.listdir(full_path)
            info['file_count'] = len([i for i in items if os.path.isfile(os.path.join(full_path, i))])
            info['folder_count'] = len([i for i in items if os.path.isdir(os.path.join(full_path, i))])
        except Exception:
            pass

    return jsonify(info)




# ==========================================
# 클립보드
# ==========================================

@file_bp.route('/clipboard', methods=['GET', 'POST'])
@login_required()
def clipboard_handler():
    """클립보드 핸들러 (스레드 안전)"""
    owner_sid = session.get('session_id', '') or ''
    owner_role = session.get('role', 'guest')
    owner_ip = get_real_ip()
    owner_key = owner_sid or f"{owner_role}:{owner_ip}"

    if request.method == 'POST':
        data = parse_json_body(request)
        content = data.get('content', '')
        if isinstance(content, str) and len(content.encode('utf-8')) > MAX_CLIPBOARD_CONTENT_BYTES:
            return jsonify({
                'success': False,
                'error': f'클립보드 내용은 {MAX_CLIPBOARD_CONTENT_BYTES}바이트 이하여야 합니다',
            }), 413
        with _clipboard_lock:
            _clipboard_store[owner_key] = content if isinstance(content, str) else str(content)
            _clipboard_store.move_to_end(owner_key)
            while len(_clipboard_store) > MAX_CLIPBOARD_ENTRIES:
                _clipboard_store.popitem(last=False)
        return jsonify({'success': True})

    with _clipboard_lock:
        content = _clipboard_store.get(owner_key, '')
    return jsonify({'content': content})




# ==========================================
# ZIP 미리보기 (v7.2.3)
# ==========================================

@file_bp.route('/api/zip_preview/<path:filepath>')
@login_required()
def zip_preview(filepath):
    """ZIP 파일 내용 미리보기"""
    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    # 경로 검증
    valid, full_path, error = validate_path(base_dir, filepath)
    if not valid:
        return jsonify({'error': error}), 400

    if not os.path.exists(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다'}), 404

    # ZIP 파일 확인
    ext = os.path.splitext(full_path)[1].lower()
    if ext not in ['.zip', '.jar', '.war', '.apk']:
        return jsonify({'error': 'ZIP 형식 파일만 지원됩니다'}), 400

    try:
        items = []
        with zipfile.ZipFile(full_path, 'r') as zf:
            for info in zf.infolist():
                items.append({
                    'name': info.filename,
                    'size': info.file_size,
                    'compressed_size': info.compress_size,
                    'is_dir': info.is_dir(),
                    'date': datetime(*info.date_time).isoformat() if info.date_time else None
                })

                # Zip Bomb Check (Preview)
                if info.file_size > 0 and info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > 200 and info.file_size > 50 * 1024 * 1024: # Preview는 조금 더 관대하게 (200배, 50MB 이상)
                         logger.add(f"Zip Bomb 의심 (Preview): {info.filename} ({ratio:.1f}x)", "WARN")

        return jsonify({
            'success': True,
            'filename': os.path.basename(full_path),
            'total_files': len([i for i in items if not i['is_dir']]),
            'total_folders': len([i for i in items if i['is_dir']]),
            'items': items[:500]  # 최대 500개 항목
        })
    except zipfile.BadZipFile:
        return jsonify({'error': '손상된 ZIP 파일입니다'}), 400
    except Exception as exc:
        return api_exception('ZIP 미리보기 오류', exc)

