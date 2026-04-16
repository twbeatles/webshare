"""
WebShare Pro - File Routes
파일 다운로드, 업로드, 관리 라우트
"""

import os
import threading
import shutil
import zipfile
import json
import hashlib
import mimetypes
import time
from datetime import datetime
from collections import OrderedDict
from flask import Blueprint, request, send_file, jsonify, session

from config import conf, STATS, stats_lock, ACCESS_LOG, access_log_lock
from utils.api_errors import api_exception
from utils.log_manager import logger, log_access
from utils.file_utils import validate_path, safe_filename, fmt_bytes, get_real_ip, get_file_type
from utils.zip_utils import create_temp_zip_from_items, make_zip_stream_response
from utils.request_policy import (
    ensure_mutation_allowed,
    ensure_path_access,
    is_protected_system_path,
    parse_json_body,
)
from security.auth import login_required
from features.audit_log import log_audit
from features.trash import move_to_trash
from features.search_indexer import indexer
from utils.helpers import add_recent_file, build_download_tracker_key, build_recent_owner_key

file_bp = Blueprint('file', __name__)

# 클립보드 저장소 (스레드 안전성을 위한 락 사용)
_clipboard_lock = threading.Lock()
_clipboard_store = OrderedDict()
MAX_CLIPBOARD_ENTRIES = 200


def _recent_owner_key() -> str:
    return build_recent_owner_key(
        session_id=session.get('session_id', '') or '',
        role=session.get('role', 'guest') or 'guest',
        ip=get_real_ip(),
    )


def _next_available_directory_path(base_path: str) -> str:
    candidate = base_path
    counter = 1
    while os.path.exists(candidate):
        candidate = f"{base_path}_{counter}"
        counter += 1
    return candidate


def _collect_allowed_zip_files(
    base_dir: str,
    root_abs: str,
    root_rel: str,
    role: str,
    arc_prefix: str = "",
):
    """
    ZIP 포함 가능 파일 목록 수집.
    - 보호 경로 제외
    - 파일 단위 read 권한 검사
    """
    zip_items = []
    normalized_root_rel = (root_rel or "").replace("\\", "/").strip("/")
    normalized_prefix = (arc_prefix or "").replace("\\", "/").strip("/")

    for walk_root, dirs, files in os.walk(root_abs):
        rel_dir = os.path.relpath(walk_root, root_abs).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""

        filtered_dirs = []
        for name in sorted(dirs):
            rel_path = "/".join(part for part in [normalized_root_rel, rel_dir, name] if part)
            if is_protected_system_path(rel_path):
                continue
            ok, _, _ = ensure_path_access(rel_path, "read", role=role)
            if ok:
                filtered_dirs.append(name)
        dirs[:] = filtered_dirs

        for name in sorted(files):
            rel_path = "/".join(part for part in [normalized_root_rel, rel_dir, name] if part)
            if is_protected_system_path(rel_path):
                continue

            ok, _, _ = ensure_path_access(rel_path, "read", role=role)
            if not ok:
                continue

            is_valid, abs_path, _ = validate_path(base_dir, rel_path)
            if not is_valid or not os.path.isfile(abs_path):
                continue

            arc_rel = os.path.relpath(abs_path, root_abs).replace("\\", "/")
            arcname = f"{normalized_prefix}/{arc_rel}" if normalized_prefix else arc_rel
            zip_items.append((abs_path, arcname))

    return zip_items


def _search_files_fallback(
    base_dir: str,
    query: str,
    role: str,
    max_results: int = 100,
    time_budget_seconds: float = 1.5,
) -> list[dict]:
    normalized_query = (query or "").strip().lower()
    if not normalized_query:
        return []

    results = []
    deadline = time.monotonic() + max(0.1, float(time_budget_seconds))
    for root, dirs, files in os.walk(base_dir):
        if time.monotonic() >= deadline:
            logger.add(f"검색 fallback 시간 예산 초과: query={normalized_query}", "WARN")
            break
        dirs[:] = [name for name in dirs if not name.startswith('.')]

        for name in dirs + files:
            if time.monotonic() >= deadline:
                logger.add(f"검색 fallback 시간 예산 초과: query={normalized_query}", "WARN")
                return results
            if name.startswith('.'):
                continue
            if normalized_query not in name.lower():
                continue

            abs_path = os.path.join(root, name)
            rel_path = os.path.relpath(abs_path, base_dir).replace('\\', '/')
            ok, _, _ = ensure_path_access(rel_path, 'read', role=role)
            if not ok:
                continue

            results.append(
                {
                    'name': name,
                    'path': rel_path,
                    'is_dir': os.path.isdir(abs_path),
                }
            )
            if len(results) >= max_results:
                return results
    return results


def _estimate_zip_transfer_bytes(zip_items: list[tuple[str, str]]) -> int:
    total = 0
    for abs_path, _arcname in zip_items:
        try:
            total += os.path.getsize(abs_path)
        except OSError:
            continue
    return total


@file_bp.route('/download/<path:filepath>')
@login_required()
def download(filepath):
    """파일 다운로드"""
    from utils.helpers import check_download_limit, track_download
    
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
    
    if os.path.isdir(full_path):
        return jsonify({'error': '폴더는 다운로드할 수 없습니다'}), 400
    
    try:
        file_size = os.path.getsize(full_path)
        client_ip = get_real_ip()
        tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
        allowed, limit_msg = check_download_limit(tracker_key, True, projected_bytes=file_size)
        if not allowed:
            return jsonify({'error': limit_msg}), 429
        
        # v5.1: 다운로드 기록 추적
        track_download(tracker_key, file_size)
        
        # 감사 로그
        log_audit(
            session.get('role', 'guest'),
            'download',
            filepath,
            f"Size: {fmt_bytes(file_size)}",
            ip=client_ip
        )
        
        log_access(client_ip, 'download', filepath)
        logger.add(f"다운로드: {filepath}")
        add_recent_file(
            filepath,
            os.path.basename(full_path),
            get_file_type(os.path.splitext(full_path)[1]),
            owner_key=_recent_owner_key(),
        )
        return send_file(full_path, as_attachment=True)
        
    except Exception as exc:
        return api_exception('다운로드 오류', exc)


@file_bp.route('/upload/<path:folderpath>', methods=['POST'])
@file_bp.route('/upload/', methods=['POST'])
@login_required()
def upload(folderpath=''):
    """파일 업로드"""
    # 권한 확인
    role = session.get('role')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'error': message}), status_code

    ok, message, status_code = ensure_path_access(folderpath, 'write', role=role)
    if not ok:
        return jsonify({'error': message}), status_code
    
    base_dir = conf.get('folder')
    
    # 경로 검증
    valid, full_path, error = validate_path(base_dir, folderpath)
    if not valid:
        return jsonify({'error': error}), 400
    
    if 'file' not in request.files:
        return jsonify({'error': '파일이 없습니다'}), 400
    
    uploaded_files = request.files.getlist('file')
    paths = request.form.getlist('paths')
    results = []
    total_size = 0
    client_ip = get_real_ip()
    
    for i, file in enumerate(uploaded_files):
        raw_filename = file.filename or ''
        if raw_filename == '':
            continue
        
        # 안전한 파일명 생성
        filename = safe_filename(raw_filename)
        
        # 폴더 구조 유지 (드래그&드롭 폴더 업로드)
        if paths and len(paths) > i and '/' in paths[i]:
            rel_path = paths[i]
            if '..' not in rel_path:
                parts = rel_path.split('/')
                safe_parts = [safe_filename(p) for p in parts]
                file_path = os.path.join(full_path, *safe_parts)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
            else:
                file_path = os.path.join(full_path, filename)
        else:
            file_path = os.path.join(full_path, filename)

        # 시스템 경로 및 권한 검증
        rel_save_path = os.path.relpath(file_path, base_dir).replace('\\', '/')
        ok, message, _ = ensure_path_access(rel_save_path, 'write', role=role)
        if not ok or is_protected_system_path(rel_save_path):
            results.append({'name': filename, 'success': False, 'error': '업로드 권한이 없습니다'})
            continue
        
        # 동일 파일명 처리
        if os.path.exists(file_path):
            parent_dir = os.path.dirname(file_path)
            original_name = os.path.basename(file_path)
            name, ext = os.path.splitext(original_name)
            counter = 1
            while os.path.exists(file_path):
                filename = f"{name}_{counter}{ext}"
                file_path = os.path.join(parent_dir, filename)
                counter += 1
        
        try:
            file.save(file_path)
            file_size = os.path.getsize(file_path)
            total_size += file_size
            
            log_audit(
                session.get('role', 'guest'),
                'upload',
                f"{folderpath}/{filename}",
                f"Size: {fmt_bytes(file_size)}",
                ip=client_ip
            )
            
            results.append({'name': filename, 'success': True})
            logger.add(f"업로드: {filename}")
            
            # 검색 인덱스 업데이트 (비동기)
            indexer.update_event(base_dir)
            
        except Exception as exc:
            results.append({'name': filename, 'success': False, 'error': '파일 저장 중 오류가 발생했습니다.'})
            logger.add(f"업로드 오류: {exc}", "ERROR")
    
    with stats_lock:
        STATS['bytes_received'] += total_size
    
    return jsonify({'success': True, 'files': results})


@file_bp.route('/mkdir/<path:folderpath>', methods=['POST'])
@file_bp.route('/mkdir/', methods=['POST'])
@login_required()
def mkdir(folderpath=''):
    """폴더 생성"""
    role = session.get('role')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'error': message}), status_code

    ok, message, status_code = ensure_path_access(folderpath, 'write', role=role)
    if not ok:
        return jsonify({'error': message}), status_code
    
    base_dir = conf.get('folder')
    data = parse_json_body(request)
    folder_name = data.get('name', '')
    
    if not folder_name:
        return jsonify({'error': '폴더 이름이 필요합니다'}), 400
    
    folder_name = safe_filename(folder_name)
    
    valid, parent_path, error = validate_path(base_dir, folderpath)
    if not valid:
        return jsonify({'error': error}), 400

    new_rel = os.path.join(folderpath, folder_name).replace('\\', '/')
    ok, message, status_code = ensure_path_access(new_rel, 'write', role=role)
    if not ok:
        return jsonify({'error': message}), status_code
    
    new_folder = os.path.join(parent_path, folder_name)
    
    if os.path.exists(new_folder):
        return jsonify({'error': '이미 존재하는 폴더입니다'}), 400
    
    try:
        os.makedirs(new_folder)
        log_audit(
            session.get('role', 'guest'),
            'mkdir',
            f"{folderpath}/{folder_name}",
            ip=get_real_ip()
        )
        logger.add(f"폴더 생성: {folder_name}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        return jsonify({'success': True})
    except Exception as exc:
        return api_exception('폴더 생성 오류', exc)


@file_bp.route('/delete/<path:filepath>', methods=['POST'])
@login_required()
def delete(filepath):
    """파일/폴더 삭제 (휴지통으로 이동)"""
    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'error': message}), status_code

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(filepath, 'delete', role=role)
    if not ok:
        return jsonify({'error': message}), status_code
    
    valid, full_path, error = validate_path(base_dir, filepath)
    if not valid:
        return jsonify({'error': error}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다'}), 404
    
    # 휴지통으로 이동
    success, result = move_to_trash(full_path)
    
    if success:
        log_audit(
            session.get('role', 'guest'),
            'delete',
            filepath,
            f"Moved to trash: {result}",
            ip=get_real_ip()
        )
        logger.add(f"삭제 (휴지통): {filepath}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        return jsonify({'success': True})
    else:
        return jsonify({'error': result}), 500


@file_bp.route('/rename/<path:filepath>', methods=['POST'])
@login_required()
def rename(filepath):
    """파일/폴더 이름 변경"""
    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'error': message}), status_code

    base_dir = conf.get('folder')
    data = parse_json_body(request)
    new_name = data.get('name', '') or data.get('new_name', '')
    old_name = data.get('old_name', '')
    
    if not new_name:
        return jsonify({'error': '새 이름이 필요합니다'}), 400
    
    new_name = safe_filename(new_name)
    
    # old_name이 있으면 filepath를 부모 폴더로 사용
    if old_name:
        old_rel = os.path.join(filepath, safe_filename(old_name)).replace('\\', '/')
        ok, message, status_code = ensure_path_access(old_rel, 'delete', role=role)
        if not ok:
            return jsonify({'error': message}), status_code
        ok, message, status_code = ensure_path_access(filepath, 'write', role=role)
        if not ok:
            return jsonify({'error': message}), status_code
        valid, parent_path, error = validate_path(base_dir, filepath)
        if not valid:
            return jsonify({'error': error}), 400
        full_path = os.path.join(parent_path, safe_filename(old_name))
        new_path = os.path.join(parent_path, new_name)
    else:
        ok, message, status_code = ensure_path_access(filepath, 'delete', role=role)
        if not ok:
            return jsonify({'error': message}), status_code
        valid, full_path, error = validate_path(base_dir, filepath)
        if not valid:
            return jsonify({'error': error}), 400
        parent_dir = os.path.dirname(full_path)
        parent_rel = os.path.dirname(filepath).replace('\\', '/')
        ok, message, status_code = ensure_path_access(parent_rel, 'write', role=role)
        if not ok:
            return jsonify({'error': message}), status_code
        new_path = os.path.join(parent_dir, new_name)
    
    if not os.path.exists(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다'}), 404
    
    if os.path.exists(new_path):
        return jsonify({'error': '동일한 이름이 이미 존재합니다'}), 400
    
    try:
        os.rename(full_path, new_path)
        log_audit(
            session.get('role', 'guest'),
            'rename',
            filepath,
            f"New name: {new_name}",
            ip=get_real_ip()
        )
        logger.add(f"이름 변경: {filepath} → {new_name}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        return jsonify({'success': True})
    except Exception as exc:
        return api_exception('이름 변경 오류', exc)


# ==========================================
# 파일/폴더 복사
# ==========================================

@file_bp.route('/copy', methods=['POST'])
@login_required()
def copy_item():
    """파일/폴더 복사"""
    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'success': False, 'error': message}), status_code

    data = parse_json_body(request)
    src_path = data.get('source', '')
    dst_path = data.get('destination', '')

    ok, message, status_code = ensure_path_access(src_path, 'read', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    ok, message, status_code = ensure_path_access(dst_path, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    
    base_dir = conf.get('folder')
    is_valid_src, full_src, _ = validate_path(base_dir, src_path)
    is_valid_dst, full_dst, _ = validate_path(base_dir, dst_path)
    
    if not is_valid_src or not is_valid_dst:
        return jsonify({'success': False, 'error': '잘못된 경로입니다.'})
    
    if not os.path.exists(full_src):
        return jsonify({'success': False, 'error': '원본을 찾을 수 없습니다.'})
    
    # 자기 자신 하위로 복사 방지
    full_src_normalized = os.path.normpath(full_src)
    full_dst_normalized = os.path.normpath(full_dst)
    if os.path.isdir(full_src) and full_dst_normalized.startswith(full_src_normalized + os.sep):
        return jsonify({'success': False, 'error': '자기 자신의 하위 폴더로 복사할 수 없습니다.'})
    
    try:
        if os.path.isdir(full_src):
            shutil.copytree(full_src, full_dst)
        else:
            os.makedirs(os.path.dirname(full_dst), exist_ok=True)
            shutil.copy2(full_src, full_dst)
        logger.add(f"복사: {src_path} -> {dst_path}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        client_ip = get_real_ip()
        log_access(client_ip, 'copy', f"{src_path} -> {dst_path}")
        log_audit(
            user=session.get('role', 'unknown'),
            action='copy',
            target=src_path,
            details=f"To: {dst_path}",
            ip=client_ip
        )
        return jsonify({'success': True})
    except Exception as exc:
        return api_exception('복사 오류', exc, extra={'success': False})


# ==========================================
# 파일/폴더 이동
# ==========================================

@file_bp.route('/move', methods=['POST'])
@login_required()
def move_item():
    """파일/폴더 이동"""
    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'success': False, 'error': message}), status_code

    data = parse_json_body(request)
    src_path = data.get('source', '')
    dst_path = data.get('destination', '')

    ok, message, status_code = ensure_path_access(src_path, 'delete', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    ok, message, status_code = ensure_path_access(dst_path, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    
    base_dir = conf.get('folder')
    is_valid_src, full_src, _ = validate_path(base_dir, src_path)
    is_valid_dst, full_dst, _ = validate_path(base_dir, dst_path)
    
    if not is_valid_src or not is_valid_dst:
        return jsonify({'success': False, 'error': '잘못된 경로입니다.'})
    
    if not os.path.exists(full_src):
        return jsonify({'success': False, 'error': '원본을 찾을 수 없습니다.'})
    
    # 자기 자신 하위로 이동 방지
    full_src_normalized = os.path.normpath(full_src)
    full_dst_normalized = os.path.normpath(full_dst)
    if os.path.isdir(full_src) and full_dst_normalized.startswith(full_src_normalized + os.sep):
        return jsonify({'success': False, 'error': '자기 자신의 하위 폴더로 이동할 수 없습니다.'})
    
    try:
        os.makedirs(os.path.dirname(full_dst), exist_ok=True)
        shutil.move(full_src, full_dst)
        logger.add(f"이동: {src_path} -> {dst_path}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        client_ip = get_real_ip()
        log_access(client_ip, 'move', f"{src_path} -> {dst_path}")
        log_audit(
            user=session.get('role', 'unknown'),
            action='move',
            target=src_path,
            details=f"To: {dst_path}",
            ip=client_ip
        )
        return jsonify({'success': True})
    except Exception as exc:
        return api_exception('이동 오류', exc, extra={'success': False})


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
# ZIP 다운로드
# ==========================================

@file_bp.route('/zip/<path:path>')
@login_required()
def download_zip(path):
    """폴더를 ZIP으로 다운로드"""
    from utils.helpers import check_download_limit, track_download

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code
    
    is_valid, target_dir, error = validate_path(base_dir, path)
    if not is_valid:
        logger.add(f"ZIP 다운로드 경로 검증 실패: {path}", "WARN")
        return jsonify({'error': error}), 403
    
    if not os.path.isdir(target_dir):
        return jsonify({'error': '폴더가 아닙니다'}), 404
    
    try:
        role = session.get('role', 'guest')
        client_ip = get_real_ip()
        tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
        zip_items = _collect_allowed_zip_files(
            base_dir=base_dir,
            root_abs=target_dir,
            root_rel=path,
            role=role,
            arc_prefix="",
        )
        estimated_size = _estimate_zip_transfer_bytes(zip_items)
        allowed, limit_msg = check_download_limit(tracker_key, True, projected_bytes=estimated_size)
        if not allowed:
            return jsonify({'error': limit_msg}), 429

        if not zip_items:
            return jsonify({'error': '다운로드 가능한 항목이 없습니다'}), 403

        temp_path = create_temp_zip_from_items(zip_items)
        zip_size = os.path.getsize(temp_path)
        allowed, limit_msg = check_download_limit(tracker_key, True, projected_bytes=zip_size)
        if not allowed:
            try:
                os.remove(temp_path)
            except Exception:
                pass
            return jsonify({'error': limit_msg}), 429
        track_download(tracker_key, zip_size)
        with stats_lock:
            STATS['bytes_sent'] += zip_size

        download_name = f"{os.path.basename(target_dir)}.zip"
        return make_zip_stream_response(temp_path, download_name)
    except Exception as exc:
        return api_exception('ZIP 생성 오류', exc)


# ==========================================
# ZIP 압축 해제
# ==========================================

@file_bp.route('/unzip/<path:path>', methods=['POST'])
@login_required()
def unzip_file(path):
    """ZIP 파일 압축 해제 (Zip Slip 공격 방지 포함)"""
    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'success': False, 'error': message}), status_code

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(path, 'read', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    
    # 경로 검증
    valid, zip_path, error = validate_path(base_dir, path)
    if not valid:
        return jsonify({'success': False, 'error': error}), 400
    
    if not os.path.exists(zip_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'}), 404
    
    extract_to = _next_available_directory_path(os.path.splitext(zip_path)[0])
    extract_rel = os.path.relpath(extract_to, base_dir).replace('\\', '/')
    ok, message, status_code = ensure_path_access(extract_rel, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Zip Slip 공격 및 Zip Bomb 방지
            extract_to_abs = os.path.abspath(extract_to)
            total_uncompressed_size = 0
            MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024 * 1024  # 50GB Limit
            MAX_RATIO = 100  # 100x Compression Ratio Limit
            
            for member in zf.namelist():
                member_path = os.path.normpath(os.path.join(extract_to, member))
                
                # Zip Slip Check
                if not os.path.abspath(member_path).startswith(extract_to_abs + os.sep) and \
                   os.path.abspath(member_path) != extract_to_abs:
                    logger.add(f"Zip Slip 공격 감지: {member}", "WARN")
                    return jsonify({'success': False, 'error': f'보안 위협 감지: 잘못된 경로 "{member}"'}), 400
                
                # Zip Bomb Check
                info = zf.getinfo(member)
                if info.file_size > 0:
                     total_uncompressed_size += info.file_size
                     if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE:
                         return jsonify({'success': False, 'error': 'Zip Bomb 감지: 압축 해제 용량 초과'}), 400
                     
                     if info.compress_size > 0:
                         ratio = info.file_size / info.compress_size
                         if ratio > MAX_RATIO and info.file_size > 10 * 1024 * 1024:  # 10MB 이상일 때만 비율 체크
                             return jsonify({'success': False, 'error': 'Zip Bomb 감지: 압축률이 너무 높습니다'}), 400
            
            zf.extractall(extract_to)
            
            # 검색 인덱스 업데이트
            indexer.update_event(base_dir)
        logger.add(f"압축해제: {path}")
        return jsonify({'success': True})
    except zipfile.BadZipFile:
        return jsonify({'success': False, 'error': '잘못된 ZIP 파일입니다.'})
    except Exception as exc:
        return api_exception('압축해제 오류', exc, extra={'success': False})


# ==========================================
# 배치 다운로드
# ==========================================

@file_bp.route('/batch_download/<path:path>', methods=['POST'])
@login_required()
def batch_download(path):
    """여러 파일 일괄 ZIP 다운로드"""
    from utils.helpers import check_download_limit, track_download

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code
    
    is_valid, current_dir, error = validate_path(base_dir, path)
    if not is_valid:
        return jsonify({'error': error}), 403
    
    try:
        try:
            data = json.loads(request.form.get('files', '[]'))
        except Exception:
            return jsonify({'error': '잘못된 요청입니다'}), 400

        client_ip = get_real_ip()
        tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
        zip_items = []
        role = session.get('role', 'guest')
        for item_name in data:
            safe_item_name = safe_filename(item_name)
            item_rel = os.path.join(path, safe_item_name).replace('\\', '/')
            ok, _, _ = ensure_path_access(item_rel, 'read')
            if not ok:
                continue
            if is_protected_system_path(item_rel):
                continue
            is_valid_item, item_path, _ = validate_path(base_dir, item_rel)
            if not is_valid_item:
                continue

            if os.path.isfile(item_path):
                zip_items.append((item_path, safe_item_name))
                continue

            if os.path.isdir(item_path):
                zip_items.extend(
                    _collect_allowed_zip_files(
                        base_dir=base_dir,
                        root_abs=item_path,
                        root_rel=item_rel,
                        role=role,
                        arc_prefix=safe_item_name,
                    )
                )

        if not zip_items:
            return jsonify({'error': '다운로드 가능한 항목이 없습니다'}), 403

        estimated_size = _estimate_zip_transfer_bytes(zip_items)
        allowed, limit_msg = check_download_limit(tracker_key, True, projected_bytes=estimated_size)
        if not allowed:
            return jsonify({'error': limit_msg}), 429

        temp_path = create_temp_zip_from_items(zip_items)
        zip_size = os.path.getsize(temp_path)
        allowed, limit_msg = check_download_limit(tracker_key, True, projected_bytes=zip_size)
        if not allowed:
            try:
                os.remove(temp_path)
            except Exception:
                pass
            return jsonify({'error': limit_msg}), 429
        track_download(tracker_key, zip_size)
        with stats_lock:
            STATS['bytes_sent'] += zip_size
        
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='batch_download',
            target=path,
            details=f"{len(data)}개 항목",
            ip=client_ip
        )
        
        return make_zip_stream_response(temp_path, "batch_download.zip")
    except Exception as exc:
        return api_exception('배치 다운로드 오류', exc)


# ==========================================
# 배치 삭제
# ==========================================

@file_bp.route('/batch_delete/<path:path>', methods=['POST'])
@login_required()
def batch_delete(path):
    """여러 파일 일괄 삭제 (휴지통으로 이동)"""
    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'error': message}), status_code

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(path, 'delete', role=role)
    if not ok:
        return jsonify({'error': message}), status_code
    
    # 경로 검증
    is_valid, current_dir, error = validate_path(base_dir, path)
    if not is_valid:
        return jsonify({'error': error}), 400
    
    data = parse_json_body(request)
    files = data.get('files', [])
    
    deleted_items = []
    failed_items = []
    count = 0
    try:
        for item_name in files:
            item_path = os.path.join(current_dir, safe_filename(item_name))
            item_rel = os.path.relpath(item_path, base_dir).replace('\\', '/')
            ok, _, _ = ensure_path_access(item_rel, 'delete', role=role)
            if not ok:
                failed_items.append({'name': item_name, 'error': 'Permission denied'})
                continue
            if os.path.exists(item_path):
                # 휴지통으로 이동
                success, result = move_to_trash(item_path)
                if success:
                    deleted_items.append(item_name)
                    count += 1
                else:
                    failed_items.append({'name': item_name, 'error': result})
            else:
                failed_items.append({'name': item_name, 'error': 'Not found'})
        
        logger.add(f"일괄 삭제: {count}개 항목 성공, {len(failed_items)}개 실패")
        
        # 감사 로그 기록
        if count > 0:
            log_audit(
                user=session.get('role', 'unknown'),
                action='batch_delete',
                target=path,
                details=f"{count}개 성공, {len(failed_items)}개 실패",
                ip=get_real_ip()
            )
            indexer.update_event(base_dir)
        
        return jsonify({
            'success': True, 
            'deleted': count, 
            'failed': len(failed_items),
            'failed_items': failed_items
        })
    except Exception as exc:
        return api_exception('일괄 삭제 오류', exc, extra={'success': False})


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
        with _clipboard_lock:
            _clipboard_store[owner_key] = data.get('content', '')
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


