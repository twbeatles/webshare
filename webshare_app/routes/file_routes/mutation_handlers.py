"""File mutation endpoints (upload, mkdir, delete, rename, copy, move, batch, unzip)."""

import os
import shutil
import zipfile
from flask import request, jsonify, session
from config import conf, STATS, stats_lock
from utils.api_errors import api_exception
from utils.log_manager import logger, log_access
from utils.file_utils import validate_path, safe_filename, fmt_bytes, get_real_ip
from utils.request_policy import ensure_mutation_allowed, ensure_path_access, is_protected_system_path, parse_json_body
from security.auth import login_required
from features.audit_log import log_audit
from features.trash import move_to_trash
from features.search_indexer import indexer
from utils.helpers import atomic_copy_file, atomic_save_upload
from webshare_app.services.file_service import resolve_folder_upload_target, _copy_directory_to_staging, _next_available_directory_path, _normalize_conflict_policy, _replace_with_staging, _resolve_conflict_path
from webshare_app.services.upload_service import estimate_file_storage_size, release_upload_disk_space, reserve_upload_disk_space
from ._common import file_bp
from .path_utils import _create_overwrite_versions_if_needed, _is_descendant_path, _normcase_path




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

        paths_entry = paths[i] if paths and len(paths) > i else None
        ok_path, file_path, rel_save_path, path_error = resolve_folder_upload_target(
            base_dir,
            folderpath,
            paths_entry,
            filename,
        )
        if not ok_path:
            results.append({'name': filename, 'success': False, 'error': path_error or '업로드 경로가 유효하지 않습니다'})
            continue

        try:
            parent_dir = os.path.dirname(file_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
        except OSError as exc:
            results.append({'name': filename, 'success': False, 'error': '업로드 경로를 생성할 수 없습니다'})
            logger.add(f"업로드 경로 생성 실패: {exc}", "ERROR")
            continue

        # 시스템 경로 및 권한 검증
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
            estimated_size = estimate_file_storage_size(file)
            disk_ok, disk_error, disk_reservation_id = reserve_upload_disk_space(
                os.path.dirname(file_path),
                estimated_size,
            )
            if not disk_ok:
                results.append({'name': filename, 'success': False, 'error': disk_error})
                continue
            try:
                atomic_save_upload(file, file_path)
            finally:
                release_upload_disk_space(disk_reservation_id)
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
    conflict_policy = _normalize_conflict_policy(data.get('conflict_policy'), default='rename')

    ok, message, status_code = ensure_path_access(src_path, 'read', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    ok, message, status_code = ensure_path_access(dst_path, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    if conflict_policy == 'overwrite':
        ok, message, status_code = ensure_path_access(dst_path, 'delete', role=role)
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
    if _normcase_path(full_src) == _normcase_path(full_dst):
        return jsonify({'success': False, 'error': '원본과 대상 경로가 같습니다.'}), 400
    if os.path.isdir(full_src) and _is_descendant_path(full_src, full_dst):
        return jsonify({'success': False, 'error': '자기 자신의 하위 폴더로 복사할 수 없습니다.'})

    resolved, final_dst, conflict_error = _resolve_conflict_path(full_dst, conflict_policy)
    if not resolved:
        return jsonify({'success': False, 'error': conflict_error, 'code': 'DESTINATION_EXISTS'}), 409

    try:
        if os.path.isdir(full_src):
            if conflict_policy == 'overwrite':
                _create_overwrite_versions_if_needed(final_dst)
                staging = _copy_directory_to_staging(full_src, final_dst)
                _replace_with_staging(staging, final_dst)
            else:
                shutil.copytree(full_src, final_dst)
        else:
            os.makedirs(os.path.dirname(final_dst), exist_ok=True)
            if conflict_policy == 'overwrite':
                _create_overwrite_versions_if_needed(final_dst)
            atomic_copy_file(full_src, final_dst)
        final_rel = os.path.relpath(final_dst, base_dir).replace('\\', '/')
        logger.add(f"복사: {src_path} -> {final_rel}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        client_ip = get_real_ip()
        log_access(client_ip, 'copy', f"{src_path} -> {final_rel}")
        log_audit(
            user=session.get('role', 'unknown'),
            action='copy',
            target=src_path,
            details=f"To: {final_rel}, conflict_policy: {conflict_policy}",
            ip=client_ip
        )
        return jsonify({'success': True, 'path': final_rel, 'conflict_policy': conflict_policy})
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
    conflict_policy = _normalize_conflict_policy(data.get('conflict_policy'), default='rename')

    ok, message, status_code = ensure_path_access(src_path, 'delete', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    ok, message, status_code = ensure_path_access(dst_path, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code
    if conflict_policy == 'overwrite':
        ok, message, status_code = ensure_path_access(dst_path, 'delete', role=role)
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
    if _normcase_path(full_src) == _normcase_path(full_dst):
        return jsonify({'success': False, 'error': '원본과 대상 경로가 같습니다.'}), 400
    if os.path.isdir(full_src) and _is_descendant_path(full_src, full_dst):
        return jsonify({'success': False, 'error': '자기 자신의 하위 폴더로 이동할 수 없습니다.'})

    resolved, final_dst, conflict_error = _resolve_conflict_path(full_dst, conflict_policy)
    if not resolved:
        return jsonify({'success': False, 'error': conflict_error, 'code': 'DESTINATION_EXISTS'}), 409

    try:
        os.makedirs(os.path.dirname(final_dst), exist_ok=True)
        if conflict_policy == 'overwrite':
            _create_overwrite_versions_if_needed(final_dst)
            if os.path.isdir(full_src) and not os.path.islink(full_src):
                staging = _copy_directory_to_staging(full_src, final_dst)
                _replace_with_staging(staging, final_dst)
                shutil.rmtree(full_src)
            else:
                os.replace(full_src, final_dst)
        else:
            shutil.move(full_src, final_dst)
        final_rel = os.path.relpath(final_dst, base_dir).replace('\\', '/')
        logger.add(f"이동: {src_path} -> {final_rel}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        client_ip = get_real_ip()
        log_access(client_ip, 'move', f"{src_path} -> {final_rel}")
        log_audit(
            user=session.get('role', 'unknown'),
            action='move',
            target=src_path,
            details=f"To: {final_rel}, conflict_policy: {conflict_policy}",
            ip=client_ip
        )
        return jsonify({'success': True, 'path': final_rel, 'conflict_policy': conflict_policy})
    except Exception as exc:
        return api_exception('이동 오류', exc, extra={'success': False})




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

