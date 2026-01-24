"""
WebShare Pro - File Routes
파일 다운로드, 업로드, 관리 라우트
"""

import os
import threading
import io
import shutil
import zipfile
import json
import hashlib
import mimetypes
from datetime import datetime
from flask import Blueprint, request, send_file, jsonify, session, after_this_request
import tempfile

from ..config import conf, STATS, stats_lock, ACCESS_LOG, access_log_lock
from ..utils.log_manager import logger, log_access
from ..utils.file_utils import validate_path, safe_filename, fmt_bytes
from ..security.auth import login_required
from ..features.audit_log import log_audit
from ..features.trash import move_to_trash
from ..features.search_indexer import indexer

file_bp = Blueprint('file', __name__)

# 클립보드 저장소 (스레드 안전성을 위한 락 사용)
_clipboard_lock = threading.Lock()
clipboard_store = ""


@file_bp.route('/download/<path:filepath>')
@login_required()
def download(filepath):
    """파일 다운로드"""
    from ..utils.helpers import check_download_limit, track_download
    from ..utils.file_utils import get_real_ip
    
    base_dir = conf.get('folder')
    
    # 경로 검증
    valid, full_path, error = validate_path(base_dir, filepath)
    if not valid:
        return jsonify({'error': error}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다'}), 404
    
    if os.path.isdir(full_path):
        return jsonify({'error': '폴더는 다운로드할 수 없습니다'}), 400
    
    # v5.1: 다운로드 제한 확인
    client_ip = get_real_ip()
    allowed, limit_msg = check_download_limit(client_ip)
    if not allowed:
        return jsonify({'error': limit_msg}), 429
    
    try:
        # 통계 업데이트
        file_size = os.path.getsize(full_path)
        with stats_lock:
            STATS['bytes_sent'] += file_size
        
        # v5.1: 다운로드 기록 추적
        track_download(client_ip, file_size)
        
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
        return send_file(full_path, as_attachment=True)
        
    except Exception as e:
        logger.add(f"다운로드 오류: {e}", "ERROR")
        return jsonify({'error': str(e)}), 500


@file_bp.route('/upload/<path:folderpath>', methods=['POST'])
@file_bp.route('/upload/', methods=['POST'])
@login_required()
def upload(folderpath=''):
    """파일 업로드"""
    # 권한 확인
    role = session.get('role')
    if role != 'admin' and not conf.get('allow_guest_upload'):
        return jsonify({'error': '업로드 권한이 없습니다'}), 403
    
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
    
    for i, file in enumerate(uploaded_files):
        if file.filename == '':
            continue
        
        # 안전한 파일명 생성
        filename = safe_filename(file.filename)
        
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
        
        # 동일 파일명 처리
        if os.path.exists(file_path):
            name, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(file_path):
                filename = f"{name}_{counter}{ext}"
                file_path = os.path.join(full_path, filename)
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
                ip=request.remote_addr
            )
            
            results.append({'name': filename, 'success': True})
            logger.add(f"업로드: {filename}")
            
            # 검색 인덱스 업데이트 (비동기)
            indexer.update_event(base_dir)
            
        except Exception as e:
            results.append({'name': filename, 'success': False, 'error': str(e)})
            logger.add(f"업로드 오류: {e}", "ERROR")
    
    with stats_lock:
        STATS['bytes_received'] += total_size
    
    return jsonify({'success': True, 'files': results})


@file_bp.route('/mkdir/<path:folderpath>', methods=['POST'])
@file_bp.route('/mkdir/', methods=['POST'])
@login_required()
def mkdir(folderpath=''):
    """폴더 생성"""
    role = session.get('role')
    if role != 'admin' and not conf.get('allow_guest_upload'):
        return jsonify({'error': '폴더 생성 권한이 없습니다'}), 403
    
    base_dir = conf.get('folder')
    data = request.get_json() or {}
    folder_name = data.get('name', '')
    
    if not folder_name:
        return jsonify({'error': '폴더 이름이 필요합니다'}), 400
    
    folder_name = safe_filename(folder_name)
    
    valid, parent_path, error = validate_path(base_dir, folderpath)
    if not valid:
        return jsonify({'error': error}), 400
    
    new_folder = os.path.join(parent_path, folder_name)
    
    if os.path.exists(new_folder):
        return jsonify({'error': '이미 존재하는 폴더입니다'}), 400
    
    try:
        os.makedirs(new_folder)
        log_audit(
            session.get('role', 'guest'),
            'mkdir',
            f"{folderpath}/{folder_name}",
            ip=request.remote_addr
        )
        logger.add(f"폴더 생성: {folder_name}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        return jsonify({'success': True})
    except Exception as e:
        logger.add(f"폴더 생성 오류: {e}", "ERROR")
        return jsonify({'error': str(e)}), 500


@file_bp.route('/delete/<path:filepath>', methods=['POST'])
@login_required('admin')
def delete(filepath):
    """파일/폴더 삭제 (휴지통으로 이동)"""
    base_dir = conf.get('folder')
    
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
            ip=request.remote_addr
        )
        logger.add(f"삭제 (휴지통): {filepath}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        return jsonify({'success': True})
    else:
        return jsonify({'error': result}), 500


@file_bp.route('/rename/<path:filepath>', methods=['POST'])
@login_required('admin')
def rename(filepath):
    """파일/폴더 이름 변경"""
    base_dir = conf.get('folder')
    data = request.get_json() or {}
    new_name = data.get('name', '') or data.get('new_name', '')
    old_name = data.get('old_name', '')
    
    if not new_name:
        return jsonify({'error': '새 이름이 필요합니다'}), 400
    
    new_name = safe_filename(new_name)
    
    # old_name이 있으면 filepath를 부모 폴더로 사용
    if old_name:
        valid, parent_path, error = validate_path(base_dir, filepath)
        if not valid:
            return jsonify({'error': error}), 400
        full_path = os.path.join(parent_path, safe_filename(old_name))
        new_path = os.path.join(parent_path, new_name)
    else:
        valid, full_path, error = validate_path(base_dir, filepath)
        if not valid:
            return jsonify({'error': error}), 400
        parent_dir = os.path.dirname(full_path)
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
            ip=request.remote_addr
        )
        logger.add(f"이름 변경: {filepath} → {new_name}")
        # 검색 인덱스 업데이트
        indexer.update_event(base_dir)
        return jsonify({'success': True})
    except Exception as e:
        logger.add(f"이름 변경 오류: {e}", "ERROR")
        return jsonify({'error': str(e)}), 500


# ==========================================
# 파일/폴더 복사
# ==========================================

@file_bp.route('/copy', methods=['POST'])
@login_required('admin')
def copy_item():
    """파일/폴더 복사"""
    data = request.get_json()
    src_path = data.get('source', '')
    dst_path = data.get('destination', '')
    
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
        log_access(request.remote_addr, 'copy', f"{src_path} -> {dst_path}")
        log_audit(
            user=session.get('role', 'unknown'),
            action='copy',
            target=src_path,
            details=f"To: {dst_path}",
            ip=request.remote_addr
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==========================================
# 파일/폴더 이동
# ==========================================

@file_bp.route('/move', methods=['POST'])
@login_required('admin')
def move_item():
    """파일/폴더 이동"""
    data = request.get_json()
    src_path = data.get('source', '')
    dst_path = data.get('destination', '')
    
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
        log_access(request.remote_addr, 'move', f"{src_path} -> {dst_path}")
        log_audit(
            user=session.get('role', 'unknown'),
            action='move',
            target=src_path,
            details=f"To: {dst_path}",
            ip=request.remote_addr
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==========================================
# 파일 검색
# ==========================================

@file_bp.route('/search')
@login_required()
def search_files():
    """서버 전체 파일 검색"""
    query = request.args.get('q', '').lower().strip()
    if not query or len(query) < 2:
        return jsonify({'results': [], 'error': '검색어는 2자 이상이어야 합니다.'})
    
    base_dir = conf.get('folder')
    results = []
    max_results = 100
    
    # v7.2.3: 인 메모리 검색 인덱서 사용
    try:
        results = indexer.search(query, max_results)
    except Exception as e:
        logger.add(f"검색 오류: {e}", "ERROR")
    
    return jsonify({'results': results, 'count': len(results)})


# ==========================================
# ZIP 다운로드
# ==========================================

@file_bp.route('/zip/<path:path>')
@login_required()
def download_zip(path):
    """폴더를 ZIP으로 다운로드"""
    base_dir = conf.get('folder')
    
    is_valid, target_dir, error = validate_path(base_dir, path)
    if not is_valid:
        logger.add(f"ZIP 다운로드 경로 검증 실패: {path}", "WARN")
        return jsonify({'error': error}), 403
    
    if not os.path.isdir(target_dir):
        return jsonify({'error': '폴더가 아닙니다'}), 404
    
    if not os.path.isdir(target_dir):
        return jsonify({'error': '폴더가 아닙니다'}), 404
    
    # Use disk-based temp file to avoid OOM
    try:
        # mkstemp is safer but NamedTemporaryFile is more convenient
        # delete=False is required for Windows as we close it before sending
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_path = temp_file.name
        temp_file.close() # Close immediately so we can write to it with ZipFile
        
        with zipfile.ZipFile(temp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    zf.write(file_path, os.path.relpath(file_path, target_dir))
        
        # Generator for safe cleanup
        def generate():
            try:
                with open(temp_path, 'rb') as f:
                    while True:
                        chunk = f.read(4096 * 10) # 40KB chunk
                        if not chunk:
                             break
                        yield chunk
            finally:
                # Cleanup after streaming is done or if error occurs
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception as e:
                    logger.add(f"Temp ZIP file cleanup error: {e}", "WARN")

        # Use direct Response for generator support
        from flask import Response
        return Response(
            generate(),
            mimetype="application/zip",
            headers={"Content-Disposition": f"attachment; filename={safe_filename(os.path.basename(target_dir))}.zip"}
        )
            
    except Exception as e:
        logger.add(f"ZIP 생성 오류: {e}", "ERROR")
        if 'temp_path' in locals() and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
        return jsonify({'error': str(e)}), 500


# ==========================================
# ZIP 압축 해제
# ==========================================

@file_bp.route('/unzip/<path:path>', methods=['POST'])
@login_required('admin')
def unzip_file(path):
    """ZIP 파일 압축 해제 (Zip Slip 공격 방지 포함)"""
    base_dir = conf.get('folder')
    
    # 경로 검증
    valid, zip_path, error = validate_path(base_dir, path)
    if not valid:
        return jsonify({'success': False, 'error': error}), 400
    
    if not os.path.exists(zip_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'}), 404
    
    extract_to = os.path.splitext(zip_path)[0]
    
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
    except Exception as e:
        logger.add(f"압축해제 오류: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})


# ==========================================
# 배치 다운로드
# ==========================================

@file_bp.route('/batch_download/<path:path>', methods=['POST'])
@login_required()
def batch_download(path):
    """여러 파일 일괄 ZIP 다운로드"""
    base_dir = conf.get('folder')
    
    is_valid, current_dir, error = validate_path(base_dir, path)
    if not is_valid:
        return jsonify({'error': error}), 403
    
    try:
        data = json.loads(request.form.get('files', '[]'))
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item_name in data:
                item_rel = os.path.join(path, safe_filename(item_name)).replace('\\', '/')
                is_valid_item, item_path, _ = validate_path(base_dir, item_rel)
                if not is_valid_item:
                    continue
                
                if os.path.isfile(item_path):
                    zf.write(item_path, item_name)
                elif os.path.isdir(item_path):
                    for root, dirs, files in os.walk(item_path):
                        for file in files:
                            abs_file = os.path.join(root, file)
                            rel_file = os.path.relpath(abs_file, current_dir)
                            zf.write(abs_file, rel_file)
        
        mem_zip.seek(0)
        
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='batch_download',
            target=path,
            details=f"{len(data)}개 항목",
            ip=request.remote_addr
        )
        
        return send_file(mem_zip, download_name="batch_download.zip", as_attachment=True)
    except Exception as e:
        logger.add(f"배치 다운로드 오류: {e}", "ERROR")
        return jsonify({'error': str(e)}), 500


# ==========================================
# 배치 삭제
# ==========================================

@file_bp.route('/batch_delete/<path:path>', methods=['POST'])
@login_required('admin')
def batch_delete(path):
    """여러 파일 일괄 삭제 (휴지통으로 이동)"""
    from ..utils.file_utils import get_real_ip
    
    base_dir = conf.get('folder')
    
    # 경로 검증
    is_valid, current_dir, error = validate_path(base_dir, path)
    if not is_valid:
        return jsonify({'error': error}), 400
    
    data = request.get_json()
    files = data.get('files', [])
    
    deleted_items = []
    failed_items = []
    count = 0
    try:
        for item_name in files:
            item_path = os.path.join(current_dir, safe_filename(item_name))
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
        
        return jsonify({
            'success': True, 
            'deleted': count, 
            'failed': len(failed_items),
            'failed_items': failed_items
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==========================================
# 파일 정보
# ==========================================

@file_bp.route('/file_info/<path:path>')
@login_required()
def get_file_info(path):
    """파일 상세 정보 조회"""
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
    global clipboard_store
    if request.method == 'POST':
        with _clipboard_lock:
            clipboard_store = request.get_json().get('content', '')
        return jsonify({'success': True})
    with _clipboard_lock:
        content = clipboard_store
    return jsonify({'content': content})


# ==========================================
# ZIP 미리보기 (v7.2.3)
# ==========================================

@file_bp.route('/api/zip_preview/<path:filepath>')
@login_required()
def zip_preview(filepath):
    """ZIP 파일 내용 미리보기"""
    base_dir = conf.get('folder')
    
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
    except Exception as e:
        logger.add(f"ZIP 미리보기 오류: {e}", "ERROR")
        return jsonify({'error': str(e)}), 500


