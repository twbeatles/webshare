"""
WebShare Pro - Share Routes
공유 링크 생성 및 관리
"""

import os
import secrets
import threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, session, send_from_directory, render_template

from config import (
    conf, SHARE_LINKS, share_links_lock,
    MAX_LOGIN_ATTEMPTS, LOGIN_BLOCK_MINUTES
)
from utils.log_manager import logger
from utils.file_utils import validate_path, get_real_ip, get_file_type
from utils.zip_utils import create_temp_zip_from_items, make_zip_stream_response
from utils.request_policy import ensure_path_access, is_protected_system_path, parse_json_body
from features.audit_log import log_audit
from security.auth import login_required, hash_password, verify_password
from features.share_links_store import save_share_links
# from .templates import SHARE_PASSWORD_TEMPLATE, SHARE_EXPIRED_TEMPLATE (Removed)

share_bp = Blueprint('share', __name__)

# ==========================================
# 공유 링크 비밀번호 브루트포스 방지 (v7.2.4)
# ==========================================
_share_password_attempts_lock = threading.Lock()
_share_password_attempts = {}  # {(ip, token): {'attempts': int, 'blocked_until': datetime}}


def check_share_password_blocked(ip: str, token: str) -> tuple:
    """공유 링크 비밀번호 시도 차단 상태 확인. (차단여부, 남은시간(분))"""
    key = (ip, token)
    with _share_password_attempts_lock:
        if key not in _share_password_attempts:
            return False, 0
        
        info = _share_password_attempts[key]
        blocked_until = info.get('blocked_until')
        
        if blocked_until:
            if datetime.now() < blocked_until:
                remaining = (blocked_until - datetime.now()).total_seconds() / 60
                return True, round(remaining)
            else:
                # 차단 해제
                del _share_password_attempts[key]
                return False, 0
        
        return False, 0


def record_share_password_attempt(ip: str, token: str, success: bool):
    """공유 링크 비밀번호 시도 기록 (스레드 안전)"""
    key = (ip, token)
    with _share_password_attempts_lock:
        if success:
            # 성공 시 기록 삭제
            if key in _share_password_attempts:
                del _share_password_attempts[key]
            return
        
        # 실패 기록
        now = datetime.now()
        if key not in _share_password_attempts:
            _share_password_attempts[key] = {'attempts': 0}
        
        _share_password_attempts[key]['attempts'] += 1
        _share_password_attempts[key]['last_attempt'] = now
        
        # 최대 횟수 초과 시 차단
        if _share_password_attempts[key]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            _share_password_attempts[key]['blocked_until'] = now + timedelta(minutes=LOGIN_BLOCK_MINUTES)
            logger.add(f"공유 링크 비밀번호 시도 차단: {ip} (토큰: {token[:8]}...)", "WARN")


def _collect_share_zip_files(root_abs: str, root_rel: str, role: str = "guest"):
    """공유 ZIP 포함 가능 파일 목록 수집 (보호 경로/권한 필터)"""
    items = []
    base_dir = conf.get('folder')
    root_name = os.path.basename(os.path.normpath(root_abs))
    normalized_root_rel = (root_rel or '').replace('\\', '/').strip('/')

    for walk_root, dirs, files in os.walk(root_abs):
        rel_dir = os.path.relpath(walk_root, root_abs).replace('\\', '/')
        if rel_dir == '.':
            rel_dir = ''

        filtered_dirs = []
        for name in sorted(dirs):
            rel_path = '/'.join(part for part in [normalized_root_rel, rel_dir, name] if part)
            if is_protected_system_path(rel_path):
                continue
            ok, _, _ = ensure_path_access(rel_path, 'read', role=role)
            if ok:
                filtered_dirs.append(name)
        dirs[:] = filtered_dirs

        for name in sorted(files):
            rel_path = '/'.join(part for part in [normalized_root_rel, rel_dir, name] if part)
            if is_protected_system_path(rel_path):
                continue
            ok, _, _ = ensure_path_access(rel_path, 'read', role=role)
            if not ok:
                continue
            is_valid, abs_path, _ = validate_path(base_dir, rel_path)
            if not is_valid or not os.path.isfile(abs_path):
                continue
            child_rel = os.path.relpath(abs_path, root_abs).replace('\\', '/')
            arcname = f"{root_name}/{child_rel}"
            items.append((abs_path, arcname))
    return items


def _estimate_zip_transfer_bytes(zip_items: list[tuple[str, str]]) -> int:
    total = 0
    for abs_path, _arcname in zip_items:
        try:
            total += os.path.getsize(abs_path)
        except OSError:
            continue
    return total


def _reserve_share_download(token: str) -> tuple[bool, str]:
    """
    Reserve one download slot atomically for max_downloads enforcement.
    Returns (ok, message).
    """
    with share_links_lock:
        share_info = SHARE_LINKS.get(token)
        if not share_info:
            return False, "링크를 찾을 수 없습니다."

        max_downloads = int(share_info.get('max_downloads', 0) or 0)
        current = int(share_info.get('download_count', 0) or 0)
        if max_downloads > 0 and current >= max_downloads:
            return False, "다운로드 횟수가 초과되었습니다."

        share_info['download_count'] = current + 1

    save_share_links()
    return True, ""


def _rollback_reserved_download(token: str):
    """Rollback a previously reserved download slot."""
    changed = False
    with share_links_lock:
        share_info = SHARE_LINKS.get(token)
        if not share_info:
            return

        current = int(share_info.get('download_count', 0) or 0)
        if current > 0:
            share_info['download_count'] = current - 1
            changed = True

    if changed:
        save_share_links()


# ==========================================
# 공유 링크 생성
# ==========================================

@share_bp.route('/share/create', methods=['POST'])
@login_required('admin')
def create_share_link():
    """임시 공유 링크 생성 (비밀번호, 다운로드 제한 지원)"""
    data = parse_json_body(request)
    path = data.get('path', '')
    raw_hours = data.get('hours', 24)
    password = data.get('password', '')
    raw_max_downloads = data.get('max_downloads', 0)

    try:
        hours = int(raw_hours)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'hours는 정수여야 합니다.'}), 400

    try:
        max_downloads = int(raw_max_downloads)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'max_downloads는 정수여야 합니다.'}), 400

    if hours < 1 or hours > 24 * 365:
        return jsonify({'success': False, 'error': 'hours는 1~8760 범위여야 합니다.'}), 400
    if max_downloads < 0 or max_downloads > 1_000_000:
        return jsonify({'success': False, 'error': 'max_downloads는 0~1000000 범위여야 합니다.'}), 400

    if is_protected_system_path(path):
        return jsonify({'success': False, 'error': '시스템 경로는 공유할 수 없습니다.'}), 403
    
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'success': False, 'error': '유효하지 않은 경로입니다.'}), 400
    
    # 토큰 생성
    token = secrets.token_urlsafe(16)
    expires = datetime.now() + timedelta(hours=hours)
    
    with share_links_lock:
        SHARE_LINKS[token] = {
            'path': path,
            'expires': expires,
            'created_by': session.get('role', 'unknown'),
            'is_dir': os.path.isdir(full_path),
            'password_hash': hash_password(password) if password else None,
            'max_downloads': max_downloads,
            'download_count': 0,
            'created_at': datetime.now().isoformat()
        }
    save_share_links()
    
    features = []
    if password: features.append('비밀번호')
    if max_downloads > 0: features.append(f'최대 {max_downloads}회')
    feature_str = f" [{', '.join(features)}]" if features else ""
    
    logger.add(f"공유 링크 생성: {path} ({hours}시간){feature_str}")
    
    # 감사 로그 기록
    log_audit(
        user=session.get('role', 'unknown'),
        action='share_create',
        target=path,
        details=f"{hours}시간, 토큰: {token[:8]}...",
        ip=get_real_ip()
    )
    
    return jsonify({
        'success': True,
        'token': token,
        'expires': expires.isoformat(),
        'link': f"/share/{token}",
        'has_password': bool(password),
        'max_downloads': max_downloads
    })


# ==========================================
# 공유 링크 접근
# ==========================================

@share_bp.route('/share/<token>', methods=['GET', 'POST'])
def access_share_link(token):
    """공유 링크로 파일 접근"""
    from utils.helpers import check_download_limit, track_download

    # 락 내에서 검증만 수행하고 필요한 정보 복사
    removed_expired_link = False
    expired_response = None
    share_snapshot: tuple[str, bool, str | None] | None = None
    with share_links_lock:
        if token not in SHARE_LINKS:
            return render_template('share_expired.html', message="링크를 찾을 수 없습니다."), 404
        
        share_info = SHARE_LINKS[token]
        
        # 만료 확인
        if datetime.now() > share_info['expires']:
            del SHARE_LINKS[token]
            removed_expired_link = True
            expired_response = (render_template('share_expired.html', message="링크가 만료되었습니다."), 410)
        else:
            # 다운로드 횟수 제한 확인
            max_downloads = share_info.get('max_downloads', 0)
            if max_downloads > 0 and share_info.get('download_count', 0) >= max_downloads:
                return render_template('share_expired.html', message="다운로드 횟수가 초과되었습니다.")
            
            # 락 외부에서 사용할 정보 복사
            share_snapshot = (
                str(share_info['path']),
                bool(share_info['is_dir']),
                share_info.get('password_hash'),
            )

    if removed_expired_link:
        save_share_links()
    if expired_response is not None:
        return expired_response
    if share_snapshot is None:
        return render_template('share_expired.html', message="링크를 찾을 수 없습니다."), 404

    path, is_dir, password_hash = share_snapshot

    if is_protected_system_path(path):
        return render_template('share_expired.html', message="접근이 허용되지 않는 파일입니다."), 403
    ok, _, _ = ensure_path_access(path, 'read', role='guest')
    if not ok:
        return render_template('share_expired.html', message="접근 권한이 없습니다."), 403
    
    # 비밀번호 확인 (락 외부)
    if password_hash:
        ip = get_real_ip()
        
        # 브루트포스 차단 확인
        is_blocked, remaining_min = check_share_password_blocked(ip, token)
        if is_blocked:
            return render_template('share_password.html', 
                token=token, error=f"너무 많은 시도로 {remaining_min}분간 차단되었습니다."), 429
        
        if request.method == 'POST':
            entered_password = request.form.get('password', '')
            if not verify_password(password_hash, entered_password):
                record_share_password_attempt(ip, token, success=False)
                return render_template('share_password.html', 
                    token=token, error="비밀번호가 올바르지 않습니다.")
            else:
                record_share_password_attempt(ip, token, success=True)
        else:
            return render_template('share_password.html', token=token, error=None)
    
    # 경로 검증 (락 외부)
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return render_template('share_expired.html', message="파일을 찾을 수 없습니다."), 404

    client_ip = get_real_ip()

    # 파일 전송 (락 외부)
    if is_dir:
        role_for_share = 'guest'
        zip_items = _collect_share_zip_files(full_path, path, role=role_for_share)
        if not zip_items:
            return render_template('share_expired.html', message="다운로드 가능한 항목이 없습니다."), 403

        estimated_size = _estimate_zip_transfer_bytes(zip_items)
        allowed, limit_msg = check_download_limit(client_ip, True, projected_bytes=estimated_size)
        if not allowed:
            return render_template('share_expired.html', message=limit_msg), 429

        # 폴더인 경우 디스크 기반 ZIP 스트리밍 (OOM 방지)
        temp_path = create_temp_zip_from_items(zip_items)
        zip_size = os.path.getsize(temp_path)
        allowed, limit_msg = check_download_limit(client_ip, True, projected_bytes=zip_size)
        if not allowed:
            try:
                os.remove(temp_path)
            except Exception:
                pass
            return render_template('share_expired.html', message=limit_msg), 429
        reserved, reserve_msg = _reserve_share_download(token)
        if not reserved:
            try:
                os.remove(temp_path)
            except Exception:
                pass
            return render_template('share_expired.html', message=reserve_msg)

        track_download(client_ip, zip_size)
        try:
            return make_zip_stream_response(temp_path, f"{os.path.basename(full_path)}.zip")
        except Exception:
            _rollback_reserved_download(token)
            try:
                os.remove(temp_path)
            except Exception:
                pass
            raise
    else:
        reserved, reserve_msg = _reserve_share_download(token)
        if not reserved:
            return render_template('share_expired.html', message=reserve_msg)

        file_size = os.path.getsize(full_path)
        allowed, limit_msg = check_download_limit(client_ip, True, projected_bytes=file_size)
        if not allowed:
            _rollback_reserved_download(token)
            return render_template('share_expired.html', message=limit_msg), 429

        track_download(client_ip, file_size)
        try:
            return send_from_directory(conf.get('folder'), path)
        except Exception:
            _rollback_reserved_download(token)
            raise


# ==========================================
# 공유 링크 목록
# ==========================================

@share_bp.route('/share/list')
@login_required('admin')
def list_share_links():
    """활성 공유 링크 목록"""
    now = datetime.now()
    active_links = []
    expired_tokens = []
    removed_expired = False
    
    with share_links_lock:
        for token, info in SHARE_LINKS.items():
            if now > info['expires']:
                expired_tokens.append(token)
            else:
                active_links.append({
                    'token': token,
                    'path': info['path'],
                    'expires': info['expires'].isoformat(),
                    'is_dir': info['is_dir'],
                    'download_count': info.get('download_count', 0),
                    'max_downloads': info.get('max_downloads', 0),
                    'has_password': info.get('password_hash') is not None
                })
        
        for token in expired_tokens:
            del SHARE_LINKS[token]
            removed_expired = True

    if removed_expired:
        save_share_links()
    
    return jsonify({'links': active_links})


# ==========================================
# 공유 링크 삭제
# ==========================================

@share_bp.route('/share/delete/<token>', methods=['POST'])
@login_required('admin')
def delete_share_link(token):
    """공유 링크 삭제"""
    path = 'unknown'
    deleted = False
    with share_links_lock:
        if token in SHARE_LINKS:
            path = SHARE_LINKS[token].get('path', 'unknown')
            del SHARE_LINKS[token]
            deleted = True
    if not deleted:
        return jsonify({'success': False, 'error': '링크를 찾을 수 없습니다.'})

    save_share_links()
    logger.add(f"공유 링크 삭제: {token}")
    
    # 감사 로그 기록
    log_audit(
        user=session.get('role', 'unknown'),
        action='share_delete',
        target=path,
        details=f"토큰: {token[:8]}...",
        ip=get_real_ip()
    )
    
    return jsonify({'success': True})
