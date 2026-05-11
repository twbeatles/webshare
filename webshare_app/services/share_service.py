"""Share link state and helper functions."""

import os
import threading
from datetime import datetime, timedelta

from config import (
    LOGIN_BLOCK_MINUTES,
    MAX_LOGIN_ATTEMPTS,
    SHARE_LINKS,
    conf,
    share_links_lock,
)
from features.runtime_state import load_share_password_attempts as _load_share_password_attempts_store
from features.runtime_state import save_share_password_attempts as _save_share_password_attempts_store
from features.share_links_store import save_share_links
from utils.file_utils import validate_path
from utils.log_manager import logger
from utils.request_policy import ensure_path_access, is_protected_system_path


# ==========================================
_share_password_attempts_lock = threading.Lock()
_share_password_attempts = {}  # {(ip, token): {'attempts': int, 'blocked_until': datetime}}
_share_password_attempts_dirty = False


def load_share_password_attempts():
    with _share_password_attempts_lock:
        _share_password_attempts.clear()
        _share_password_attempts.update(_load_share_password_attempts_store())


def flush_share_password_attempts_if_dirty(force: bool = False) -> bool:
    global _share_password_attempts_dirty
    with _share_password_attempts_lock:
        if not force and not _share_password_attempts_dirty:
            return False
        snapshot = dict(_share_password_attempts)
    saved = _save_share_password_attempts_store(snapshot)
    if saved:
        _share_password_attempts_dirty = False
    return saved


def check_share_password_blocked(ip: str, token: str) -> tuple:
    global _share_password_attempts_dirty
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
                _share_password_attempts_dirty = True
                return False, 0

        return False, 0


def record_share_password_attempt(ip: str, token: str, success: bool):
    global _share_password_attempts_dirty
    """공유 링크 비밀번호 시도 기록 (스레드 안전)"""
    key = (ip, token)
    with _share_password_attempts_lock:
        if success:
            # 성공 시 기록 삭제
            if key in _share_password_attempts:
                del _share_password_attempts[key]
                _share_password_attempts_dirty = True
            return

        # 실패 기록
        now = datetime.now()
        if key not in _share_password_attempts:
            _share_password_attempts[key] = {'attempts': 0}

        _share_password_attempts[key]['attempts'] += 1
        _share_password_attempts[key]['last_attempt'] = now
        _share_password_attempts_dirty = True

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
