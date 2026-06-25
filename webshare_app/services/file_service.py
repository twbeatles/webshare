"""File route business helpers."""

import os
import shutil
import tempfile
import time

from flask import session

from utils.file_utils import get_real_ip, safe_filename, validate_path
from utils.helpers import build_recent_owner_key
from utils.log_manager import logger
from utils.request_policy import ensure_path_access, is_protected_system_path, normalize_relative_path


COPY_MOVE_CONFLICT_POLICIES = {'rename', 'fail', 'overwrite'}


def resolve_folder_upload_target(
    base_dir: str,
    folderpath: str,
    paths_entry: str | None,
    filename: str,
) -> tuple[bool, str, str, str]:
    """
    Resolve a drag-and-drop folder upload destination.

    Returns:
        (ok, abs_path, rel_path, error_message)
    """
    folder_rel = normalize_relative_path(folderpath)
    safe_name = safe_filename(filename)

    if paths_entry:
        normalized_entry = str(paths_entry).replace("\\", "/").strip("/")
        for segment in normalized_entry.split("/"):
            if segment == "..":
                return False, "", "", "잘못된 업로드 경로입니다"

        rel_under = normalize_relative_path(normalized_entry)
        if rel_under:
            parts = [safe_filename(part) for part in rel_under.split("/") if part]
            if parts:
                parts[-1] = safe_filename(parts[-1]) or safe_name
            rel_under = "/".join(parts) if parts else safe_name
        else:
            rel_under = safe_name
    else:
        rel_under = safe_name

    rel_save = "/".join(part for part in [folder_rel, rel_under] if part)
    valid, abs_path, error = validate_path(base_dir, rel_save)
    if not valid:
        return False, "", "", error or "잘못된 업로드 경로입니다"
    return True, abs_path, rel_save, ""


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


def _normalize_conflict_policy(value: str | None, default: str = 'rename') -> str:
    policy = str(value or default).strip().lower()
    return policy if policy in COPY_MOVE_CONFLICT_POLICIES else default


def _next_available_path(path: str) -> str:
    if not os.path.exists(path):
        return path

    parent = os.path.dirname(path)
    basename = os.path.basename(path)
    name, ext = os.path.splitext(basename)
    counter = 1
    while True:
        candidate_name = f"{name}_{counter}{ext}"
        candidate = os.path.join(parent, candidate_name)
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def _resolve_conflict_path(path: str, policy: str) -> tuple[bool, str, str]:
    if not os.path.exists(path):
        return True, path, ''
    if policy == 'fail':
        return False, path, '대상 경로가 이미 존재합니다.'
    if policy == 'rename':
        return True, _next_available_path(path), ''
    if policy == 'overwrite':
        return True, path, ''
    return False, path, '지원하지 않는 충돌 정책입니다.'


def _remove_existing_target(path: str):
    if not os.path.exists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def _copy_directory_to_staging(src: str, dst: str) -> str:
    parent = os.path.dirname(dst) or "."
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(dir=parent, prefix=".webshare_copydir_")
    shutil.rmtree(staging, ignore_errors=True)
    try:
        shutil.copytree(src, staging)
        return staging
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _replace_with_staging(staging: str, dst: str):
    backup = ""
    if os.path.exists(dst):
        backup = tempfile.mkdtemp(dir=os.path.dirname(dst) or ".", prefix=".webshare_backup_")
        shutil.rmtree(backup, ignore_errors=True)
        os.replace(dst, backup)
    try:
        os.replace(staging, dst)
        if backup:
            shutil.rmtree(backup, ignore_errors=True)
    except Exception:
        if backup and os.path.exists(backup) and not os.path.exists(dst):
            os.replace(backup, dst)
        raise


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
