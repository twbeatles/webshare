"""
WebShare Pro - Trash and Versioning
휴지통 및 버전 관리
"""

import os
import json
import re
import shutil
import tempfile
import uuid
from datetime import datetime

from config import conf, TRASH_FOLDER_NAME, TRASH_AUTO_DELETE_DAYS
from utils.log_manager import logger

TRASH_METADATA_FILE = ".webshare_trash.json"


def extract_original_name_from_trash(trash_name: str) -> str:
    """
    휴지통 파일명에서 원본 파일명 추출.
    형식: YYYYMMDD_HHMMSS_원본파일명
    """
    pattern = r'^\d{8}_\d{6}_(.+)$'
    match = re.match(pattern, trash_name)
    if match:
        return match.group(1)
    return trash_name


def _trash_metadata_path() -> str:
    return os.path.join(conf.get('folder'), TRASH_METADATA_FILE)


def _load_trash_metadata() -> dict:
    path = _trash_metadata_path()
    if not os.path.exists(path):
        return {'entries': {}}
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            raw = json.load(handle)
    except Exception:
        return {'entries': {}}

    entries = raw.get('entries', {}) if isinstance(raw, dict) else {}
    if isinstance(entries, list):
        entries = {
            str(item.get('trash_name', '') or item.get('id', '')): item
            for item in entries
            if isinstance(item, dict)
        }
    if not isinstance(entries, dict):
        entries = {}
    return {'entries': entries}


def _save_trash_metadata(metadata: dict):
    base_dir = conf.get('folder')
    os.makedirs(base_dir, exist_ok=True)
    path = _trash_metadata_path()
    fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix='.webshare_trash_', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(metadata, handle, ensure_ascii=False, indent=2)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def get_trash_metadata_entry(trash_name: str) -> dict:
    metadata = _load_trash_metadata()
    entry = metadata.get('entries', {}).get(os.path.basename(str(trash_name or '')), {})
    return dict(entry) if isinstance(entry, dict) else {}


def _next_available_trash_path(trash_dir: str, trash_name: str) -> tuple[str, str]:
    candidate_name = trash_name
    candidate_path = os.path.join(trash_dir, candidate_name)
    counter = 1
    stem, ext = os.path.splitext(trash_name)
    while os.path.exists(candidate_path):
        candidate_name = f"{stem}_{counter}{ext}"
        candidate_path = os.path.join(trash_dir, candidate_name)
        counter += 1
    return candidate_name, candidate_path


def _next_available_restore_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    counter = 1
    while os.path.exists(f"{stem}_{counter}{ext}"):
        counter += 1
    return f"{stem}_{counter}{ext}"


def auto_cleanup_trash() -> int:
    """휴지통 자동 비우기 (오래된 파일 삭제)"""
    base_dir = conf.get('folder')
    trash_dir = os.path.join(base_dir, TRASH_FOLDER_NAME)
    
    if not os.path.exists(trash_dir):
        return 0
    
    deleted_count = 0
    now = datetime.now()
    max_age_days = conf.get('trash_auto_delete_days') or TRASH_AUTO_DELETE_DAYS
    
    metadata = _load_trash_metadata()
    metadata_changed = False

    try:
        for item in os.listdir(trash_dir):
            item_path = os.path.join(trash_dir, item)
            # 타임스탬프에서 삭제 시간 추출 (형식: YYYYMMDD_HHMMSS_파일명)
            try:
                timestamp_str = item[:15]  # YYYYMMDD_HHMMSS
                deleted_time = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                age_days = (now - deleted_time).days
                
                if age_days >= max_age_days:
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
                    if metadata.get('entries', {}).pop(item, None) is not None:
                        metadata_changed = True
                    deleted_count += 1
                    logger.add(f"휴지통 자동 삭제: {item} ({age_days}일 경과)")
            except (ValueError, OSError):
                continue
    except Exception as e:
        logger.add(f"휴지통 자동 비우기 오류: {e}", "ERROR")

    if metadata_changed:
        try:
            _save_trash_metadata(metadata)
        except Exception as exc:
            logger.add(f"휴지통 metadata 저장 실패: {exc}", "ERROR")
    
    return deleted_count


def move_to_trash(file_path: str) -> tuple:
    """파일을 휴지통으로 이동 (경로 검증 포함)"""
    from utils.file_utils import validate_path
    
    base_dir = conf.get('folder')
    
    # 경로 검증: base_dir 내부 파일만 휴지통으로 이동 가능
    valid, validated_path, error = validate_path(base_dir, os.path.relpath(file_path, base_dir) if os.path.isabs(file_path) else file_path)
    if not valid:
        logger.add(f"휴지통 이동 거부 (경로 검증 실패): {file_path}", "WARN")
        return False, "유효하지 않은 경로입니다"
    
    if not os.path.exists(validated_path):
        return False, "파일을 찾을 수 없습니다"
    
    trash_dir = os.path.join(base_dir, TRASH_FOLDER_NAME)
    os.makedirs(trash_dir, exist_ok=True)
    
    filename = os.path.basename(validated_path)
    original_rel_path = os.path.relpath(validated_path, base_dir).replace('\\', '/')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    entry_id = uuid.uuid4().hex
    trash_name, trash_path = _next_available_trash_path(trash_dir, f"{timestamp}_{entry_id}_{filename}")

    try:
        shutil.move(validated_path, trash_path)
        metadata = _load_trash_metadata()
        metadata.setdefault('entries', {})[trash_name] = {
            'id': entry_id,
            'original_rel_path': original_rel_path,
            'trash_name': trash_name,
            'deleted_at': datetime.now().isoformat(),
            'is_dir': os.path.isdir(trash_path),
        }
        _save_trash_metadata(metadata)
        logger.add(f"휴지통 이동: {filename}")
        return True, trash_name
    except Exception as e:
        logger.add(f"휴지통 이동 실패: {e}", "ERROR")
        return False, "휴지통으로 이동하는 중 오류가 발생했습니다."


def restore_from_trash(trash_name: str, restore_path: str | None = None) -> tuple:
    """
    휴지통에서 파일 복원.
    
    Args:
        trash_name: 휴지통 내 파일명 (YYYYMMDD_HHMMSS_원본파일명)
        restore_path: 복원 경로 (None이면 기본 폴더로 복원)
    
    Returns:
        tuple: (success: bool, result_path_or_error: str)
    """
    from utils.file_utils import validate_path
    
    base_dir = conf.get('folder')
    trash_dir = os.path.join(base_dir, TRASH_FOLDER_NAME)
    safe_trash_name = os.path.basename(str(trash_name or ''))
    trash_path = os.path.join(trash_dir, safe_trash_name)
    
    if not os.path.exists(trash_path):
        return False, "파일을 찾을 수 없습니다"
    
    metadata = _load_trash_metadata()
    entry = metadata.get('entries', {}).get(safe_trash_name, {})
    original_rel_path = ''
    if isinstance(entry, dict):
        original_rel_path = str(entry.get('original_rel_path', '') or '').strip('/')

    # 원본 파일명 추출 (metadata가 없는 legacy 항목 호환)
    original_name = extract_original_name_from_trash(safe_trash_name)
    
    if restore_path is None:
        target_rel_path = original_rel_path or original_name
        valid, validated_path, error = validate_path(base_dir, target_rel_path)
        if not valid:
            logger.add(f"휴지통 복원 거부 (유효하지 않은 원본 경로): {target_rel_path}", "WARN")
            return False, "유효하지 않은 복원 파일명입니다"
        restore_path = validated_path
    else:
        # 경로 탐색 공격 방지: restore_path가 base_dir 내부인지 검증
        valid, validated_path, error = validate_path(base_dir, restore_path)
        if not valid:
            logger.add(f"휴지통 복원 거부 (경로 검증 실패): {restore_path}", "WARN")
            return False, "유효하지 않은 복원 경로입니다"
        restore_path = validated_path
    
    restore_dir = os.path.dirname(restore_path) or base_dir
    os.makedirs(restore_dir, exist_ok=True)
    restore_path = _next_available_restore_path(restore_path)
    
    try:
        shutil.move(trash_path, restore_path)
        if metadata.get('entries', {}).pop(safe_trash_name, None) is not None:
            _save_trash_metadata(metadata)
        logger.add(f"휴지통 복원: {original_name}")
        return True, restore_path
    except Exception as e:
        logger.add(f"휴지통 복원 실패: {e}", "ERROR")
        return False, "휴지통에서 복원하는 중 오류가 발생했습니다."
