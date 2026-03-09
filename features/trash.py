"""
WebShare Pro - Trash and Versioning
휴지통 및 버전 관리
"""

import os
import re
import shutil
from datetime import datetime

from config import conf, TRASH_FOLDER_NAME, TRASH_AUTO_DELETE_DAYS
from utils.log_manager import logger


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


def auto_cleanup_trash() -> int:
    """휴지통 자동 비우기 (오래된 파일 삭제)"""
    base_dir = conf.get('folder')
    trash_dir = os.path.join(base_dir, TRASH_FOLDER_NAME)
    
    if not os.path.exists(trash_dir):
        return 0
    
    deleted_count = 0
    now = datetime.now()
    max_age_days = conf.get('trash_auto_delete_days') or TRASH_AUTO_DELETE_DAYS
    
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
                    deleted_count += 1
                    logger.add(f"휴지통 자동 삭제: {item} ({age_days}일 경과)")
            except (ValueError, OSError):
                continue
    except Exception as e:
        logger.add(f"휴지통 자동 비우기 오류: {e}", "ERROR")
    
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
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    trash_name = f"{timestamp}_{filename}"
    trash_path = os.path.join(trash_dir, trash_name)
    
    try:
        shutil.move(validated_path, trash_path)
        logger.add(f"휴지통 이동: {filename}")
        return True, trash_name
    except Exception as e:
        logger.add(f"휴지통 이동 실패: {e}", "ERROR")
        return False, str(e)


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
    trash_path = os.path.join(trash_dir, trash_name)
    
    if not os.path.exists(trash_path):
        return False, "파일을 찾을 수 없습니다"
    
    # 원본 파일명 추출
    original_name = extract_original_name_from_trash(trash_name)
    
    if restore_path is None:
        # 원본 이름이 안전한지 검증
        potential_path = os.path.join(base_dir, original_name)
        valid, validated_path, error = validate_path(base_dir, potential_path)
        if not valid:
            logger.add(f"휴지통 복원 거부 (유효하지 않은 원본 경로): {original_name}", "WARN")
            return False, "유효하지 않은 복원 파일명입니다"
        restore_path = validated_path
    else:
        # 경로 탐색 공격 방지: restore_path가 base_dir 내부인지 검증
        valid, validated_path, error = validate_path(base_dir, restore_path)
        if not valid:
            logger.add(f"휴지통 복원 거부 (경로 검증 실패): {restore_path}", "WARN")
            return False, "유효하지 않은 복원 경로입니다"
        restore_path = validated_path
    
    # 동일 파일 존재 시 번호 추가
    if os.path.exists(restore_path):
        name, ext = os.path.splitext(restore_path)
        counter = 1
        while os.path.exists(f"{name}_{counter}{ext}"):
            counter += 1
        restore_path = f"{name}_{counter}{ext}"
    
    try:
        shutil.move(trash_path, restore_path)
        logger.add(f"휴지통 복원: {original_name}")
        return True, restore_path
    except Exception as e:
        logger.add(f"휴지통 복원 실패: {e}", "ERROR")
        return False, str(e)
