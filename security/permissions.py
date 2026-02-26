"""
WebShare Pro - Folder Permissions (v7.2)
폴더별 접근 권한 관리
"""

import os
import json
import tempfile

from config import (
    conf, permissions_lock, FOLDER_PERMISSIONS, PERMISSIONS_FILE
)
from utils.log_manager import logger


def check_permission(path: str, user: str, action: str) -> bool:
    """
    폴더 권한 확인 (read/write/delete).
    
    권한 상속: 상위 폴더의 권한이 하위 폴더에 적용됨.
    기본 정책: 권한이 명시되지 않은 경우 허용 (allow by default)
    """
    # 관리자는 모든 권한 허용
    if user == 'admin':
        return True
    
    with permissions_lock:
        # 상위 폴더부터 권한 확인 (상속)
        path_parts = path.replace('\\', '/').split('/')
        current_path = ''
        
        for part in path_parts:
            if not part:
                continue
            current_path = current_path + '/' + part if current_path else part
            
            if current_path in FOLDER_PERMISSIONS:
                perm = FOLDER_PERMISSIONS[current_path]
                action_users = perm.get(action, [])
                
                # '*' 는 모든 사용자 허용
                if '*' in action_users or user in action_users:
                    continue
                
                # 권한이 명시적으로 정의되어 있고 사용자가 없으면 거부
                if action_users:
                    return False
        
        return True


def save_permissions():
    """폴더 권한 파일로 저장 (원자적 쓰기)"""
    base_dir = conf.get('folder')
    perm_path = os.path.join(base_dir, PERMISSIONS_FILE)
    
    with permissions_lock:
        try:
            # 원자적 쓰기: 임시 파일에 쓴 후 rename
            fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix='.webshare_perm_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(FOLDER_PERMISSIONS, f, ensure_ascii=False, indent=2)
                if os.path.exists(perm_path):
                    os.remove(perm_path)
                os.rename(temp_path, perm_path)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        except Exception as e:
            logger.add(f"권한 저장 실패: {e}", "ERROR")


def load_permissions():
    """폴더 권한 파일에서 로드"""
    base_dir = conf.get('folder')
    perm_path = os.path.join(base_dir, PERMISSIONS_FILE)
    
    if not os.path.exists(perm_path):
        return
    
    with permissions_lock:
        try:
            with open(perm_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                FOLDER_PERMISSIONS.clear()
                FOLDER_PERMISSIONS.update(loaded)
            logger.add(f"폴더 권한 로드: {len(FOLDER_PERMISSIONS)}개 폴더")
        except Exception as e:
            logger.add(f"권한 로드 실패: {e}", "ERROR")


def set_folder_permission(path: str, action: str, users: list):
    """폴더 권한 설정"""
    with permissions_lock:
        if path not in FOLDER_PERMISSIONS:
            FOLDER_PERMISSIONS[path] = {'read': ['*'], 'write': ['*'], 'delete': ['admin']}
        FOLDER_PERMISSIONS[path][action] = users
    save_permissions()


def delete_folder_permission(path: str) -> bool:
    """폴더 권한 삭제"""
    with permissions_lock:
        if path in FOLDER_PERMISSIONS:
            del FOLDER_PERMISSIONS[path]
            save_permissions()
            logger.add(f"폴더 권한 삭제: {path}")
            return True
    return False
