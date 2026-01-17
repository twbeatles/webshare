"""
WebShare Pro - Cloud Sync (v7.2)
클라우드 동기화 설정 관리
"""

import os
import json
import tempfile

from ..config import conf, CLOUD_SYNC_CONFIG, CLOUD_SYNC_FILE, cloud_sync_lock
from ..utils.log_manager import logger


def save_cloud_config():
    """클라우드 설정 저장 (스레드 안전, 원자적 쓰기)"""
    base_dir = conf.get('folder')
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)
    
    with cloud_sync_lock:
        try:
            # 민감 정보 제외 (토큰만 저장)
            safe_config = {}
            for provider, cfg in CLOUD_SYNC_CONFIG.items():
                safe_config[provider] = {
                    'enabled': cfg.get('enabled', False),
                    'token': cfg.get('token'),
                    'folder_id': cfg.get('folder_id', '')
                }
            
            # 원자적 쓰기: 임시 파일에 쓴 후 rename
            fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix='.webshare_cloud_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(safe_config, f, ensure_ascii=False, indent=2)
                if os.path.exists(cloud_path):
                    os.remove(cloud_path)
                os.rename(temp_path, cloud_path)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        except Exception as e:
            logger.add(f"클라우드 설정 저장 실패: {e}", "ERROR")


def load_cloud_config():
    """클라우드 설정 로드 (스레드 안전)"""
    base_dir = conf.get('folder')
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)
    
    if not os.path.exists(cloud_path):
        return
    
    with cloud_sync_lock:
        try:
            with open(cloud_path, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            
            for provider, cfg in saved.items():
                if provider in CLOUD_SYNC_CONFIG:
                    CLOUD_SYNC_CONFIG[provider].update(cfg)
            
            logger.add("클라우드 설정 로드 완료")
        except Exception as e:
            logger.add(f"클라우드 설정 로드 실패: {e}", "ERROR")
