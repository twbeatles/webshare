"""
WebShare Pro - Metadata
태그, 메모, 즐겨찾기 관리
"""

import os
import json
from datetime import datetime

from ..config import (
    conf, metadata_lock,
    FILE_TAGS, FILE_MEMOS, FAVORITE_FOLDERS, BOOKMARKS
)
from ..utils.log_manager import logger


def save_metadata():
    """메타데이터(태그, 즐겨찾기, 메모) 파일로 저장 (스레드 안전, 원자적 쓰기)"""
    import tempfile
    
    base_dir = conf.get('folder')
    meta_path = os.path.join(base_dir, '.webshare_meta.json')
    
    with metadata_lock:
        data = {
            'tags': FILE_TAGS,
            'favorites': FAVORITE_FOLDERS,
            'memos': FILE_MEMOS,
            'bookmarks': BOOKMARKS,
            'updated': datetime.now().isoformat()
        }
        
        try:
            # 원자적 쓰기: 임시 파일에 쓴 후 rename (데이터 손실 방지)
            fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix='.webshare_meta_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                # Windows에서는 rename 전에 기존 파일 삭제 필요
                if os.path.exists(meta_path):
                    os.remove(meta_path)
                os.rename(temp_path, meta_path)
            except Exception:
                # 실패 시 임시 파일 정리
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        except Exception as e:
            logger.add(f"메타데이터 저장 실패: {e}", "ERROR")


def load_metadata():
    """메타데이터(태그, 즐겨찾기, 메모) 파일에서 로드 (스레드 안전)"""
    global FILE_TAGS, FAVORITE_FOLDERS, FILE_MEMOS, BOOKMARKS
    
    base_dir = conf.get('folder')
    meta_path = os.path.join(base_dir, '.webshare_meta.json')
    
    if not os.path.exists(meta_path):
        return
    
    with metadata_lock:
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            FILE_TAGS.clear()
            FILE_TAGS.update(data.get('tags', {}))
            
            FAVORITE_FOLDERS.clear()
            FAVORITE_FOLDERS.extend(data.get('favorites', []))
            
            FILE_MEMOS.clear()
            FILE_MEMOS.update(data.get('memos', {}))
            
            BOOKMARKS.clear()
            BOOKMARKS.extend(data.get('bookmarks', []))
            
            logger.add("메타데이터 로드 완료")
        except Exception as e:
            logger.add(f"메타데이터 로드 실패: {e}", "ERROR")
