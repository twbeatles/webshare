"""
WebShare Pro - Metadata
태그, 메모, 즐겨찾기 관리
"""

import os
import json
import subprocess
from datetime import datetime

from config import (
    conf, metadata_lock, VIDEO_THUMB_FOLDER,
    FILE_TAGS, FILE_MEMOS, FAVORITE_FOLDERS, BOOKMARKS
)
from utils.log_manager import logger


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
    # Note: global 선언 불필요 - clear(), update(), extend()로 기존 객체를 수정함
    
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


def generate_video_thumbnail(video_path: str) -> str | None:
    """
    동영상 썸네일 생성 (ffmpeg 사용)
    
    Args:
        video_path: 동영상 파일 경로
        
    Returns:
        썸네일 파일 경로 또는 None
    """
    base_dir = conf.get('folder')
    thumb_dir = os.path.join(base_dir, VIDEO_THUMB_FOLDER)
    os.makedirs(thumb_dir, exist_ok=True)
    
    # 파일명 해시로 썸네일 파일명 생성
    import hashlib
    file_hash = hashlib.md5(video_path.encode()).hexdigest()[:12]
    thumb_path = os.path.join(thumb_dir, f"{file_hash}.jpg")
    
    # 이미 썸네일이 존재하고 크기가 0보다 크면 반환
    if os.path.exists(thumb_path) and os.path.getsize(thumb_path) > 0:
        return thumb_path
    
    try:
        # ffmpeg로 썸네일 생성 (5초 지점)
        cmd = [
            'ffmpeg', '-i', video_path,
            '-ss', '5', '-vframes', '1',
            '-vf', 'scale=320:-1',
            '-y', thumb_path
        ]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30
        )
        
        # ffmpeg 성공 및 파일 크기 검증
        if result.returncode == 0 and os.path.exists(thumb_path):
            if os.path.getsize(thumb_path) > 0:
                return thumb_path
            else:
                # 빈 파일 생성된 경우 삭제
                os.remove(thumb_path)
                logger.add(f"동영상 썸네일 생성 실패 (빈 파일): {video_path}", "WARN")
        
    except FileNotFoundError:
        # ffmpeg가 설치되어 있지 않음
        pass
    except subprocess.TimeoutExpired:
        logger.add(f"동영상 썸네일 생성 시간 초과: {video_path}", "WARN")
    except Exception as e:
        logger.add(f"동영상 썸네일 생성 실패: {e}", "ERROR")
    
    return None

