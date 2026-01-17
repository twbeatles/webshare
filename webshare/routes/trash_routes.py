"""
WebShare Pro - Trash Routes
휴지통 기능
"""

import os
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, request

from ..config import (
    conf, TRASH_FOLDER_NAME
)
from ..utils.log_manager import logger
from ..utils.file_utils import validate_path, safe_filename
from ..security.auth import login_required
from ..features.trash import extract_original_name_from_trash

trash_bp = Blueprint('trash', __name__)


# ==========================================
# 휴지통으로 이동
# ==========================================

@trash_bp.route('/trash', methods=['POST'])
@login_required('admin')
def move_to_trash():
    """파일을 휴지통으로 이동"""
    data = request.get_json()
    path = data.get('path', '')
    
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'}), 404
    
    # 휴지통 폴더 생성
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    os.makedirs(trash_dir, exist_ok=True)
    
    # 타임스탬프를 붙여 이동
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = os.path.basename(full_path)
    trash_name = f"{timestamp}_{base_name}"
    trash_path = os.path.join(trash_dir, trash_name)
    
    try:
        shutil.move(full_path, trash_path)
        logger.add(f"휴지통 이동: {path}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==========================================
# 휴지통 목록
# ==========================================

@trash_bp.route('/trash/list')
@login_required('admin')
def list_trash():
    """휴지통 목록"""
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    if not os.path.exists(trash_dir):
        return jsonify({'items': []})
    
    items = []
    for name in os.listdir(trash_dir):
        full_path = os.path.join(trash_dir, name)
        try:
            stat = os.stat(full_path)
            items.append({
                'name': name,
                'original_name': extract_original_name_from_trash(name),
                'is_dir': os.path.isdir(full_path),
                'size': stat.st_size,
                'deleted_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        except OSError:
            continue
    
    return jsonify({'items': items})


# ==========================================
# 휴지통 복원
# ==========================================

@trash_bp.route('/trash/restore', methods=['POST'])
@login_required('admin')
def restore_from_trash():
    """휴지통에서 복원"""
    data = request.get_json()
    name = data.get('name', '')
    
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    trash_path = os.path.join(trash_dir, safe_filename(name))
    
    if not os.path.exists(trash_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'})
    
    # 원래 이름 추출
    original_name = extract_original_name_from_trash(name)
    restore_path = os.path.join(conf.get('folder'), original_name)
    
    # 동일 이름 파일 존재 시 이름 변경
    if os.path.exists(restore_path):
        base, ext = os.path.splitext(original_name)
        counter = 1
        while os.path.exists(restore_path):
            restore_path = os.path.join(conf.get('folder'), f"{base}_복원{counter}{ext}")
            counter += 1
            
    try:
        shutil.move(trash_path, restore_path)
        restored_name = os.path.basename(restore_path)
        logger.add(f"휴지통 복원: {name} -> {restored_name}")
        return jsonify({'success': True, 'restored_name': restored_name})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ==========================================
# 휴지통 비우기
# ==========================================

@trash_bp.route('/trash/empty', methods=['POST'])
@login_required('admin')
def empty_trash():
    """휴지통 비우기"""
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    if os.path.exists(trash_dir):
        try:
            shutil.rmtree(trash_dir)
            logger.add("휴지통 비움")
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return jsonify({'success': True})
