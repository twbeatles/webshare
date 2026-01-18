"""
WebShare Pro - Trash Routes
휴지통 기능
"""

import os
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, request, session

from ..config import (
    conf, TRASH_FOLDER_NAME
)
from ..utils.log_manager import logger
from ..utils.file_utils import validate_path, safe_filename, get_real_ip
from ..security.auth import login_required
from ..features.trash import extract_original_name_from_trash
from ..features.audit_log import log_audit

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
        
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='trash_move',
            target=path,
            details=f"Trash name: {trash_name}",
            ip=get_real_ip()
        )
        
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
    from ..features.trash import restore_from_trash as restore_feature
    
    data = request.get_json()
    name = data.get('name', '')
    
    success, result = restore_feature(name)
    
    if success:
        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='trash_restore',
            target=name,
            details=f"Restored to: {os.path.basename(result)}",
            ip=get_real_ip()
        )
        return jsonify({'success': True, 'restored_name': os.path.basename(result)})
    else:
        return jsonify({'success': False, 'error': result})


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
            # 삭제 전 파일 수 계산
            item_count = len(os.listdir(trash_dir))
            shutil.rmtree(trash_dir)
            logger.add("휴지통 비움")
            
            # 감사 로그 기록
            log_audit(
                user=session.get('role', 'unknown'),
                action='trash_empty',
                target=TRASH_FOLDER_NAME,
                details=f"{item_count}개 항목 영구 삭제",
                ip=get_real_ip()
            )
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return jsonify({'success': True})
