"""Trash maintenance endpoints."""

from flask import jsonify, request
from config import conf
from utils.log_manager import logger
from security.auth import login_required
from utils.request_policy import parse_json_body
from ._common import admin_bp




# ==========================================
# 휴지통 설정
# ==========================================

@admin_bp.route('/api/trash_settings', methods=['GET', 'POST'])
@login_required('admin')
def trash_settings():
    """휴지통 자동 삭제 설정"""
    from config import TRASH_AUTO_DELETE_DAYS

    if request.method == 'GET':
        return jsonify({
            'auto_delete_days': conf.get('trash_auto_delete_days', TRASH_AUTO_DELETE_DAYS)
        })

    elif request.method == 'POST':
        data = parse_json_body(request)
        days = data.get('auto_delete_days', 30)

        if not isinstance(days, int) or days < 1:
            return jsonify({'error': '유효하지 않은 일수입니다.'}), 400

        conf.set('trash_auto_delete_days', days)
        conf.save()
        logger.add(f"휴지통 설정 변경: {days}일 후 자동 삭제")
        return jsonify({'success': True})

    return jsonify({'success': False, 'error': '지원하지 않는 메서드입니다.'}), 405




@admin_bp.route('/api/cleanup_trash', methods=['POST'])
@login_required('admin')
def cleanup_trash():
    """휴지통 수동 정리"""
    from features.trash import auto_cleanup_trash
    deleted = auto_cleanup_trash()
    return jsonify({'success': True, 'deleted': deleted})

