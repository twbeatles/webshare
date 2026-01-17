"""
WebShare Pro - Cloud Routes
클라우드 동기화 API
"""

import os
from flask import Blueprint, jsonify, request, session

from ..config import conf, CLOUD_SYNC_CONFIG, cloud_sync_lock
from ..utils.log_manager import logger
from ..security.auth import login_required
from ..features.audit_log import log_audit

cloud_bp = Blueprint('cloud', __name__)


def save_cloud_config():
    """클라우드 설정 저장"""
    import json
    from ..config import CLOUD_SYNC_FILE
    
    try:
        with open(CLOUD_SYNC_FILE, 'w', encoding='utf-8') as f:
            json.dump(CLOUD_SYNC_CONFIG, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.add(f"클라우드 설정 저장 실패: {e}", "ERROR")


@cloud_bp.route('/api/cloud/config', methods=['GET', 'POST'])
@login_required('admin')
def cloud_config():
    """클라우드 동기화 설정"""
    if request.method == 'GET':
        # 민감 정보 마스킹
        safe_config = {}
        for provider, cfg in CLOUD_SYNC_CONFIG.items():
            safe_config[provider] = {
                'enabled': cfg.get('enabled', False),
                'configured': bool(cfg.get('token')),
                'folder_id': cfg.get('folder_id', '')
            }
        return jsonify({'config': safe_config})
    
    elif request.method == 'POST':
        data = request.get_json()
        provider = data.get('provider')
        
        if provider not in CLOUD_SYNC_CONFIG:
            return jsonify({'error': '지원하지 않는 클라우드 서비스입니다.'}), 400
        
        with cloud_sync_lock:
            CLOUD_SYNC_CONFIG[provider].update({
                'enabled': data.get('enabled', False),
                'client_id': data.get('client_id', ''),
                'client_secret': data.get('client_secret', ''),
                'app_key': data.get('app_key', ''),
                'app_secret': data.get('app_secret', ''),
                'folder_id': data.get('folder_id', '')
            })
        
        save_cloud_config()
        return jsonify({'success': True})


@cloud_bp.route('/api/cloud/status', methods=['GET'])
@login_required('admin')
def cloud_status():
    """클라우드 동기화 상태"""
    status = {}
    for provider, cfg in CLOUD_SYNC_CONFIG.items():
        status[provider] = {
            'enabled': cfg.get('enabled', False),
            'connected': bool(cfg.get('token')),
            'last_sync': cfg.get('last_sync', None)
        }
    return jsonify({'status': status})


@cloud_bp.route('/api/cloud/sync/<provider>', methods=['POST'])
@login_required('admin')
def cloud_sync(provider):
    """클라우드 동기화 실행"""
    if provider not in CLOUD_SYNC_CONFIG:
        return jsonify({'error': '지원하지 않는 클라우드 서비스입니다.'}), 400
    
    cfg = CLOUD_SYNC_CONFIG[provider]
    if not cfg.get('enabled') or not cfg.get('token'):
        return jsonify({'error': '클라우드 서비스가 설정되지 않았습니다.'}), 400
    
    data = request.get_json() or {}
    sync_path = data.get('path', '')
    direction = data.get('direction', 'upload')
    
    log_audit(
        session.get('role', 'admin'),
        'cloud_sync',
        f"{provider}:{sync_path}",
        f"direction={direction}",
        ip=request.remote_addr
    )
    
    return jsonify({
        'success': True,
        'message': f'{provider} 동기화가 시작되었습니다.',
        'note': 'API 키 설정이 필요합니다.'
    })
