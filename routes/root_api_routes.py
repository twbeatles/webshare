"""
WebShare Pro - Root API Routes
프론트엔드 호환을 위한 루트 레벨 API 엔드포인트
(기존 레거시 코드에서 /api 없이 사용하던 라우트들)
"""

import os
from flask import Blueprint, jsonify
from datetime import datetime

from config import (
    conf, APP_VERSION, ACTIVE_SESSIONS, RECENT_FILES, ACCESS_LOG,
    session_lock, recent_files_lock, access_log_lock,
)
from utils.dashboard_service import get_disk_payload, get_metrics_payload
from utils.file_utils import get_folder_size, fmt_bytes, validate_path
from utils.request_policy import ensure_path_access
from security.auth import login_required

root_api_bp = Blueprint('root_api', __name__)


# ==========================================
# 서버 상태 및 통계 (루트 레벨)
# ==========================================

@root_api_bp.route('/healthz')
def healthz():
    """Liveness 체크 (비인증)"""
    return jsonify({
        'status': 'ok',
        'time': datetime.now().isoformat(),
        'version': APP_VERSION
    })


@root_api_bp.route('/readyz')
def readyz():
    """Readiness 체크 (비인증)"""
    from server import is_runtime_initialized

    folder = conf.get('folder') or ''
    checks = {
        'runtime_initialized': is_runtime_initialized(),
        'config_loaded': bool(folder),
        'shared_folder_access': bool(folder) and os.path.isdir(folder) and os.access(folder, os.R_OK),
    }
    ready = all(checks.values())
    payload = {
        'status': 'ready' if ready else 'not_ready',
        'checks': checks
    }
    return jsonify(payload), 200 if ready else 503

@root_api_bp.route('/metrics')
@login_required()
def metrics():
    """서버 통계"""
    payload = get_metrics_payload()
    return jsonify({
        'uptime': payload['uptime'],
        'requests': payload['requests'],
        'sent': payload['bytes_sent_fmt'],
        'recv': payload['bytes_received_fmt'],
        'bytes_sent': payload['bytes_sent'],
        'bytes_received': payload['bytes_received'],
        'bytes_sent_fmt': payload['bytes_sent_fmt'],
        'bytes_received_fmt': payload['bytes_received_fmt'],
        'errors': payload['errors'],
        'active': payload['active_connections'],
        'active_connections': payload['active_connections']
    })


@root_api_bp.route('/disk_info')
@login_required()
def disk_info():
    """디스크 정보"""
    try:
        disk = get_disk_payload()
        return jsonify({
            'total': disk['total'],
            'used': disk['used'],
            'free': disk['free'],
            'percent': disk['percent'],
            'total_fmt': disk['total_fmt'],
            'used_fmt': disk['used_fmt'],
            'free_fmt': disk['free_fmt'],
            'warning': disk['warning'],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@root_api_bp.route('/disk_status')
@login_required()
def disk_status():
    """디스크 상태 및 경고"""
    try:
        disk = get_disk_payload()
        return jsonify({
            'total': disk['total'],
            'used': disk['used'],
            'free': disk['free'],
            'percent': disk['percent'],
            'warning': disk['warning'],
            'threshold': disk['threshold']
        })
    except (OSError, IOError, ValueError) as e:
        return jsonify({'error': str(e)}), 500


@root_api_bp.route('/active_sessions')
@login_required('admin')
def active_sessions():
    """활성 세션 목록 (접속자 모니터링)"""
    now = datetime.now()
    timeout = conf.get('session_timeout') or 30
    active = []
    
    with session_lock:
        for sid, info in ACTIVE_SESSIONS.items():
            last_active = info.get('last_active')
            if last_active:
                # datetime 처리
                if isinstance(last_active, str):
                    try:
                        last_active = datetime.fromisoformat(last_active)
                    except ValueError:
                        last_active = now
                
                elapsed = (now - last_active).total_seconds() / 60
                if elapsed < timeout:
                    login_time = info.get('login_time', now)
                    if isinstance(login_time, datetime):
                        login_time = login_time.isoformat()
                    
                    active.append({
                        'ip': info.get('ip', 'unknown'),
                        'role': info.get('role', 'guest'),
                        'login_time': login_time,
                        'last_active': last_active.isoformat() if isinstance(last_active, datetime) else str(last_active),
                        'idle_minutes': round(elapsed, 1)
                    })
    
    return jsonify({'sessions': active, 'count': len(active)})


@root_api_bp.route('/recent_files')
@login_required()
def recent_files():
    """최근 파일 목록"""
    with recent_files_lock:
        files = list(RECENT_FILES[:20])
    return jsonify({'files': files})


@root_api_bp.route('/folder_size/<path:folder_path>')
@login_required()
def folder_size(folder_path):
    """폴더 크기 계산"""
    ok, message, status_code = ensure_path_access(folder_path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), folder_path)
    if not is_valid or not os.path.isdir(full_path):
        return jsonify({'error': '폴더를 찾을 수 없습니다.'}), 404
    
    size = get_folder_size(full_path)
    return jsonify({'size': size, 'size_formatted': fmt_bytes(size)})


@root_api_bp.route('/access_log')
@login_required('admin')
def get_access_log():
    """접속 기록 조회"""
    with access_log_lock:
        logs = list(ACCESS_LOG)
    return jsonify({'logs': logs})
