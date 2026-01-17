"""
WebShare Pro - Root API Routes
프론트엔드 호환을 위한 루트 레벨 API 엔드포인트
(기존 레거시 코드에서 /api 없이 사용하던 라우트들)
"""

import os
import shutil
from flask import Blueprint, jsonify, request, session
from datetime import datetime

from ..config import (
    conf, STATS, ACTIVE_SESSIONS, RECENT_FILES, ACCESS_LOG,
    stats_lock, session_lock, recent_files_lock, access_log_lock,
    SERVER_START_TIME
)
from ..utils.log_manager import logger
from ..utils.file_utils import get_folder_size, fmt_bytes, validate_path
from ..security.auth import login_required
from ..security.ip_blocker import get_blocked_ips, unblock_ip

root_api_bp = Blueprint('root_api', __name__)


# ==========================================
# 서버 상태 및 통계 (루트 레벨)
# ==========================================

@root_api_bp.route('/metrics')
@login_required()
def metrics():
    """서버 통계"""
    uptime = datetime.now() - SERVER_START_TIME
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    with stats_lock:
        stats_copy = STATS.copy()
    
    with session_lock:
        active_count = len(ACTIVE_SESSIONS)
    
    return jsonify({
        'uptime': f"{hours}h {minutes}m {seconds}s",
        'requests': stats_copy['requests'],
        'sent': fmt_bytes(stats_copy['bytes_sent']),
        'recv': fmt_bytes(stats_copy['bytes_received']),
        'bytes_sent': stats_copy['bytes_sent'],
        'bytes_received': stats_copy['bytes_received'],
        'bytes_sent_fmt': fmt_bytes(stats_copy['bytes_sent']),
        'bytes_received_fmt': fmt_bytes(stats_copy['bytes_received']),
        'errors': stats_copy['errors'],
        'active': active_count,
        'active_connections': active_count
    })


@root_api_bp.route('/disk_info')
@login_required()
def disk_info():
    """디스크 정보"""
    try:
        t, u, f = shutil.disk_usage(conf.get('folder'))
        return jsonify({
            'total': f"{t/1024**3:.1f}GB", 
            'used': f"{u/1024**3:.1f}GB", 
            'free': f"{f/1024**3:.1f}GB",
            'percent': round((u/t)*100, 1)
        })
    except Exception as e:
        logger.add(f"디스크 정보 조회 오류: {e}", "ERROR")
        return jsonify({'error': '디스크 정보를 가져올 수 없습니다.'})


@root_api_bp.route('/disk_status')
@login_required()
def disk_status():
    """디스크 상태 및 경고"""
    try:
        t, u, f = shutil.disk_usage(conf.get('folder'))
        percent = round((u / t) * 100, 1)
        threshold = conf.get('disk_warning_threshold') or 90
        
        return jsonify({
            'total': f"{t / 1024**3:.1f}GB",
            'used': f"{u / 1024**3:.1f}GB",
            'free': f"{f / 1024**3:.1f}GB",
            'percent': percent,
            'warning': percent >= threshold,
            'threshold': threshold
        })
    except (OSError, IOError) as e:
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
    is_valid, full_path, error = validate_path(conf.get('folder'), folder_path)
    if not is_valid or not os.path.isdir(full_path):
        return jsonify({'error': '폴더를 찾을 수 없습니다.'}), 404
    
    size = get_folder_size(full_path)
    # 포맷팅
    if size < 1024:
        size_str = f"{size} B"
    elif size < 1024 * 1024:
        size_str = f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        size_str = f"{size / 1024 / 1024:.1f} MB"
    else:
        size_str = f"{size / 1024 / 1024 / 1024:.2f} GB"
    
    return jsonify({'size': size, 'size_formatted': size_str})


@root_api_bp.route('/access_log')
@login_required('admin')
def get_access_log():
    """접속 기록 조회"""
    with access_log_lock:
        logs = list(ACCESS_LOG)
    return jsonify({'logs': logs})
