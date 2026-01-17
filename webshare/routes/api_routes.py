"""
WebShare Pro - API Routes
REST API 엔드포인트
"""

import os
from flask import Blueprint, jsonify, request, session
from datetime import datetime

from ..config import (
    conf, STATS, ACTIVE_SESSIONS, RECENT_FILES,
    stats_lock, session_lock, recent_files_lock,
    SERVER_START_TIME
)
from ..utils.log_manager import logger
from ..utils.file_utils import get_folder_size, fmt_bytes
from ..security.auth import login_required
from ..security.ip_blocker import get_blocked_ips, unblock_ip
from ..features.trash import auto_cleanup_trash
from ..features.audit_log import AUDIT_LOG, audit_lock

api_bp = Blueprint('api', __name__)


@api_bp.route('/metrics')
@login_required()
def metrics():
    """서버 통계"""
    uptime = datetime.now() - SERVER_START_TIME
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    with session_lock:
        active_count = len(ACTIVE_SESSIONS)
    
    return jsonify({
        'requests': STATS['requests'],
        'bytes_sent': STATS['bytes_sent'],
        'bytes_received': STATS['bytes_received'],
        'bytes_sent_fmt': fmt_bytes(STATS['bytes_sent']),
        'bytes_received_fmt': fmt_bytes(STATS['bytes_received']),
        'errors': STATS['errors'],
        'active_connections': active_count,
        'uptime': f"{hours}h {minutes}m {seconds}s"
    })


@api_bp.route('/disk_info')
@login_required()
def disk_info():
    """디스크 정보"""
    import shutil
    
    base_dir = conf.get('folder')
    
    try:
        total, used, free = shutil.disk_usage(base_dir)
        percent = round(used / total * 100, 1)
        
        return jsonify({
            'total': fmt_bytes(total),
            'used': fmt_bytes(used),
            'free': fmt_bytes(free),
            'percent': percent,
            'warning': percent >= conf.get('disk_warning_threshold', 90)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/disk_status')
@login_required()
def disk_status():
    """디스크 경고 상태"""
    import shutil
    
    base_dir = conf.get('folder')
    
    try:
        total, used, free = shutil.disk_usage(base_dir)
        percent = round(used / total * 100, 1)
        threshold = conf.get('disk_warning_threshold', 90)
        
        return jsonify({
            'percent': percent,
            'free': fmt_bytes(free),
            'warning': percent >= threshold
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/active_sessions')
@login_required()
def active_sessions():
    """활성 세션 목록"""
    now = datetime.now()
    sessions = []
    
    with session_lock:
        for sid, info in ACTIVE_SESSIONS.items():
            last_active = info.get('last_active', info.get('login_time'))
            
            # datetime 처리
            if isinstance(last_active, str):
                try:
                    last_active = datetime.fromisoformat(last_active)
                except ValueError:
                    last_active = now
            
            idle_minutes = int((now - last_active).total_seconds() / 60)
            
            sessions.append({
                'ip': info.get('ip', 'unknown'),
                'role': info.get('role', 'guest'),
                'idle_minutes': idle_minutes
            })
    
    return jsonify({
        'count': len(sessions),
        'sessions': sessions
    })


@api_bp.route('/recent_files')
@login_required()
def recent_files():
    """최근 파일 목록"""
    with recent_files_lock:
        files = list(RECENT_FILES[:20])
    
    return jsonify({'files': files})


@api_bp.route('/blocked_ips')
@login_required('admin')
def blocked_ips():
    """차단된 IP 목록"""
    return jsonify({'blocked': get_blocked_ips()})


@api_bp.route('/unblock/<ip>', methods=['POST'])
@login_required('admin')
def unblock(ip):
    """IP 차단 해제"""
    success = unblock_ip(ip)
    if success:
        logger.add(f"IP 차단 해제: {ip}")
        return jsonify({'success': True})
    return jsonify({'error': 'IP를 찾을 수 없습니다'}), 404


@api_bp.route('/audit_log')
@login_required('admin')
def audit_log():
    """감사 로그 조회"""
    limit = request.args.get('limit', 100, type=int)
    
    with audit_lock:
        logs = list(AUDIT_LOG[-limit:])
    
    return jsonify({'logs': logs[::-1]})  # 최신순


@api_bp.route('/folder_size/<path:folderpath>')
@login_required()
def folder_size(folderpath):
    """폴더 크기 계산"""
    from ..utils.file_utils import validate_path
    
    base_dir = conf.get('folder')
    valid, full_path, error = validate_path(base_dir, folderpath)
    
    if not valid:
        return jsonify({'error': error}), 400
    
    if not os.path.isdir(full_path):
        return jsonify({'error': '폴더가 아닙니다'}), 400
    
    size = get_folder_size(full_path)
    return jsonify({
        'path': folderpath,
        'size': size,
        'size_fmt': fmt_bytes(size)
    })


@api_bp.route('/trash/cleanup', methods=['POST'])
@login_required('admin')
def trash_cleanup():
    """휴지통 정리"""
    deleted = auto_cleanup_trash()
    return jsonify({
        'success': True,
        'deleted': deleted
    })
