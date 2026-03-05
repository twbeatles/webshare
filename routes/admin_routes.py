"""
WebShare Pro - Admin Routes
사용자 관리, 권한 관리, 감사 로그, 대시보드
"""

import os
import re
import io
import csv
import threading
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, send_file, session

from config import (
    conf, FOLDER_PERMISSIONS, ACCESS_LOG, AUDIT_LOG,
    permissions_lock, access_log_lock, audit_lock
)
from utils.log_manager import logger
from utils.file_utils import get_folder_size
from security.auth import login_required, hash_password
from security.permissions import save_permissions
from security.ip_blocker import get_blocked_ips
from features.audit_log import save_audit_log, log_audit
from utils.file_utils import get_real_ip
from utils.request_policy import parse_json_body

admin_bp = Blueprint('admin', __name__)

_users_file_lock = threading.Lock()
USER_API_NOTICE = "사용자 API는 현재 로그인 인증과 연동되지 않음"
USER_API_WARNING = "현재 로그인 방식은 admin_pw/guest_pw(비밀번호 단독)이며 사용자 API 계정과 연동되지 않습니다."


def get_users_file_path():
    """사용자 파일 경로 반환 (공유 폴더 내부에 저장)"""
    return os.path.join(conf.get('folder'), '.webshare_users.json')


# ==========================================
# 사용자 관리
# ==========================================

def load_users():
    """사용자 목록 로드 (스레드 안전)"""
    import json
    users_file = get_users_file_path()
    with _users_file_lock:
        if os.path.exists(users_file):
            try:
                with open(users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {
            'users': {
                '_legacy_admin': {
                    'password_hash': conf.get('admin_pw', '1234'),
                    'role': 'admin',
                    'quota_mb': 0,
                    'folders': ['*'],
                    'created': datetime.now().isoformat()
                },
                '_legacy_guest': {
                    'password_hash': conf.get('guest_pw', '0000'),
                    'role': 'guest',
                    'quota_mb': 0,
                    'folders': ['*'],
                    'created': datetime.now().isoformat()
                }
            }
        }


def save_users(users_data):
    """사용자 목록 저장 (스레드 안전)"""
    import json
    import tempfile

    users_file = get_users_file_path()
    with _users_file_lock:
        try:
            base_dir = os.path.dirname(users_file) or '.'
            os.makedirs(base_dir, exist_ok=True)
            fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix='.webshare_users_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(users_data, f, indent=2, ensure_ascii=False)
                os.replace(temp_path, users_file)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
            return True
        except IOError as e:
            logger.add(f"사용자 저장 실패: {e}", "ERROR")
            return False


def get_user_usage(username):
    """사용자 업로드 용량 계산"""
    user_folder = os.path.join(conf.get('folder'), f'_user_{username}')
    if os.path.exists(user_folder):
        return get_folder_size(user_folder)
    return 0


@admin_bp.route('/api/users', methods=['GET', 'POST'])
@login_required('admin')
def manage_users():
    """사용자 목록 조회 및 생성"""
    users_data = load_users()
    
    if request.method == 'GET':
        safe_users = {}
        for username, info in users_data.get('users', {}).items():
            if not username.startswith('_legacy_'):
                safe_users[username] = {
                    'role': info.get('role', 'user'),
                    'quota_mb': info.get('quota_mb', 0),
                    'folders': info.get('folders', []),
                    'created': info.get('created', ''),
                    'usage_mb': round(get_user_usage(username) / 1024 / 1024, 2)
                }
        return jsonify({
            'users': safe_users,
            'login_mode': 'password_only',
            'login_linked': False,
            'notice': USER_API_NOTICE
        })
    
    elif request.method == 'POST':
        data = parse_json_body(request)
        username = data.get('username', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'user')
        quota_mb = data.get('quota_mb', 1024)
        folders = data.get('folders', [])
        
        if not username or not password:
            return jsonify({'success': False, 'error': '사용자명과 비밀번호가 필요합니다.'}), 400
        
        if not re.match(r'^[a-zA-Z0-9_\-]{3,20}$', username):
            return jsonify({'success': False, 
                'error': '사용자명은 3-20자의 영문, 숫자, _, -만 사용 가능합니다.'}), 400
        
        if username in users_data.get('users', {}):
            return jsonify({'success': False, 'error': '이미 존재하는 사용자입니다.'}), 400
        
        users_data.setdefault('users', {})[username] = {
            'password_hash': hash_password(password),
            'role': role,
            'quota_mb': quota_mb,
            'folders': folders if folders else [f'/_user_{username}'],
            'created': datetime.now().isoformat()
        }
        
        user_folder = os.path.join(conf.get('folder'), f'_user_{username}')
        os.makedirs(user_folder, exist_ok=True)
        
        if save_users(users_data):
            logger.add(f"사용자 생성: {username}")
            log_audit(
                user=session.get('role', 'unknown'),
                action='user_create',
                target=username,
                details=f"Role: {role}",
                ip=get_real_ip()
            )
            return jsonify({'success': True, 'warning': USER_API_WARNING})
        return jsonify({'success': False, 'error': '저장 실패'}), 500


@admin_bp.route('/api/users/<username>', methods=['GET', 'PUT', 'DELETE'])
@login_required('admin')
def manage_single_user(username):
    """개별 사용자 관리"""
    users_data = load_users()
    users = users_data.get('users', {})
    
    if username not in users:
        return jsonify({'error': '사용자를 찾을 수 없습니다.'}), 404
    
    if request.method == 'GET':
        info = users[username]
        return jsonify({
            'username': username,
            'role': info.get('role', 'user'),
            'quota_mb': info.get('quota_mb', 0),
            'folders': info.get('folders', []),
            'created': info.get('created', ''),
            'usage_mb': round(get_user_usage(username) / 1024 / 1024, 2)
        })
    
    elif request.method == 'PUT':
        data = parse_json_body(request)
        
        if 'password' in data and data['password']:
            users[username]['password_hash'] = hash_password(data['password'])
        if 'role' in data:
            users[username]['role'] = data['role']
        if 'quota_mb' in data:
            users[username]['quota_mb'] = data['quota_mb']
        if 'folders' in data:
            users[username]['folders'] = data['folders']
        
        if save_users(users_data):
            logger.add(f"사용자 수정: {username}")
            log_audit(
                user=session.get('role', 'unknown'),
                action='user_update',
                target=username,
                details=f"Fields: {list(data.keys())}",
                ip=get_real_ip()
            )
            return jsonify({'success': True, 'warning': USER_API_WARNING})
        return jsonify({'success': False, 'error': '저장 실패'}), 500
    
    elif request.method == 'DELETE':
        if username.startswith('_legacy_'):
            return jsonify({'success': False, 'error': '기본 사용자는 삭제할 수 없습니다.'}), 400
        
        del users[username]
        if save_users(users_data):
            logger.add(f"사용자 삭제: {username}")
            log_audit(
                user=session.get('role', 'unknown'),
                action='user_delete',
                target=username,
                ip=get_real_ip()
            )
            return jsonify({'success': True, 'warning': USER_API_WARNING})
        return jsonify({'success': False, 'error': '저장 실패'}), 500


# ==========================================
# 폴더 권한 관리
# ==========================================

@admin_bp.route('/api/permissions', methods=['GET', 'POST'])
@login_required('admin')
def manage_permissions():
    """폴더 권한 관리"""
    if request.method == 'GET':
        with permissions_lock:
            return jsonify({'permissions': FOLDER_PERMISSIONS.copy()})
    
    elif request.method == 'POST':
        data = parse_json_body(request)
        path = data.get('path', '').strip('/')
        read_users = data.get('read', ['*'])
        write_users = data.get('write', ['*'])
        delete_users = data.get('delete', ['admin'])
        
        if not path:
            return jsonify({'error': '경로가 필요합니다.'}), 400
        
        with permissions_lock:
            FOLDER_PERMISSIONS[path] = {
                'read': read_users,
                'write': write_users,
                'delete': delete_users
            }
        save_permissions()
        
        logger.add(f"폴더 권한 설정: {path}")
        return jsonify({'success': True})


@admin_bp.route('/api/permissions/<path:path>', methods=['GET', 'PUT', 'DELETE'])
@login_required('admin')
def manage_folder_permission(path):
    """특정 폴더 권한 관리"""
    path = path.strip('/')
    
    if request.method == 'GET':
        with permissions_lock:
            perm = FOLDER_PERMISSIONS.get(path, {})
        return jsonify({'path': path, 'permission': perm})
    
    elif request.method == 'PUT':
        data = parse_json_body(request)
        with permissions_lock:
            if path not in FOLDER_PERMISSIONS:
                FOLDER_PERMISSIONS[path] = {}
            FOLDER_PERMISSIONS[path].update(data)
        save_permissions()
        logger.add(f"폴더 권한 수정: {path}")
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        with permissions_lock:
            if path in FOLDER_PERMISSIONS:
                del FOLDER_PERMISSIONS[path]
                save_permissions()
                logger.add(f"폴더 권한 삭제: {path}")
                return jsonify({'success': True})
        return jsonify({'success': False, 'error': '권한을 찾을 수 없습니다.'})


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


@admin_bp.route('/api/cleanup_trash', methods=['POST'])
@login_required('admin')
def cleanup_trash():
    """휴지통 수동 정리"""
    from features.trash import auto_cleanup_trash
    deleted = auto_cleanup_trash()
    return jsonify({'success': True, 'deleted': deleted})


# ==========================================
# 감사 로그
# ==========================================

@admin_bp.route('/api/audit_log', methods=['GET'])
@login_required('admin')
def get_audit_log():
    """감사 로그 조회 (필터링/페이징 지원)"""
    limit = request.args.get('limit', type=int)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')
    
    with audit_lock:
        filtered = AUDIT_LOG.copy()
    
    if action_filter:
        filtered = [e for e in filtered if e.get('action') == action_filter]
    if user_filter:
        filtered = [e for e in filtered if e.get('user') == user_filter]
    if date_from:
        filtered = [e for e in filtered if e.get('timestamp', '') >= date_from]
    if date_to:
        filtered = [e for e in filtered if e.get('timestamp', '') <= date_to]
    
    filtered.reverse()

    # 하위호환: /api/audit_log?limit=N
    if limit is not None and limit > 0:
        return jsonify({'logs': filtered[:limit]})
    
    total = len(filtered)
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        'logs': filtered[start:end],
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })


@admin_bp.route('/api/audit_log/export', methods=['GET'])
@login_required('admin')
def export_audit_log():
    """감사 로그 CSV 내보내기"""
    with audit_lock:
        logs = AUDIT_LOG.copy()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'User', 'IP', 'Action', 'Target', 'Details', 'Result'])
    
    for log in logs:
        writer.writerow([
            log.get('timestamp', ''),
            log.get('user', ''),
            log.get('ip', ''),
            log.get('action', ''),
            log.get('target', ''),
            log.get('details', ''),
            log.get('result', '')
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'audit_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@admin_bp.route('/api/audit_log/clear', methods=['POST'])
@login_required('admin')
def clear_audit_log():
    """감사 로그 정리"""
    global AUDIT_LOG
    data = parse_json_body(request)
    days = data.get('days', 30)
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    
    with audit_lock:
        before_count = len(AUDIT_LOG)
        AUDIT_LOG[:] = [e for e in AUDIT_LOG if e.get('timestamp', '') >= cutoff]
        after_count = len(AUDIT_LOG)
    
    save_audit_log()
    return jsonify({
        'success': True,
        'deleted': before_count - after_count,
        'remaining': after_count
    })


# ==========================================
# 접속 대시보드
# ==========================================

@admin_bp.route('/api/access_dashboard')
@login_required('admin')
def access_dashboard():
    """접속 대시보드 데이터"""
    hourly_stats = {}
    action_stats = {}
    ip_stats = {}
    
    with access_log_lock:
        logs = list(ACCESS_LOG)
    
    for log in logs:
        try:
            log_time = datetime.fromisoformat(log['time'])
            hour = log_time.strftime('%H:00')
            hourly_stats[hour] = hourly_stats.get(hour, 0) + 1
            
            action = log.get('action', 'unknown')
            action_stats[action] = action_stats.get(action, 0) + 1
            
            ip = log.get('ip', 'unknown')
            ip_stats[ip] = ip_stats.get(ip, 0) + 1
        except:
            continue
    
    recent_logs = logs[:10]
    blocked = get_blocked_ips()
    
    return jsonify({
        'hourly_stats': hourly_stats,
        'action_stats': action_stats,
        'ip_stats': ip_stats,
        'recent_logs': recent_logs,
        'blocked_ips': blocked,
        'total_logs': len(logs)
    })


# ==========================================
# 시스템 리소스 모니터링 (v7.2.3)
# ==========================================

@admin_bp.route('/api/system_stats')
@login_required('admin')
def system_stats():
    """시스템 리소스 모니터링 (관리자 전용)"""
    try:
        import psutil
        
        # CPU 정보
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count()
        
        # 메모리 정보
        mem = psutil.virtual_memory()
        memory_info = {
            'total': mem.total,
            'available': mem.available,
            'used': mem.used,
            'percent': mem.percent,
            'total_gb': round(mem.total / (1024**3), 2),
            'used_gb': round(mem.used / (1024**3), 2)
        }
        
        # 디스크 정보 (공유 폴더)
        folder = conf.get('folder', '.')
        try:
            disk = psutil.disk_usage(folder)
            disk_info = {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent,
                'total_gb': round(disk.total / (1024**3), 2),
                'used_gb': round(disk.used / (1024**3), 2),
                'free_gb': round(disk.free / (1024**3), 2)
            }
        except Exception:
            disk_info = {'error': '디스크 정보 없음'}
        
        # 네트워크 정보
        try:
            net = psutil.net_io_counters()
            network_info = {
                'bytes_sent': net.bytes_sent,
                'bytes_recv': net.bytes_recv,
                'packets_sent': net.packets_sent,
                'packets_recv': net.packets_recv
            }
        except Exception:
            network_info = {}
        
        # 부팅 시간
        import time
        boot_time = datetime.fromtimestamp(psutil.boot_time()).isoformat()
        uptime_seconds = int(time.time() - psutil.boot_time())
        uptime_str = f"{uptime_seconds // 86400}일 {(uptime_seconds % 86400) // 3600}시간"
        
        return jsonify({
            'success': True,
            'cpu': {
                'percent': cpu_percent,
                'count': cpu_count
            },
            'memory': memory_info,
            'disk': disk_info,
            'network': network_info,
            'boot_time': boot_time,
            'uptime': uptime_str,
            'timestamp': datetime.now().isoformat()
        })
        
    except ImportError:
        return jsonify({
            'success': False,
            'error': 'psutil 라이브러리가 설치되지 않았습니다. pip install psutil'
        }), 500
    except Exception as e:
        logger.add(f"시스템 통계 오류: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)}), 500

