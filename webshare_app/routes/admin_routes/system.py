"""Dashboard and system-statistics endpoints."""

from datetime import datetime
from flask import jsonify
from config import conf, ACCESS_LOG, access_log_lock
from utils.api_errors import api_exception
from security.auth import login_required
from security.ip_blocker import get_blocked_ips
from ._common import admin_bp




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
    except Exception as exc:
        return api_exception("시스템 통계 오류", exc, extra={'success': False})

