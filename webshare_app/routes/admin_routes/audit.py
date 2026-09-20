"""Audit-log endpoints."""

import io
import csv
from datetime import datetime, timedelta
from flask import jsonify, request, send_file
from config import AUDIT_LOG, audit_lock
from security.auth import login_required
from features.audit_log import save_audit_log
from utils.request_policy import parse_json_body
from ._common import admin_bp




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

