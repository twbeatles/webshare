"""
WebShare Pro - Cloud Routes
Cloud sync API (mock scaffold).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from config import CLOUD_SYNC_CONFIG, cloud_sync_lock
from features.audit_log import log_audit
from features.cloud_sync import save_cloud_config
from security.auth import login_required
from utils.file_utils import get_real_ip
from utils.request_policy import parse_json_body

cloud_bp = Blueprint('cloud', __name__)

_MOCK_NOTICE = "Cloud Sync provider integration is not implemented yet. Running in mock mode."


def _provider_mock_state(provider: str, cfg: dict) -> dict:
    return {
        'mode': 'mock',
        'enabled': cfg.get('enabled', False),
        'configured': bool(cfg.get('token')),
        'connected': bool(cfg.get('token')),
        'folder_id': cfg.get('folder_id', ''),
        'last_sync': cfg.get('last_sync', None),
        'state': 'idle',
        'progress': 0,
        'error': None,
        'provider': provider,
    }


@cloud_bp.route('/api/cloud/config', methods=['GET', 'POST'])
@login_required('admin')
def cloud_config():
    """Cloud sync config (mock mode)."""
    if request.method == 'GET':
        safe_config = {}
        for provider, cfg in CLOUD_SYNC_CONFIG.items():
            safe_config[provider] = {
                'mode': 'mock',
                'enabled': cfg.get('enabled', False),
                'configured': bool(cfg.get('token')),
                'folder_id': cfg.get('folder_id', ''),
            }
        return jsonify({'mode': 'mock', 'config': safe_config, 'message': _MOCK_NOTICE})

    data = parse_json_body(request)
    provider = data.get('provider')

    if provider not in CLOUD_SYNC_CONFIG:
        return jsonify({'error': '지원하지 않는 클라우드 서비스입니다.'}), 400

    with cloud_sync_lock:
        CLOUD_SYNC_CONFIG[provider].update(
            {
                'enabled': data.get('enabled', False),
                'client_id': data.get('client_id', ''),
                'client_secret': data.get('client_secret', ''),
                'app_key': data.get('app_key', ''),
                'app_secret': data.get('app_secret', ''),
                'folder_id': data.get('folder_id', ''),
            }
        )

    save_cloud_config()
    return jsonify({'success': True, 'mode': 'mock', 'message': _MOCK_NOTICE})


@cloud_bp.route('/api/cloud/status', methods=['GET'])
@login_required('admin')
def cloud_status():
    """Cloud sync status (mock mode)."""
    status = {}
    for provider, cfg in CLOUD_SYNC_CONFIG.items():
        status[provider] = _provider_mock_state(provider, cfg)

    return jsonify({'mode': 'mock', 'status': status, 'message': _MOCK_NOTICE})


@cloud_bp.route('/api/cloud/sync/<provider>', methods=['POST'])
@login_required('admin')
def cloud_sync(provider):
    """Accept a mock cloud sync job."""
    if provider not in CLOUD_SYNC_CONFIG:
        return jsonify({'error': '지원하지 않는 클라우드 서비스입니다.'}), 400

    data = parse_json_body(request)
    sync_path = data.get('path', '')
    direction = data.get('direction', 'upload')

    job_id = f"mock-{provider}-{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    log_audit(
        session.get('role', 'admin'),
        'cloud_sync',
        f"{provider}:{sync_path}",
        f"direction={direction}, mode=mock, job_id={job_id}",
        ip=get_real_ip(),
    )

    return (
        jsonify(
            {
                'success': True,
                'mode': 'mock',
                'job_id': job_id,
                'state': 'accepted',
                'progress': 0,
                'error': None,
                'provider': provider,
                'path': sync_path,
                'direction': direction,
                'message': _MOCK_NOTICE,
                'accepted_at': now_iso,
            }
        ),
        202,
    )
