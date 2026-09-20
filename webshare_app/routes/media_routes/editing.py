"""Text content read/write endpoints."""

import os
from flask import jsonify, request, session
from config import conf
from utils.api_errors import api_exception
from utils.log_manager import logger
from utils.file_utils import validate_path, get_real_ip, get_file_type
from utils.request_policy import ensure_mutation_allowed, ensure_path_access, parse_json_body
from security.auth import login_required
from features.audit_log import log_audit
from utils.helpers import add_recent_file
from webshare_app.services.media_service import MAX_TEXT_EDIT_SIZE, _recent_owner_key
from ._common import media_bp




# ==========================================
# 텍스트 파일 읽기/쓰기
# ==========================================

@media_bp.route('/get_content/<path:path>')
@login_required()
def get_content(path):
    """텍스트 파일 내용 읽기"""
    ok, message, status_code = ensure_path_access(path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid:
        return jsonify({'error': error}), 403
    if not os.path.isfile(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다.'}), 404

    file_size = os.path.getsize(full_path)
    if file_size > MAX_TEXT_EDIT_SIZE:
        return jsonify({
            'error': f'파일 크기가 너무 큽니다. 최대 {MAX_TEXT_EDIT_SIZE // (1024 * 1024)}MB까지 편집할 수 있습니다.',
            'max_bytes': MAX_TEXT_EDIT_SIZE,
            'file_size': file_size,
        }), 413

    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        add_recent_file(
            path,
            os.path.basename(full_path),
            get_file_type(os.path.splitext(full_path)[1]),
            owner_key=_recent_owner_key(),
        )
        return jsonify({'content': content})
    except Exception as exc:
        return api_exception('파일 읽기 오류', exc)




@media_bp.route('/save_content/<path:path>', methods=['POST'])
@login_required()
def save_content(path):
    """텍스트 파일 저장"""
    from utils.helpers import create_file_version

    role = session.get('role', 'guest')
    allowed, message, status_code = ensure_mutation_allowed(role)
    if not allowed:
        return jsonify({'success': False, 'error': message}), status_code

    ok, message, status_code = ensure_path_access(path, 'write', role=role)
    if not ok:
        return jsonify({'success': False, 'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid:
        return jsonify({'success': False, 'error': error}), 403

    try:
        data = parse_json_body(request)
        content = data.get('content', '')
        if not isinstance(content, str):
            content = str(content)
        content_bytes = len(content.encode('utf-8'))
        if content_bytes > MAX_TEXT_EDIT_SIZE:
            return jsonify({
                'success': False,
                'error': f'저장할 내용이 너무 큽니다. 최대 {MAX_TEXT_EDIT_SIZE // (1024 * 1024)}MB까지 저장할 수 있습니다.',
                'max_bytes': MAX_TEXT_EDIT_SIZE,
                'content_size': content_bytes,
            }), 413

        # 수정 전 버전 백업
        create_file_version(full_path)

        # Resolve through the package namespace (not the module global) so
        # monkeypatching `routes.media_routes.atomic_write_bytes` keeps
        # simulating atomic-replace failures after this split.
        from webshare_app.routes import media_routes as _media_routes_pkg

        _media_routes_pkg.atomic_write_bytes(full_path, content.encode('utf-8'))
        logger.add(f"파일수정: {path}")

        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='file_edit',
            target=path,
            details=f"크기: {content_bytes} 바이트",
            ip=get_real_ip()
        )

        return jsonify({'success': True})
    except Exception as exc:
        return api_exception('파일 저장 오류', exc, extra={'success': False})

