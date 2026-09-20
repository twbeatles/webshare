"""File download endpoints (single, zip, batch)."""

import os
import json
from flask import request, send_file, jsonify, session
from config import conf, STATS, stats_lock
from utils.api_errors import api_exception
from utils.log_manager import logger, log_access
from utils.file_utils import validate_path, safe_filename, fmt_bytes, get_real_ip, get_file_type
from utils.zip_utils import make_zip_stream_response
from utils.request_policy import ensure_path_access, is_protected_system_path
from security.auth import login_required
from features.audit_log import log_audit
from utils.helpers import add_recent_file, build_download_tracker_key
from webshare_app.services.file_service import _collect_allowed_zip_files, _estimate_zip_transfer_bytes, _recent_owner_key
from ._common import file_bp




@file_bp.route('/download/<path:filepath>')
@login_required()
def download(filepath):
    """파일 다운로드"""
    from utils.helpers import reserve_download_quota, rollback_download_quota

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    # 경로 검증
    valid, full_path, error = validate_path(base_dir, filepath)
    if not valid:
        return jsonify({'error': error}), 400

    if not os.path.exists(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다'}), 404

    if os.path.isdir(full_path):
        return jsonify({'error': '폴더는 다운로드할 수 없습니다'}), 400

    try:
        file_size = os.path.getsize(full_path)
        client_ip = get_real_ip()
        tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
        allowed, limit_msg, quota_reservation = reserve_download_quota(tracker_key, True, projected_bytes=file_size)
        if not allowed:
            return jsonify({'error': limit_msg}), 429

        # 감사 로그
        log_audit(
            session.get('role', 'guest'),
            'download',
            filepath,
            f"Size: {fmt_bytes(file_size)}",
            ip=client_ip
        )

        log_access(client_ip, 'download', filepath)
        logger.add(f"다운로드: {filepath}")
        add_recent_file(
            filepath,
            os.path.basename(full_path),
            get_file_type(os.path.splitext(full_path)[1]),
            owner_key=_recent_owner_key(),
        )
        try:
            return send_file(full_path, as_attachment=True)
        except Exception:
            rollback_download_quota(quota_reservation)
            raise

    except Exception as exc:
        return api_exception('다운로드 오류', exc)




# ==========================================
# ZIP 다운로드
# ==========================================

@file_bp.route('/zip/<path:path>')
@login_required()
def download_zip(path):
    """폴더를 ZIP으로 다운로드"""
    from utils.helpers import check_download_limit, reserve_download_quota, rollback_download_quota

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, target_dir, error = validate_path(base_dir, path)
    if not is_valid:
        logger.add(f"ZIP 다운로드 경로 검증 실패: {path}", "WARN")
        return jsonify({'error': error}), 403

    if not os.path.isdir(target_dir):
        return jsonify({'error': '폴더가 아닙니다'}), 404

    try:
        role = session.get('role', 'guest')
        client_ip = get_real_ip()
        tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
        zip_items = _collect_allowed_zip_files(
            base_dir=base_dir,
            root_abs=target_dir,
            root_rel=path,
            role=role,
            arc_prefix="",
        )
        estimated_size = _estimate_zip_transfer_bytes(zip_items)
        allowed, limit_msg = check_download_limit(tracker_key, True, projected_bytes=estimated_size)
        if not allowed:
            return jsonify({'error': limit_msg}), 429

        if not zip_items:
            return jsonify({'error': '다운로드 가능한 항목이 없습니다'}), 403

        # Resolve through the package namespace (not the module global) so
        # monkeypatching `routes.file_routes.create_temp_zip_from_items`
        # keeps guarding zip creation after this split.
        from webshare_app.routes import file_routes as _file_routes_pkg

        temp_path = _file_routes_pkg.create_temp_zip_from_items(zip_items)
        zip_size = os.path.getsize(temp_path)
        allowed, limit_msg, quota_reservation = reserve_download_quota(tracker_key, True, projected_bytes=zip_size)
        if not allowed:
            try:
                os.remove(temp_path)
            except Exception:
                pass
            return jsonify({'error': limit_msg}), 429
        with stats_lock:
            STATS['bytes_sent'] += zip_size

        download_name = f"{os.path.basename(target_dir)}.zip"
        try:
            return make_zip_stream_response(temp_path, download_name)
        except Exception:
            rollback_download_quota(quota_reservation)
            raise
    except Exception as exc:
        return api_exception('ZIP 생성 오류', exc)




# ==========================================
# 배치 다운로드
# ==========================================

@file_bp.route('/batch_download/<path:path>', methods=['POST'])
@login_required()
def batch_download(path):
    """여러 파일 일괄 ZIP 다운로드"""
    from utils.helpers import check_download_limit, reserve_download_quota, rollback_download_quota

    base_dir = conf.get('folder')

    ok, message, status_code = ensure_path_access(path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, current_dir, error = validate_path(base_dir, path)
    if not is_valid:
        return jsonify({'error': error}), 403

    try:
        try:
            data = json.loads(request.form.get('files', '[]'))
        except Exception:
            return jsonify({'error': '잘못된 요청입니다'}), 400

        client_ip = get_real_ip()
        tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
        zip_items = []
        role = session.get('role', 'guest')
        for item_name in data:
            safe_item_name = safe_filename(item_name)
            item_rel = os.path.join(path, safe_item_name).replace('\\', '/')
            ok, _, _ = ensure_path_access(item_rel, 'read')
            if not ok:
                continue
            if is_protected_system_path(item_rel):
                continue
            is_valid_item, item_path, _ = validate_path(base_dir, item_rel)
            if not is_valid_item:
                continue

            if os.path.isfile(item_path):
                zip_items.append((item_path, safe_item_name))
                continue

            if os.path.isdir(item_path):
                zip_items.extend(
                    _collect_allowed_zip_files(
                        base_dir=base_dir,
                        root_abs=item_path,
                        root_rel=item_rel,
                        role=role,
                        arc_prefix=safe_item_name,
                    )
                )

        if not zip_items:
            return jsonify({'error': '다운로드 가능한 항목이 없습니다'}), 403

        estimated_size = _estimate_zip_transfer_bytes(zip_items)
        allowed, limit_msg = check_download_limit(tracker_key, True, projected_bytes=estimated_size)
        if not allowed:
            return jsonify({'error': limit_msg}), 429

        # Resolve through the package namespace (not the module global) so
        # monkeypatching `routes.file_routes.create_temp_zip_from_items`
        # keeps guarding zip creation after this split.
        from webshare_app.routes import file_routes as _file_routes_pkg

        temp_path = _file_routes_pkg.create_temp_zip_from_items(zip_items)
        zip_size = os.path.getsize(temp_path)
        allowed, limit_msg, quota_reservation = reserve_download_quota(tracker_key, True, projected_bytes=zip_size)
        if not allowed:
            try:
                os.remove(temp_path)
            except Exception:
                pass
            return jsonify({'error': limit_msg}), 429
        with stats_lock:
            STATS['bytes_sent'] += zip_size

        # 감사 로그 기록
        log_audit(
            user=session.get('role', 'unknown'),
            action='batch_download',
            target=path,
            details=f"{len(data)}개 항목",
            ip=client_ip
        )

        try:
            return make_zip_stream_response(temp_path, "batch_download.zip")
        except Exception:
            rollback_download_quota(quota_reservation)
            raise
    except Exception as exc:
        return api_exception('배치 다운로드 오류', exc)

