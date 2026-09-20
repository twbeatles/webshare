"""Media streaming endpoints (range streaming, HLS)."""

import os
import re
import mimetypes
from flask import jsonify, request, send_file, abort, session
from config import conf
from utils.log_manager import logger
from utils.file_utils import validate_path, get_real_ip, get_file_type
from utils.request_policy import ensure_path_access
from security.auth import login_required
from utils.helpers import add_recent_file, build_download_tracker_key
from webshare_app.services.media_service import _recent_owner_key
from ._common import media_bp



# ==========================================

@media_bp.route('/stream/<path:filepath>')
@login_required()
def stream_media(filepath):
    """HTTP Range 요청을 지원하는 미디어 스트리밍"""
    from flask import current_app
    from utils.helpers import reserve_download_quota

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.isfile(full_path):
        return abort(404)

    file_size = os.path.getsize(full_path)
    mime_type, _ = mimetypes.guess_type(full_path)
    if not mime_type:
        mime_type = 'application/octet-stream'

    client_ip = get_real_ip()
    tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
    range_header = request.headers.get('Range')

    if range_header:
        # Range 요청 파싱
        byte_start = 0
        byte_end = file_size - 1

        match = re.match(r'bytes=(\d+)-(\d*)', range_header)
        if match:
            byte_start = int(match.group(1))
            if match.group(2):
                byte_end = int(match.group(2))

        byte_end = min(byte_end, file_size - 1)
        content_length = byte_end - byte_start + 1
        if content_length <= 0:
            return abort(416)
        allowed, limit_msg, _quota_reservation = reserve_download_quota(tracker_key, False, projected_bytes=content_length)
        if not allowed:
            return jsonify({'error': limit_msg}), 429
        if byte_start == 0:
            add_recent_file(
                filepath,
                os.path.basename(full_path),
                get_file_type(os.path.splitext(full_path)[1]),
                owner_key=_recent_owner_key(),
            )

        def generate():
            with open(full_path, 'rb') as f:
                f.seek(byte_start)
                remaining = content_length
                chunk_size = 1024 * 1024  # 1MB chunks
                while remaining > 0:
                    read_size = min(chunk_size, remaining)
                    data = f.read(read_size)
                    if not data:
                        break
                    remaining -= len(data)
                    yield data

        response = current_app.response_class(
            generate(),
            status=206,
            mimetype=mime_type,
            direct_passthrough=True
        )
        response.headers['Content-Range'] = f'bytes {byte_start}-{byte_end}/{file_size}'
        response.headers['Content-Length'] = content_length
        response.headers['Accept-Ranges'] = 'bytes'
        return response
    else:
        allowed, limit_msg, _quota_reservation = reserve_download_quota(tracker_key, False, projected_bytes=file_size)
        if not allowed:
            return jsonify({'error': limit_msg}), 429
        add_recent_file(
            filepath,
            os.path.basename(full_path),
            get_file_type(os.path.splitext(full_path)[1]),
            owner_key=_recent_owner_key(),
        )
        # 전체 파일 스트리밍
        def generate_full():
            with open(full_path, 'rb') as f:
                while True:
                    data = f.read(1024 * 1024)
                    if not data:
                        break
                    yield data

        response = current_app.response_class(
            generate_full(),
            mimetype=mime_type,
            direct_passthrough=True
        )
        response.headers['Content-Length'] = file_size
        response.headers['Accept-Ranges'] = 'bytes'
        return response




# ==========================================
# HLS 트랜스코딩 스트리밍 (v7.2.3)
# ==========================================

@media_bp.route('/stream/hls/<path:filepath>/index.m3u8')
@login_required()
def stream_hls_playlist(filepath):
    """HLS 플레이리스트 반환 (트랜스코딩 시작)"""
    from features.transcoder import get_transcoder
    from utils.helpers import reserve_download_quota

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.exists(full_path):
        return abort(404)

    try:
        client_ip = get_real_ip()
        tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
        transcoder = get_transcoder(full_path)

        # 파일이 생성될 때까지 잠시 대기
        for _ in range(20):
            if os.path.exists(transcoder.playlist_path):
                playlist_size = os.path.getsize(transcoder.playlist_path)
                allowed, limit_msg, _quota_reservation = reserve_download_quota(tracker_key, False, projected_bytes=playlist_size)
                if not allowed:
                    return jsonify({'error': limit_msg}), 429
                add_recent_file(
                    filepath,
                    os.path.basename(full_path),
                    get_file_type(os.path.splitext(full_path)[1]),
                    owner_key=_recent_owner_key(),
                )
                return send_file(transcoder.playlist_path, mimetype='application/vnd.apple.mpegurl')
            import time
            time.sleep(0.5)

        return abort(503, description="Transcoding timeout")
    except Exception as exc:
        logger.add(f"트랜스코딩 오류: {exc}", "ERROR")
        return abort(500)



@media_bp.route('/stream/hls/<path:filepath>/<segment>')
@login_required()
def stream_hls_segment(filepath, segment):
    """HLS 세그먼트 반환"""
    from features.transcoder import get_transcoder
    from utils.helpers import reserve_download_quota

    # 세그먼트 파일명 검증
    if not re.match(r'segment_\d+\.ts', segment):
        return abort(404)

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, _ = validate_path(conf.get('folder'), filepath)
    if not is_valid:
        return abort(404)

    try:
        # 세션 찾기 (이미 생성되어 있어야 함)
        transcoder = get_transcoder(full_path)
        seg_path = os.path.join(transcoder.output_dir, segment)

        if os.path.exists(seg_path):
            file_size = os.path.getsize(seg_path)

            # 대역폭 제한 확인
            client_ip = get_real_ip()
            tracker_key = build_download_tracker_key(session.get('session_id', ''), client_ip)
            allowed, limit_msg, _quota_reservation = reserve_download_quota(tracker_key, False, projected_bytes=file_size)
            if not allowed:
                 # HLS는 429를 받으면 재생이 멈출 수 있음.
                 # 하지만 정책상 차단해야 함.
                 return jsonify({'error': limit_msg}), 429

            return send_file(seg_path, mimetype='video/MP2T')

        return abort(404)
    except Exception:
        return abort(404)

