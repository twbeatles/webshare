"""Thumbnail, playlist, gallery, and document-preview endpoints."""

import os
import io
from markupsafe import escape
from flask import jsonify, send_file, abort
from config import conf, cache_lock
from utils.api_errors import api_exception
from utils.log_manager import logger
from utils.file_utils import validate_path
from utils.request_policy import ensure_path_access
from security.auth import login_required
# 썸네일 캐시
from webshare_app.services.media_service import MAX_DOCUMENT_PREVIEW_SIZE, MAX_THUMBNAIL_CACHE, THUMBNAIL_CACHE
from ._common import media_bp




# ==========================================
# 이미지 썸네일
# ==========================================

@media_bp.route('/thumbnail/<path:filepath>')
@login_required()
def get_thumbnail(filepath):
    """이미지 썸네일 생성 (LRU 캐시)"""
    try:
        from PIL import Image
    except ImportError:
        return abort(500)

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, _ = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.exists(full_path):
        return abort(404)

    if os.path.splitext(full_path)[1].lower() == '.svg':
        response = send_file(full_path, mimetype='image/svg+xml')
        response.headers['Content-Security-Policy'] = "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    cache_key = f"{filepath}_{os.path.getmtime(full_path)}"

    # 캐시 확인
    with cache_lock:
        if cache_key in THUMBNAIL_CACHE:
            return send_file(io.BytesIO(THUMBNAIL_CACHE[cache_key]), mimetype='image/jpeg')

    try:
        img = Image.open(full_path)
        img.thumbnail((150, 150), Image.Resampling.LANCZOS)
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=70)
        buffer.seek(0)

        # 캐시 저장
        with cache_lock:
            if len(THUMBNAIL_CACHE) >= MAX_THUMBNAIL_CACHE:
                THUMBNAIL_CACHE.popitem(last=False)
            THUMBNAIL_CACHE[cache_key] = buffer.getvalue()

        buffer.seek(0)
        return send_file(buffer, mimetype='image/jpeg')
    except Exception as e:
        logger.add(f"썸네일 생성 실패: {e}", "ERROR")
        return abort(500)




# ==========================================
# 동영상 썸네일
# ==========================================

@media_bp.route('/video_thumbnail/<path:filepath>')
@login_required()
def video_thumbnail(filepath):
    """동영상 썸네일 반환"""
    from features.metadata import generate_video_thumbnail

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, _ = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.isfile(full_path):
        return abort(404)

    thumb_path = generate_video_thumbnail(full_path)
    if thumb_path and os.path.exists(thumb_path):
        return send_file(thumb_path, mimetype='image/jpeg')

    return abort(404)




# ==========================================
# 오디오 플레이리스트
# ==========================================

@media_bp.route('/playlist/<path:folder_path>')
@login_required()
def get_playlist(folder_path):
    """폴더 내 오디오 파일 플레이리스트"""
    ok, message, status_code = ensure_path_access(folder_path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), folder_path)
    if not is_valid or not os.path.isdir(full_path):
        return jsonify({'error': '폴더를 찾을 수 없습니다.'}), 404

    audio_extensions = {'.mp3', '.wav', '.ogg', '.m4a', '.flac', '.aac', '.wma'}
    tracks = []

    for name in sorted(os.listdir(full_path)):
        ext = os.path.splitext(name)[1].lower()
        if ext in audio_extensions:
            rel_path = os.path.join(folder_path, name).replace('\\', '/')
            ok, _, _ = ensure_path_access(rel_path, 'read')
            if not ok:
                continue
            tracks.append({
                'name': name,
                'path': rel_path,
                'stream_url': f'/stream/{rel_path}'
            })

    return jsonify({'folder': folder_path, 'tracks': tracks, 'count': len(tracks)})




# ==========================================
# 이미지 갤러리
# ==========================================

@media_bp.route('/gallery/<path:folder_path>')
@login_required()
def get_gallery(folder_path):
    """폴더 내 이미지 갤러리"""
    ok, message, status_code = ensure_path_access(folder_path, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), folder_path)
    if not is_valid or not os.path.isdir(full_path):
        return jsonify({'error': '폴더를 찾을 수 없습니다.'}), 404

    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'}
    images = []

    for name in sorted(os.listdir(full_path)):
        ext = os.path.splitext(name)[1].lower()
        if ext in image_extensions:
            rel_path = os.path.join(folder_path, name).replace('\\', '/')
            ok, _, _ = ensure_path_access(rel_path, 'read')
            if not ok:
                continue
            images.append({
                'name': name,
                'path': rel_path,
                'url': f'/download/{rel_path}',
                'thumbnail': f'/thumbnail/{rel_path}'
            })

    return jsonify({'folder': folder_path, 'images': images, 'count': len(images)})




# ==========================================
# 문서 미리보기
# ==========================================

@media_bp.route('/preview/<path:filepath>')
@login_required()
def document_preview(filepath):
    """문서 미리보기 (Word, Excel, PowerPoint, CSV, JSON)"""
    import json as json_module

    ok, message, status_code = ensure_path_access(filepath, 'read')
    if not ok:
        return jsonify({'error': message}), status_code

    is_valid, full_path, error = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.isfile(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다.'}), 404

    ext = os.path.splitext(full_path)[1].lower()
    file_size = os.path.getsize(full_path)
    if file_size > MAX_DOCUMENT_PREVIEW_SIZE:
        return jsonify({
            'success': False,
            'error': f'미리보기 파일 크기가 너무 큽니다. 최대 {MAX_DOCUMENT_PREVIEW_SIZE // (1024 * 1024)}MB까지 지원합니다.',
            'max_bytes': MAX_DOCUMENT_PREVIEW_SIZE,
            'file_size': file_size,
        }), 413
    content = ""
    preview_type = "text"

    try:
        # Word (.docx)
        if ext == '.docx':
            try:
                from docx import Document
                doc = Document(full_path)
                paragraphs = []
                for para in doc.paragraphs[:100]:
                    if para.text.strip():
                        paragraphs.append(f"<p>{escape(para.text)}</p>")
                content = "\n".join(paragraphs) if paragraphs else "<p>문서가 비어있습니다.</p>"
                preview_type = "html"
            except ImportError:
                content = "python-docx 라이브러리가 필요합니다. pip install python-docx"

        # Excel (.xlsx)
        elif ext in ['.xlsx', '.xls']:
            try:
                from openpyxl import load_workbook
                wb = load_workbook(full_path, read_only=True, data_only=True)
                sheet = wb.active
                rows = []
                if sheet is not None:
                    for i, row in enumerate(sheet.iter_rows(max_row=50, values_only=True)):
                        if i >= 50:
                            break
                        cells = "".join([f"<td>{escape(str(cell)) if cell is not None else ''}</td>" for cell in row[:20]])
                        rows.append(f"<tr>{cells}</tr>")
                content = f"<table border='1' style='border-collapse:collapse; width:100%;'>{''.join(rows)}</table>"
                preview_type = "html"
                wb.close()
            except ImportError:
                content = "openpyxl 라이브러리가 필요합니다. pip install openpyxl"

        # PowerPoint (.pptx)
        elif ext == '.pptx':
            try:
                from pptx import Presentation  # type: ignore[reportMissingImports]
                prs = Presentation(full_path)
                slides_content = []
                for i, slide in enumerate(list(prs.slides)[:20]):
                    slide_text = []
                    for shape in slide.shapes:
                        shape_text = getattr(shape, "text", "")
                        if isinstance(shape_text, str) and shape_text.strip():
                            slide_text.append(shape_text)
                    if slide_text:
                        escaped_text = '<br>'.join([str(escape(t)) for t in slide_text])
                        slides_content.append(f"<div style='border:1px solid #ccc; padding:15px; margin:10px 0; border-radius:8px;'><strong>슬라이드 {i+1}</strong><br>{escaped_text}</div>")
                content = "".join(slides_content) if slides_content else "<p>프레젠테이션이 비어있습니다.</p>"
                preview_type = "html"
            except ImportError:
                content = "python-pptx 라이브러리가 필요합니다. pip install python-pptx"

        # CSV
        elif ext == '.csv':
            import csv
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                rows = []
                for i, row in enumerate(reader):
                    if i >= 100: break
                    cells = "".join([f"<td>{escape(cell)}</td>" for cell in row[:20]])
                    rows.append(f"<tr>{cells}</tr>")
                content = f"<table border='1' style='border-collapse:collapse; width:100%;'>{''.join(rows)}</table>"
                preview_type = "html"

        # JSON
        elif ext == '.json':
            with open(full_path, 'r', encoding='utf-8') as f:
                data = json_module.load(f)
                safe_json = escape(json_module.dumps(data, ensure_ascii=False, indent=2)[:10000])
                content = f"<pre>{safe_json}</pre>"
                preview_type = "html"

        else:
            content = "지원하지 않는 파일 형식입니다."

        return jsonify({
            'success': True,
            'content': content,
            'type': preview_type,
            'filename': os.path.basename(full_path),
            'safe_html': preview_type == 'html',
        })

    except Exception as exc:
        return api_exception('문서 미리보기 오류', exc, extra={'success': False})

