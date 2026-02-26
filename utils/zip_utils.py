"""
WebShare Pro - ZIP Utilities
디스크 기반 ZIP 생성/스트리밍 공통 유틸리티
"""

from __future__ import annotations

import os
import tempfile
import zipfile
from typing import Iterable, Iterator, Tuple
from urllib.parse import quote

from flask import Response

from .file_utils import safe_filename


# 이미 압축되어 있거나 재압축 효율이 낮은 확장자
NO_COMPRESS_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tgz",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv",
    ".mp3", ".aac", ".ogg", ".flac", ".m4a", ".wav",
    ".pdf", ".docx", ".xlsx", ".pptx",
}


def _compress_type_for(path: str) -> int:
    ext = os.path.splitext(path)[1].lower()
    if ext in NO_COMPRESS_EXTENSIONS:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


def _iter_files(root_dir: str) -> Iterable[Tuple[str, str]]:
    """
    root_dir를 순회하며 (abs_path, rel_path) 반환.
    """
    for root, dirs, files in os.walk(root_dir):
        dirs.sort()
        files.sort()
        for file_name in files:
            abs_path = os.path.join(root, file_name)
            rel_path = os.path.relpath(abs_path, root_dir).replace("\\", "/")
            yield abs_path, rel_path


def create_temp_zip_from_folder(folder_path: str, include_root: bool = False) -> str:
    """
    폴더를 임시 ZIP 파일로 생성 후 경로 반환.
    """
    fd, temp_path = tempfile.mkstemp(prefix=".webshare_zip_", suffix=".zip")
    os.close(fd)
    root_name = os.path.basename(os.path.normpath(folder_path))

    try:
        with zipfile.ZipFile(
            temp_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            allowZip64=True,
        ) as zf:
            for abs_path, rel_path in _iter_files(folder_path):
                arcname = rel_path
                if include_root:
                    arcname = os.path.join(root_name, rel_path).replace("\\", "/")
                zf.write(abs_path, arcname=arcname, compress_type=_compress_type_for(abs_path))
        return temp_path
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def create_temp_zip_from_items(items: Iterable[Tuple[str, str]]) -> str:
    """
    지정 파일/폴더들을 ZIP으로 묶어 임시 파일 경로 반환.
    items: (abs_path, arcname_root)
    """
    fd, temp_path = tempfile.mkstemp(prefix=".webshare_zip_", suffix=".zip")
    os.close(fd)

    try:
        with zipfile.ZipFile(
            temp_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            allowZip64=True,
        ) as zf:
            for abs_path, arc_root in items:
                if os.path.isfile(abs_path):
                    arcname = arc_root.replace("\\", "/")
                    zf.write(abs_path, arcname=arcname, compress_type=_compress_type_for(abs_path))
                    continue

                if os.path.isdir(abs_path):
                    for child_abs, child_rel in _iter_files(abs_path):
                        arcname = os.path.join(arc_root, child_rel).replace("\\", "/")
                        zf.write(child_abs, arcname=arcname, compress_type=_compress_type_for(child_abs))
        return temp_path
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def iter_file_chunks(path: str, chunk_size: int = 256 * 1024) -> Iterator[bytes]:
    """
    파일을 청크 단위로 읽고 종료 시 임시 파일 삭제.
    """
    try:
        with open(path, "rb") as handle:
            while True:
                data = handle.read(chunk_size)
                if not data:
                    break
                yield data
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def make_zip_stream_response(temp_zip_path: str, download_name: str) -> Response:
    """
    임시 ZIP 파일을 스트리밍 응답으로 반환.
    """
    fallback_name = safe_filename(download_name) or "download.zip"
    if not fallback_name.lower().endswith(".zip"):
        fallback_name += ".zip"
    encoded_name = quote(download_name if download_name.lower().endswith(".zip") else f"{download_name}.zip")

    headers = {
        "Content-Type": "application/zip",
        "Content-Disposition": f"attachment; filename=\"{fallback_name}\"; filename*=UTF-8''{encoded_name}",
    }
    return Response(iter_file_chunks(temp_zip_path), headers=headers, direct_passthrough=True)
