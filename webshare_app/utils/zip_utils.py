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


# ZIP creation guards against temp-disk exhaustion and transfer blowups.
# Callers translate ZipLimitExceeded into a 413 response.
MAX_ZIP_ITEMS = 5000
MAX_ZIP_TOTAL_BYTES = 10 * 1024 * 1024 * 1024


class ZipLimitExceeded(ValueError):
    """A ZIP item-count or total-size limit was exceeded."""


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


def _new_zip_guard_state() -> dict:
    return {"items": 0, "total_bytes": 0}


def _guarded_zip_write(zf, abs_path: str, arcname: str, state: dict) -> None:
    """Write one file into zf, enforcing MAX_ZIP_ITEMS / MAX_ZIP_TOTAL_BYTES."""
    try:
        size = os.path.getsize(abs_path)
    except OSError:
        size = 0
    state["items"] += 1
    state["total_bytes"] += size
    if state["items"] > MAX_ZIP_ITEMS:
        raise ZipLimitExceeded(f"ZIP 항목 수 상한 초과 (최대 {MAX_ZIP_ITEMS}개)")
    if state["total_bytes"] > MAX_ZIP_TOTAL_BYTES:
        raise ZipLimitExceeded("ZIP 합산 크기 상한 초과 (최대 10GB)")
    zf.write(abs_path, arcname=arcname, compress_type=_compress_type_for(abs_path))


def create_temp_zip_from_folder(folder_path: str, include_root: bool = False) -> str:
    """
    폴더를 임시 ZIP 파일로 생성 후 경로 반환.
    """
    fd, temp_path = tempfile.mkstemp(prefix=".webshare_zip_", suffix=".zip")
    os.close(fd)
    _guard_state = _new_zip_guard_state()
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
                _guarded_zip_write(zf, abs_path, arcname, _guard_state)
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
    _guard_state = _new_zip_guard_state()

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
                    _guarded_zip_write(zf, abs_path, arcname, _guard_state)
                    continue

                if os.path.isdir(abs_path):
                    for child_abs, child_rel in _iter_files(abs_path):
                        arcname = os.path.join(arc_root, child_rel).replace("\\", "/")
                        _guarded_zip_write(zf, child_abs, arcname, _guard_state)
        return temp_path
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def iter_file_chunks(
    path: str, chunk_size: int = 256 * 1024, on_chunk=None, on_finish=None
) -> Iterator[bytes]:
    """
    파일을 청크 단위로 읽고 종료 시 임시 파일 삭제.
    on_chunk가 주어지면 yield한 바이트 수를 전달하고, 스트림이 닫히면
    (완료·중단 모두) on_finish에 총 전송 바이트 수를 전달한다.
    """
    sent = 0
    try:
        with open(path, "rb") as handle:
            while True:
                data = handle.read(chunk_size)
                if not data:
                    break
                sent += len(data)
                if on_chunk is not None:
                    on_chunk(len(data))
                yield data
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        if on_finish is not None:
            try:
                on_finish(sent)
            except Exception:
                pass


def make_zip_stream_response(
    temp_zip_path: str, download_name: str, on_chunk=None, on_finish=None, on_close=None
) -> Response:
    """
    임시 ZIP 파일을 스트리밍 응답으로 반환.
    on_chunk는 전송 바이트 계측 콜백, on_finish/on_close는 스트림 종료
    콜백이다(종료 시점의 총 전송 바이트는 on_finish가 받는다).
    """
    fallback_name = safe_filename(download_name) or "download.zip"
    if not fallback_name.lower().endswith(".zip"):
        fallback_name += ".zip"
    encoded_name = quote(download_name if download_name.lower().endswith(".zip") else f"{download_name}.zip")

    headers = {
        "Content-Type": "application/zip",
        "Content-Disposition": f"attachment; filename=\"{fallback_name}\"; filename*=UTF-8''{encoded_name}",
    }
    response = Response(
        iter_file_chunks(temp_zip_path, on_chunk=on_chunk, on_finish=on_finish),
        headers=headers,
        direct_passthrough=True,
    )
    if on_close is not None:
        response.call_on_close(on_close)
    return response


def make_settled_zip_stream_response(temp_zip_path: str, download_name: str, reservation: dict) -> Response:
    """Stream a finished temp zip and settle a quota reservation on close.

    Bytes actually yielded are counted in the streaming generator itself
    (direct_passthrough responses never run call_on_close, so the hook
    lives in the generator finally, which the WSGI server triggers by
    closing the iterable). When the stream closes, the reservation is
    settled down to the delivered count, so an aborted download refunds
    the unsent remainder instead of holding the full projected size. A
    fully delivered download settles to a no-op. Settlement runs at most
    once even if both the generator and the response close fire.
    """
    state = {"done": False}

    def _settle_once(actual):
        if state["done"]:
            return
        state["done"] = True
        try:
            from webshare_app.utils.helpers.download_quota import settle_download_quota

            settle_download_quota(reservation, actual)
        except Exception:
            pass

    return make_zip_stream_response(
        temp_zip_path,
        download_name,
        on_finish=_settle_once,
        on_close=lambda: _settle_once(None),
    )
