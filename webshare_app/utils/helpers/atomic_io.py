"""Atomic file-write helpers."""

from __future__ import annotations
import os
import shutil
import tempfile




def atomic_write_bytes(path: str, payload: bytes):
    """Write bytes atomically in the destination directory."""
    directory = os.path.dirname(path) or "."
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_write_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise




def atomic_save_upload(file_storage, path: str):
    """Save a Werkzeug FileStorage object through a same-directory temp file."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_upload_", suffix=".tmp")
    try:
        try:
            file_storage.stream.seek(0, os.SEEK_SET)
        except Exception:
            pass
        with os.fdopen(fd, "wb") as handle:
            shutil.copyfileobj(file_storage.stream, handle, length=1024 * 1024)
        os.replace(temp_path, path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise




def atomic_copy_file(src: str, dst: str):
    """Copy a file to a temp file in the destination directory, then replace."""
    directory = os.path.dirname(dst) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_copy_", suffix=".tmp")
    os.close(fd)
    try:
        shutil.copy2(src, temp_path)
        os.replace(temp_path, dst)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

