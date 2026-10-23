"""Atomic file-write helpers."""

from __future__ import annotations
import os
import shutil
import tempfile
import time

_MAX_COMMIT_NAMES = 10000


def commit_no_replace(temp_path: str, path: str) -> str:
    """Move temp_path to path without ever replacing an existing entry.

    The final name (path, then stem_1.ext, stem_2.ext, ...) is claimed with an
    O_EXCL placeholder at commit time and temp_path is replaced over that
    placeholder, so concurrent commits of the same name cannot overwrite each
    other (audit ISSUE-002). Returns the committed path.
    """
    directory = os.path.dirname(path) or "."
    stem, ext = os.path.splitext(os.path.basename(path))
    for counter in range(_MAX_COMMIT_NAMES):
        candidate = path if counter == 0 else os.path.join(directory, f"{stem}_{counter}{ext}")
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            continue
        except PermissionError:
            # Windows reports an existing directory (or a name held open for
            # deletion) as access denied: treat it as taken.
            if os.path.lexists(candidate):
                continue
            raise
        os.close(fd)
        try:
            _replace_with_retry(temp_path, candidate)
        except Exception:
            try:
                os.remove(candidate)
            except OSError:
                pass
            raise
        return candidate
    raise FileExistsError(f"no available file name for {path}")


def _replace_with_retry(src: str, dst: str):
    """os.replace with a short retry: on Windows a scanner/indexer may hold
    the fresh placeholder open for a moment (WinError 5)."""
    for attempt in range(5):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.02 * (attempt + 1))



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




def atomic_save_upload(file_storage, path: str) -> str:
    """Save a Werkzeug FileStorage object through a same-directory temp file.

    Commits under path or the next free name_N variant (never replacing an
    existing file) and returns the committed path.
    """
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
        return commit_no_replace(temp_path, path)
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

