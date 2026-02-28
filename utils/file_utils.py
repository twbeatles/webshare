"""
WebShare Pro - File Utilities
"""

from __future__ import annotations

import os
import re
import threading
import time
import unicodedata
from pathlib import Path

from flask import request


# Folder size cache (TTL)
_folder_size_cache = {}
_folder_size_cache_lock = threading.Lock()
FOLDER_SIZE_CACHE_TTL = 60


def _extract_client_ip_from_xff(xff: str, trusted_hops: int) -> str:
    parts = [p.strip() for p in (xff or "").split(",") if p.strip()]
    if not parts:
        return ""
    hops = max(1, int(trusted_hops or 1))
    # Right-most entries are proxies; pick client IP before trusted hops.
    index = len(parts) - hops - 1
    if index < 0:
        index = 0
    return parts[index]


def get_real_ip() -> str:
    """Return the best-effort real client IP address."""
    remote_ip = request.remote_addr or ""
    try:
        from config import conf

        trusted_proxies = conf.get("trusted_proxies", []) or []
        trusted_hops = conf.get("trusted_hops", 1)
        is_trusted_proxy = remote_ip in trusted_proxies
    except Exception:
        trusted_hops = 1
        is_trusted_proxy = False

    if is_trusted_proxy:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            candidate = _extract_client_ip_from_xff(xff, trusted_hops)
            if candidate:
                return candidate
        x_real_ip = request.headers.get("X-Real-IP")
        if x_real_ip:
            return x_real_ip

    return remote_ip


def safe_filename(filename: str) -> str:
    """Return a filename sanitized for cross-platform use while preserving Unicode."""
    if not filename:
        return "unnamed"

    windows_reserved_names = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }

    filename = unicodedata.normalize("NFC", filename)

    filename = filename.replace("/", "_").replace("\\", "_")
    filename = filename.replace(":", "_").replace("*", "_")
    filename = filename.replace("?", "_").replace('"', "_")
    filename = filename.replace("<", "_").replace(">", "_")
    filename = filename.replace("|", "_")

    filename = re.sub(r"_+", "_", filename)
    filename = filename.strip().strip("_")
    filename = filename.rstrip(". ")

    if filename.startswith("."):
        filename = f"_{filename}"

    if not filename:
        return "unnamed"

    name, ext = os.path.splitext(filename)
    if name.upper() in windows_reserved_names:
        filename = f"_{name}{ext}"

    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[: 200 - len(ext)] + ext

    return filename


def validate_path(base_dir: str, path: str) -> tuple[bool, str, str]:
    """
    Validate a user path to ensure the resolved target stays under base_dir.

    Returns:
        (is_valid, full_path, error_msg)
    """
    try:
        base_dir_real = os.path.realpath(os.path.normpath(base_dir))
    except Exception:
        return False, "", "접근 권한이 없습니다"

    if not path:
        return True, base_dir_real, ""

    try:
        target_real = str((Path(base_dir_real) / str(path)).resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False, "", "접근 권한이 없습니다"

    try:
        common = os.path.commonpath([base_dir_real, target_real])
    except ValueError:
        # e.g. Windows drive mismatch
        return False, "", "접근 권한이 없습니다"

    if common != base_dir_real:
        return False, "", "접근 권한이 없습니다"

    return True, target_real, ""


def fmt_bytes(size_bytes: int) -> str:
    """Return a human-readable byte string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / 1024 / 1024:.1f} MB"
    return f"{size_bytes / 1024 / 1024 / 1024:.2f} GB"


def get_folder_size(folder_path: str, use_cache: bool = True) -> int:
    """Compute folder size in bytes with optional TTL cache."""
    now = time.time()
    cache_key = os.path.normpath(folder_path)

    if use_cache:
        with _folder_size_cache_lock:
            cached = _folder_size_cache.get(cache_key)
            if cached:
                cached_size, cached_time = cached
                if now - cached_time < FOLDER_SIZE_CACHE_TTL:
                    return cached_size

    total = 0
    try:
        for dirpath, _, filenames in os.walk(folder_path):
            for file_name in filenames:
                file_path = os.path.join(dirpath, file_name)
                try:
                    total += os.path.getsize(file_path)
                except OSError:
                    pass
    except Exception:
        pass

    with _folder_size_cache_lock:
        _folder_size_cache[cache_key] = (total, now)
        if len(_folder_size_cache) > 100:
            oldest_key = min(_folder_size_cache, key=lambda key: _folder_size_cache[key][1])
            del _folder_size_cache[oldest_key]

    return total


def invalidate_folder_size_cache(folder_path: str | None = None):
    """Invalidate folder size cache for one path (or all paths when None)."""
    with _folder_size_cache_lock:
        if folder_path is None:
            _folder_size_cache.clear()
            return

        cache_key = os.path.normpath(folder_path)
        keys_to_delete = [key for key in _folder_size_cache if key.startswith(cache_key)]
        for key in keys_to_delete:
            del _folder_size_cache[key]


def get_file_type(ext: str) -> str:
    """Map file extension to a logical type."""
    from config import (
        ARCHIVE_EXTENSIONS,
        AUDIO_EXTENSIONS,
        IMAGE_EXTENSIONS,
        TEXT_EXTENSIONS,
        VIDEO_EXTENSIONS,
    )

    ext = (ext or "").lower()
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in VIDEO_EXTENSIONS:
        return "video"
    if ext in AUDIO_EXTENSIONS:
        return "audio"
    if ext in TEXT_EXTENSIONS:
        return "text"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive"
    return "file"
