"""Persistent runtime state for rate limits and brute-force guards."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from config import (
    DOWNLOAD_TRACKER,
    LOGIN_ATTEMPTS,
    conf,
    download_tracker_lock,
    login_attempts_lock,
)
from utils.app_paths import atomic_write_json
from utils.log_manager import logger


DOWNLOAD_TRACKER_FILE = ".webshare_download_tracker.json"
LOGIN_ATTEMPTS_FILE = ".webshare_login_attempts.json"
SHARE_PASSWORD_ATTEMPTS_FILE = ".webshare_share_password_attempts.json"

_download_tracker_dirty = False
_login_attempts_dirty = False


def _runtime_path(file_name: str) -> str:
    return os.path.join(conf.get("folder"), file_name)


def _serialize_datetime(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _parse_datetime(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return value


def mark_download_tracker_dirty():
    global _download_tracker_dirty
    _download_tracker_dirty = True


def mark_login_attempts_dirty():
    global _login_attempts_dirty
    _login_attempts_dirty = True


def save_download_tracker(force: bool = True) -> bool:
    global _download_tracker_dirty
    if not force and not _download_tracker_dirty:
        return False
    with download_tracker_lock:
        payload = {
            str(key): {
                "count": int(value.get("count", 0) or 0),
                "bytes": int(value.get("bytes", 0) or 0),
                "date": str(value.get("date", "") or ""),
            }
            for key, value in DOWNLOAD_TRACKER.items()
            if isinstance(value, dict)
        }
    try:
        atomic_write_json(_runtime_path(DOWNLOAD_TRACKER_FILE), payload)
        _download_tracker_dirty = False
        return True
    except Exception as exc:
        logger.add(f"download tracker save failed: {exc}", "ERROR")
        return False


def load_download_tracker():
    path = _runtime_path(DOWNLOAD_TRACKER_FILE)
    if not os.path.exists(path):
        return
    try:
        import json

        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return
        loaded = {}
        for key, value in payload.items():
            if not isinstance(value, dict):
                continue
            loaded[str(key)] = {
                "count": max(0, int(value.get("count", 0) or 0)),
                "bytes": max(0, int(value.get("bytes", 0) or 0)),
                "date": str(value.get("date", "") or ""),
            }
        with download_tracker_lock:
            DOWNLOAD_TRACKER.clear()
            DOWNLOAD_TRACKER.update(loaded)
    except Exception as exc:
        logger.add(f"download tracker load failed: {exc}", "ERROR")


def save_login_attempts(force: bool = True) -> bool:
    global _login_attempts_dirty
    if not force and not _login_attempts_dirty:
        return False
    with login_attempts_lock:
        payload = {
            str(ip): {
                key: _serialize_datetime(value)
                for key, value in info.items()
                if key in {"attempts", "last_attempt", "blocked_until"}
            }
            for ip, info in LOGIN_ATTEMPTS.items()
            if isinstance(info, dict)
        }
    try:
        atomic_write_json(_runtime_path(LOGIN_ATTEMPTS_FILE), payload)
        _login_attempts_dirty = False
        return True
    except Exception as exc:
        logger.add(f"login attempts save failed: {exc}", "ERROR")
        return False


def load_login_attempts():
    path = _runtime_path(LOGIN_ATTEMPTS_FILE)
    if not os.path.exists(path):
        return
    try:
        import json

        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return
        loaded = {}
        for ip, info in payload.items():
            if not isinstance(info, dict):
                continue
            loaded[str(ip)] = {
                "attempts": max(0, int(info.get("attempts", 0) or 0)),
            }
            for key in ("last_attempt", "blocked_until"):
                if key in info:
                    loaded[str(ip)][key] = _parse_datetime(info.get(key))
        with login_attempts_lock:
            LOGIN_ATTEMPTS.clear()
            LOGIN_ATTEMPTS.update(loaded)
    except Exception as exc:
        logger.add(f"login attempts load failed: {exc}", "ERROR")


def flush_runtime_state_if_dirty(force: bool = False):
    save_login_attempts(force=force)
    save_download_tracker(force=force)


def save_share_password_attempts(attempts: dict[tuple[str, str], dict[str, Any]]) -> bool:
    payload = {}
    for key, info in attempts.items():
        if not isinstance(key, tuple) or len(key) != 2 or not isinstance(info, dict):
            continue
        ip, token = key
        payload[f"{ip}\n{token}"] = {
            "attempts": int(info.get("attempts", 0) or 0),
            "last_attempt": _serialize_datetime(info.get("last_attempt")),
            "blocked_until": _serialize_datetime(info.get("blocked_until")),
        }
    try:
        atomic_write_json(_runtime_path(SHARE_PASSWORD_ATTEMPTS_FILE), payload)
        return True
    except Exception as exc:
        logger.add(f"share password attempts save failed: {exc}", "ERROR")
        return False


def load_share_password_attempts() -> dict[tuple[str, str], dict[str, Any]]:
    path = _runtime_path(SHARE_PASSWORD_ATTEMPTS_FILE)
    if not os.path.exists(path):
        return {}
    try:
        import json

        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return {}
        loaded = {}
        for key, info in payload.items():
            if "\n" not in str(key) or not isinstance(info, dict):
                continue
            ip, token = str(key).split("\n", 1)
            loaded[(ip, token)] = {
                "attempts": max(0, int(info.get("attempts", 0) or 0)),
            }
            for field in ("last_attempt", "blocked_until"):
                if info.get(field):
                    loaded[(ip, token)][field] = _parse_datetime(info.get(field))
        return loaded
    except Exception as exc:
        logger.add(f"share password attempts load failed: {exc}", "ERROR")
        return {}
