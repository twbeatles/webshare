"""
WebShare Pro - Folder permissions.
"""

from __future__ import annotations

import json
import os
from typing import Any

from config import FOLDER_PERMISSIONS, PERMISSIONS_FILE, conf, permissions_lock
from utils.file_utils import validate_path
from utils.log_manager import logger
from webshare_app.core.persistence import persist_json_snapshot

PERMISSIONS_PERSIST_KEY = "folder_permissions"

VALID_PERMISSION_ACTIONS = {"read", "write", "delete"}
VALID_PERMISSION_PRINCIPALS = {"admin", "guest", "*"}
DEFAULT_PERMISSION = {"read": ["*"], "write": ["*"], "delete": ["admin"]}


def _is_protected_permission_path(path: str) -> bool:
    for segment in path.split("/"):
        if not segment:
            continue
        lower = segment.lower()
        if segment.startswith(".") or lower.startswith(".webshare"):
            return True
    return False


def normalize_permission_path(path: str | None) -> str:
    value = str(path or "").replace("\\", "/").strip("/")
    parts: list[str] = []
    for part in value.split("/"):
        part = part.strip()
        if not part or part == ".":
            continue
        if part == "..":
            raise ValueError("invalid permission path")
        parts.append(part)

    normalized = "/".join(parts)
    if not normalized or _is_protected_permission_path(normalized):
        raise ValueError("invalid permission path")

    valid, _full_path, _error = validate_path(conf.get("folder"), normalized)
    if not valid:
        raise ValueError("invalid permission path")
    return normalized


def normalize_permission_users(users: Any) -> list[str]:
    if not isinstance(users, list):
        raise ValueError("invalid permission users")
    normalized: list[str] = []
    for user in users:
        value = str(user or "").strip()
        if value not in VALID_PERMISSION_PRINCIPALS:
            raise ValueError("invalid permission user")
        if value not in normalized:
            normalized.append(value)
    return normalized


def normalize_permission_entry(path: str | None, data: dict[str, Any]) -> tuple[str, dict[str, list[str]]]:
    if not isinstance(data, dict):
        raise ValueError("invalid permission entry")

    normalized_path = normalize_permission_path(path)
    entry: dict[str, list[str]] = {}
    for action, users in data.items():
        if action not in VALID_PERMISSION_ACTIONS:
            raise ValueError("invalid permission action")
        entry[action] = normalize_permission_users(users)
    if not entry:
        raise ValueError("empty permission entry")
    return normalized_path, entry


def check_permission(path: str, user: str, action: str) -> bool:
    """Check inherited read/write/delete permissions. Admin is always allowed."""
    if user == "admin":
        return True
    if action not in VALID_PERMISSION_ACTIONS:
        return False

    normalized = str(path or "").replace("\\", "/").strip("/")
    with permissions_lock:
        current_path = ""
        for part in normalized.split("/"):
            if not part:
                continue
            current_path = f"{current_path}/{part}" if current_path else part
            perm = FOLDER_PERMISSIONS.get(current_path)
            if not isinstance(perm, dict) or action not in perm:
                continue

            action_users = perm.get(action, [])
            if not isinstance(action_users, list):
                return False
            if "*" in action_users or user in action_users:
                continue
            return False

    return True


def _validated_permissions_snapshot() -> dict[str, dict[str, list[str]]]:
    snapshot: dict[str, dict[str, list[str]]] = {}
    for path, entry in FOLDER_PERMISSIONS.items():
        try:
            normalized_path, normalized_entry = normalize_permission_entry(path, entry)
        except ValueError:
            logger.add(f"Invalid permission skipped during save: {path}", "WARN")
            continue
        snapshot[normalized_path] = normalized_entry
    return snapshot


def save_permissions():
    """Persist folder permissions atomically."""
    base_dir = conf.get("folder")
    perm_path = os.path.join(base_dir, PERMISSIONS_FILE)
    try:
        persist_json_snapshot(
            PERMISSIONS_PERSIST_KEY,
            perm_path,
            permissions_lock,
            _validated_permissions_snapshot,
        )
    except Exception as exc:
        logger.add(f"permission save failed: {exc}", "ERROR")


def load_permissions():
    """Load folder permissions, skipping invalid legacy entries."""
    base_dir = conf.get("folder")
    perm_path = os.path.join(base_dir, PERMISSIONS_FILE)
    if not os.path.exists(perm_path):
        return

    try:
        with open(perm_path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except Exception as exc:
        logger.add(f"permission load failed: {exc}", "ERROR")
        return

    normalized: dict[str, dict[str, list[str]]] = {}
    if isinstance(loaded, dict):
        for path, entry in loaded.items():
            try:
                normalized_path, normalized_entry = normalize_permission_entry(path, entry)
            except ValueError:
                logger.add(f"Invalid permission skipped: {path}", "WARN")
                continue
            normalized[normalized_path] = normalized_entry

    with permissions_lock:
        FOLDER_PERMISSIONS.clear()
        FOLDER_PERMISSIONS.update(normalized)
    logger.add(f"folder permissions loaded: {len(normalized)}")


def set_folder_permission(path: str, action: str, users: list):
    """Set a validated folder permission."""
    normalized_path = normalize_permission_path(path)
    if action not in VALID_PERMISSION_ACTIONS:
        raise ValueError("invalid permission action")
    normalized_users = normalize_permission_users(users)

    with permissions_lock:
        current = dict(DEFAULT_PERMISSION)
        current.update(FOLDER_PERMISSIONS.get(normalized_path, {}))
        current[action] = normalized_users
        FOLDER_PERMISSIONS[normalized_path] = current
    save_permissions()


def delete_folder_permission(path: str) -> bool:
    """Delete a validated folder permission."""
    try:
        normalized_path = normalize_permission_path(path)
    except ValueError:
        return False

    with permissions_lock:
        if normalized_path not in FOLDER_PERMISSIONS:
            return False
        del FOLDER_PERMISSIONS[normalized_path]
    save_permissions()
    logger.add(f"folder permission deleted: {normalized_path}")
    return True
