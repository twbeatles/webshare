"""
WebShare Pro - Request Policy Utilities
요청 정책/경로 보호/권한 검사 공통 유틸리티
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from flask import Request, session

from config import conf
from security.permissions import check_permission


STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
WEBDAV_WRITE_METHODS = {"PUT", "POST", "DELETE", "MKCOL", "MOVE", "COPY", "PROPPATCH", "LOCK", "UNLOCK"}
WEBDAV_DELETE_METHODS = {"DELETE"}


def parse_json_body(req: Request) -> Dict[str, Any]:
    """JSON 본문 파싱 (None 안전)"""
    data = req.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def normalize_relative_path(path: str | None) -> str:
    if not path:
        return ""
    value = str(path).replace("\\", "/").strip("/")
    parts = [part for part in value.split("/") if part and part != "."]
    return "/".join(parts)


def get_parent_relative_path(path: str | None) -> str:
    normalized = normalize_relative_path(path)
    if not normalized or "/" not in normalized:
        return ""
    return normalized.rsplit("/", 1)[0]


def role_can_mutate(role: str | None = None) -> bool:
    current_role = role or session.get("role", "guest")
    if current_role == "admin":
        return True
    return bool(conf.get("allow_guest_upload", False))


def ensure_mutation_allowed(role: str | None = None) -> Tuple[bool, str, int]:
    if role_can_mutate(role):
        return True, "", 200
    return False, "업로드/변경 권한이 없습니다", 403


def build_path_capabilities(path: str | None, role: str | None = None, *, is_dir: bool = False, item_type: str = "") -> Dict[str, bool]:
    normalized = normalize_relative_path(path)
    current_role = role or session.get("role", "guest")
    parent_path = get_parent_relative_path(normalized)
    mutation_allowed = role_can_mutate(current_role)

    read_allowed = (not is_protected_system_path(normalized)) and check_permission(normalized, current_role, "read")
    write_allowed = mutation_allowed and (not is_protected_system_path(normalized)) and check_permission(normalized, current_role, "write")
    delete_allowed = mutation_allowed and (not is_protected_system_path(normalized)) and check_permission(normalized, current_role, "delete")
    parent_write_allowed = mutation_allowed and (not is_protected_system_path(parent_path)) and check_permission(parent_path, current_role, "write")

    return {
        "read": bool(read_allowed),
        "write": bool(write_allowed),
        "delete": bool(delete_allowed),
        "rename": bool(delete_allowed and parent_write_allowed),
        "move": bool(delete_allowed),
        "copy": bool(mutation_allowed and read_allowed),
        "upload": bool(write_allowed if is_dir else parent_write_allowed),
        "mkdir": bool(write_allowed if is_dir else parent_write_allowed),
        "edit": bool(write_allowed and not is_dir),
        "trash": bool(delete_allowed),
        "unzip": bool(
            mutation_allowed
            and not is_dir
            and item_type == "archive"
            and read_allowed
            and parent_write_allowed
        ),
    }


def is_protected_system_path(path: str | None) -> bool:
    """
    시스템 경로(.webshare*, 숨김 세그먼트) 접근 여부
    """
    normalized = normalize_relative_path(path)
    if not normalized:
        return False

    for segment in normalized.split("/"):
        lower = segment.lower()
        if segment.startswith(".") or lower.startswith(".webshare"):
            return True
    return False


def ensure_path_access(path: str | None, action: str, role: str | None = None) -> Tuple[bool, str, int]:
    """
    경로 보호 + 권한 검사
    Returns: (ok, message, status_code)
    """
    normalized = normalize_relative_path(path)
    if is_protected_system_path(normalized):
        return False, "시스템 경로 접근이 차단되었습니다", 403

    current_role = role or session.get("role", "guest")
    if not check_permission(normalized, current_role, action):
        return False, "권한이 없습니다", 403

    return True, "", 200
