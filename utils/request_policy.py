"""
WebShare Pro - Request Policy Utilities
요청 정책/경로 보호/권한 검사 공통 유틸리티
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from flask import Request, session

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

