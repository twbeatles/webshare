"""
WebShare Pro - API Error Utilities
공통 API 에러 응답 스키마/요청 ID 유틸리티
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

from flask import g, jsonify

from utils.log_manager import logger


DEFAULT_ERROR_BY_STATUS = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "UNPROCESSABLE_ENTITY",
    429: "TOO_MANY_REQUESTS",
    500: "INTERNAL_ERROR",
    502: "BAD_GATEWAY",
    503: "SERVICE_UNAVAILABLE",
    504: "GATEWAY_TIMEOUT",
    507: "INSUFFICIENT_STORAGE",
}

PUBLIC_ERROR_MESSAGE_5XX_STATUSES = {507}


def api_request_id() -> str:
    """Return a per-request id, creating one when needed."""
    rid = getattr(g, "request_id", None)
    if not rid:
        rid = uuid.uuid4().hex[:16]
        g.request_id = rid
    return rid


def api_error_payload(
    code: str | None,
    message: str,
    status: int,
    error: str | None = None,
    request_id: str | None = None,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    resolved_code = code or DEFAULT_ERROR_BY_STATUS.get(int(status), "ERROR")
    resolved_message = str(message or "")
    payload: Dict[str, Any] = {
        "success": False,
        "error": str(error or resolved_message),
        "code": resolved_code,
        "message": resolved_message,
        "request_id": request_id or api_request_id(),
    }
    if extra:
        payload.update(extra)
    return payload


def api_error(
    code: str | None,
    message: str,
    status: int,
    error: str | None = None,
    request_id: str | None = None,
    extra: Dict[str, Any] | None = None,
):
    """Build a standardized JSON error response."""
    payload = api_error_payload(
        code=code,
        message=message,
        status=status,
        error=error,
        request_id=request_id,
        extra=extra,
    )
    return jsonify(payload), int(status)


def normalize_error_response_payload(payload: Dict[str, Any], status_code: int) -> Dict[str, Any]:
    """
    Ensure an error-like JSON payload follows the common schema.
    Keeps existing keys for backward compatibility.
    """
    if not isinstance(payload, dict):
        return payload

    should_normalize = int(status_code) >= 400 or payload.get("success") is False or "error" in payload
    if not should_normalize:
        return payload

    normalized = dict(payload)
    message = str(
        normalized.get("message")
        or normalized.get("error")
        or DEFAULT_ERROR_BY_STATUS.get(int(status_code), "Error")
    )
    if int(status_code) >= 500 and int(status_code) not in PUBLIC_ERROR_MESSAGE_5XX_STATUSES:
        # Do not expose internal exception details by default.
        message = "서버 내부 오류가 발생했습니다."
    normalized.setdefault("success", False)
    if int(status_code) >= 500 and int(status_code) not in PUBLIC_ERROR_MESSAGE_5XX_STATUSES:
        normalized["error"] = message
    else:
        normalized.setdefault("error", message)
    normalized.setdefault("code", DEFAULT_ERROR_BY_STATUS.get(int(status_code), "ERROR"))
    normalized["message"] = message
    normalized.setdefault("request_id", api_request_id())
    return normalized


def api_exception(
    context: str,
    exc: Exception,
    *,
    message: str = "서버 내부 오류가 발생했습니다.",
    status: int = 500,
    code: str | None = None,
    level: str = "ERROR",
    extra: Dict[str, Any] | None = None,
):
    """Log an internal exception and return a standardized JSON error response."""
    logger.add(f"{context}: {exc}", level)
    return api_error(code, message, int(status), extra=extra)
