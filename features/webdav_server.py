"""
WebShare Pro - WebDAV Server (v7.2.3)
WsgiDAV를 이용한 WebDAV 기능 제공
"""

import importlib
import os
import threading
from datetime import datetime, timedelta
from urllib.parse import unquote, urlparse

from config import conf
from security.permissions import check_permission
from utils.log_manager import logger
from utils.request_policy import (
    WEBDAV_DELETE_METHODS,
    WEBDAV_WRITE_METHODS,
    is_protected_system_path,
    normalize_relative_path,
)


_WEBDAV_AUTH_MAX_ATTEMPTS = 8
_WEBDAV_AUTH_BLOCK_MINUTES = 10
_webdav_auth_lock = threading.Lock()
_webdav_auth_attempts = {}


def _extract_client_ip_from_xff(xff: str, trusted_hops: int) -> str:
    parts = [p.strip() for p in (xff or "").split(",") if p.strip()]
    if not parts:
        return ""
    hops = max(1, int(trusted_hops or 1))
    index = len(parts) - hops - 1
    if index < 0:
        index = 0
    return parts[index]


def get_webdav_real_ip(environ) -> str:
    """WSGI environ에서 실제 클라이언트 IP 추출"""
    remote_ip = environ.get("REMOTE_ADDR", "") or ""
    trusted_proxies = conf.get("trusted_proxies", []) or []
    trusted_hops = conf.get("trusted_hops", 1)

    if remote_ip in trusted_proxies:
        xff = environ.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            candidate = _extract_client_ip_from_xff(xff, trusted_hops)
            if candidate:
                return candidate
        x_real = environ.get("HTTP_X_REAL_IP", "")
        if x_real:
            return x_real
    return remote_ip


def is_secure_webdav_request(environ) -> bool:
    """TLS 여부 판별 (직접 TLS 또는 신뢰 프록시 헤더)"""
    scheme = (environ.get("wsgi.url_scheme", "") or "").lower()
    if scheme == "https":
        return True

    https_flag = str(environ.get("HTTPS", "")).lower()
    if https_flag in {"on", "1", "true"}:
        return True

    remote_ip = environ.get("REMOTE_ADDR", "") or ""
    trusted_proxies = conf.get("trusted_proxies", []) or []
    if remote_ip in trusted_proxies:
        xfp = (environ.get("HTTP_X_FORWARDED_PROTO", "") or "").lower()
        if xfp.startswith("https"):
            return True

    return False


def _record_auth_attempt(ip: str, success: bool):
    with _webdav_auth_lock:
        if success:
            _webdav_auth_attempts.pop(ip, None)
            return

        item = _webdav_auth_attempts.setdefault(ip, {"attempts": 0, "blocked_until": None})
        item["attempts"] += 1
        if item["attempts"] >= _WEBDAV_AUTH_MAX_ATTEMPTS:
            item["blocked_until"] = datetime.now() + timedelta(minutes=_WEBDAV_AUTH_BLOCK_MINUTES)
            logger.add(f"WebDAV 인증 시도 차단: {ip}", "WARN")


def _is_auth_blocked(ip: str) -> tuple[bool, int]:
    with _webdav_auth_lock:
        item = _webdav_auth_attempts.get(ip)
        if not item:
            return False, 0
        blocked_until = item.get("blocked_until")
        if not blocked_until:
            return False, 0
        if datetime.now() >= blocked_until:
            _webdav_auth_attempts.pop(ip, None)
            return False, 0
        remain = int((blocked_until - datetime.now()).total_seconds() / 60) + 1
        return True, max(remain, 1)


def _method_to_action(method: str) -> str:
    if method in WEBDAV_DELETE_METHODS:
        return "delete"
    if method in WEBDAV_WRITE_METHODS:
        return "write"
    return "read"


def _normalize_webdav_path(path: str | None) -> str:
    raw = unquote(path or "")
    return normalize_relative_path(raw)


def _normalize_destination_path(destination: str | None) -> str:
    if not destination:
        return ""
    raw = destination
    if "://" in raw:
        raw = urlparse(raw).path
    raw = unquote(raw)
    if raw.startswith("/webdav/"):
        raw = raw[len("/webdav/"):]
    elif raw == "/webdav":
        raw = ""
    return normalize_relative_path(raw)


def _is_allowed_webdav_path(path: str, role: str, action: str) -> bool:
    if is_protected_system_path(path):
        return False
    return check_permission(path, role, action)


class WebDAVPolicyMiddleware:
    """WebDAV 요청 공통 정책 미들웨어"""

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _forbidden(start_response, message: str):
        payload = message.encode("utf-8")
        start_response(
            "403 Forbidden",
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(payload))),
            ],
        )
        return [payload]

    def __call__(self, environ, start_response):
        method = (environ.get("REQUEST_METHOD", "GET") or "GET").upper()
        rel_path = _normalize_webdav_path(environ.get("PATH_INFO", ""))
        username = environ.get("REMOTE_USER", "") or ""
        if not username:
            # 인증 전 단계에서는 Authorization 헤더의 username을 보조적으로 사용
            auth = environ.get("HTTP_AUTHORIZATION", "")
            if auth.lower().startswith("basic "):
                import base64

                try:
                    decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", errors="ignore")
                    username = decoded.split(":", 1)[0]
                except Exception:
                    username = ""

        role = "admin" if username == "admin" else "guest"
        action = _method_to_action(method)

        if is_protected_system_path(rel_path):
            return self._forbidden(start_response, "Protected path")

        if action in {"write", "delete"} and not is_secure_webdav_request(environ):
            if not conf.get("webdav_allow_insecure", False):
                logger.add(f"WebDAV 비TLS 쓰기 차단: {method} {rel_path}", "WARN")
                return self._forbidden(start_response, "HTTPS required for write operations")

        if role == "guest" and action in {"write", "delete"} and not conf.get("allow_guest_upload"):
            return self._forbidden(start_response, "Guest write access denied")

        if not _is_allowed_webdav_path(rel_path, role, action):
            return self._forbidden(start_response, "Permission denied")

        # COPY/MOVE destination 추가 검증
        if method in {"COPY", "MOVE"}:
            dst_path = _normalize_destination_path(environ.get("HTTP_DESTINATION", ""))
            if dst_path:
                if is_protected_system_path(dst_path):
                    return self._forbidden(start_response, "Protected destination path")
                if not check_permission(dst_path, role, "write"):
                    return self._forbidden(start_response, "Destination permission denied")
                if method == "MOVE" and not check_permission(rel_path, role, "delete"):
                    return self._forbidden(start_response, "Source delete permission denied")
                if method == "COPY" and not check_permission(rel_path, role, "read"):
                    return self._forbidden(start_response, "Source read permission denied")

        return self.app(environ, start_response)


def _build_domain_controller(base_domain_controller):
    class WebShareDomainController(base_domain_controller):
        """WebShare 인증 정보를 사용하는 도메인 컨트롤러"""

        def __init__(self, wsgidav_app, config):
            super().__init__(wsgidav_app, config)

        def get_domain_realm(self, input_header, environ):
            return "WebShare Pro WebDAV"

        def require_authentication(self, realmname, environ):
            return True

        def basic_auth_user(self, realmname, username, password, environ):
            """인증 검증"""
            ip = get_webdav_real_ip(environ)
            blocked, remain = _is_auth_blocked(ip)
            if blocked:
                logger.add(f"WebDAV 인증 차단 중: {ip} ({remain}분 남음)", "WARN")
                return False

            admin_pw = conf.get("admin_pw")
            guest_pw = conf.get("guest_pw")

            from security.auth import verify_password

            if username == "admin":
                if verify_password(admin_pw, password):
                    environ["webshare.role"] = "admin"
                    _record_auth_attempt(ip, True)
                    return True

            if username == "guest":
                if verify_password(guest_pw, password):
                    environ["webshare.role"] = "guest"
                    _record_auth_attempt(ip, True)
                    return True

            _record_auth_attempt(ip, False)
            return False

        def supports_http_digest_auth(self):
            return False

        def get_permissions(self, realmname, user, environ, url):
            """권한 확인"""
            role = "admin" if user == "admin" else "guest"
            method = (environ.get("REQUEST_METHOD", "GET") or "GET").upper()
            action = _method_to_action(method)
            rel_path = _normalize_webdav_path(url)

            if is_protected_system_path(rel_path):
                return False

            if action in {"write", "delete"} and not is_secure_webdav_request(environ):
                if not conf.get("webdav_allow_insecure", False):
                    return False

            if role == "guest" and action in {"write", "delete"} and not conf.get("allow_guest_upload"):
                return False

            return check_permission(rel_path, role, action)

    return WebShareDomainController


def create_webdav_app():
    """WebDAV WSGI 앱 생성"""
    try:
        base_dc_module = importlib.import_module("wsgidav.dc.base_dc")
        provider_module = importlib.import_module("wsgidav.fs_dav_provider")
        app_module = importlib.import_module("wsgidav.wsgidav_app")
    except ImportError:
        return None

    try:
        base_domain_controller = getattr(base_dc_module, "BaseDomainController")
        filesystem_provider = getattr(provider_module, "FilesystemProvider")
        wsgidav_app_cls = getattr(app_module, "WsgiDAVApp")
        root_path = conf.get("folder")
        if not os.path.exists(root_path):
            os.makedirs(root_path, exist_ok=True)

        domain_controller = _build_domain_controller(base_domain_controller)
        config = {
            "provider_mapping": {"/": filesystem_provider(root_path)},
            "user_mapping": {},
            "middleware_stack": [
                "wsgidav.middleware.debug.DebugFilter",
                "wsgidav.error_printer.ErrorPrinter",
                "wsgidav.http_authenticator.HTTPAuthenticator",
                "wsgidav.dir_browser.DirBrowser",
            ],
            "simple_dc": {"user_mapping": {}},
            "verbose": 1,
            "domain_controller": domain_controller,
            "logging": {
                "enable": True,
                "enable_loggers": [],
            },
        }
        app = wsgidav_app_cls(config)
        app = WebDAVPolicyMiddleware(app)

        if not conf.get("webdav_allow_insecure", False):
            logger.add("WebDAV 비TLS 쓰기 기본 차단 정책 활성화", "WARN")

        logger.add("WebDAV 앱이 초기화되었습니다.", "INFO")
        return app
    except Exception as e:
        logger.add(f"WebDAV 초기화 실패: {e}", "ERROR")
        return None
