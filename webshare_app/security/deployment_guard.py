"""Deployment safety checks for default credentials and public binding."""

from __future__ import annotations

from config import conf
from security.auth import verify_password

DEFAULT_ADMIN_PASSWORD = "1234"
DEFAULT_GUEST_PASSWORD = "0000"
_PUBLIC_BIND_HOSTS = frozenset({"0.0.0.0", "::", ""})


def uses_default_admin_password() -> bool:
    stored = str(conf.get("admin_pw", "") or "")
    if not stored:
        return True
    return verify_password(stored, DEFAULT_ADMIN_PASSWORD)


def uses_default_guest_password() -> bool:
    stored = str(conf.get("guest_pw", "") or "")
    if not stored:
        return True
    return verify_password(stored, DEFAULT_GUEST_PASSWORD)


def uses_default_credentials() -> bool:
    return uses_default_admin_password() or uses_default_guest_password()


def is_public_bind_host(host: str | None = None) -> bool:
    value = str(host if host is not None else conf.get("display_host", "") or "").strip()
    return value in _PUBLIC_BIND_HOSTS


def collect_deployment_warnings(*, host: str | None = None) -> list[str]:
    warnings: list[str] = []
    bind_host = str(host if host is not None else conf.get("display_host", "") or "")

    if uses_default_credentials() and is_public_bind_host(bind_host):
        warnings.append(
            "기본 비밀번호(Admin 1234 / Guest 0000)로 모든 네트워크 인터페이스에 바인딩되어 있습니다. "
            "즉시 비밀번호를 변경하세요."
        )
    elif uses_default_credentials():
        warnings.append(
            "기본 비밀번호(Admin 1234 / Guest 0000)가 설정되어 있습니다. 운영 환경에서는 변경을 권장합니다."
        )
    elif is_public_bind_host(bind_host):
        warnings.append(
            f"서버가 공개 주소({bind_host or '0.0.0.0'})에 바인딩됩니다. 방화벽과 비밀번호 정책을 확인하세요."
        )

    if not str(conf.get("secret_key", "") or "").strip():
        warnings.append(
            "Flask secret_key가 설정 파일에 없습니다. 앱 설정 디렉터리에 자동 생성됩니다."
        )

    return warnings


def log_deployment_warnings(*, host: str | None = None) -> list[str]:
    from utils.log_manager import logger

    warnings = collect_deployment_warnings(host=host)
    for message in warnings:
        level = "ERROR" if uses_default_credentials() and is_public_bind_host(host) else "WARN"
        logger.add(message, level)
    return warnings