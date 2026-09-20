"""ConfigManager persistence/typed access and the `conf` singleton."""

import os
from typing import cast, overload
from utils.log_manager import logger
from .defaults import CONFIG_FILE, DEFAULT_PORT, SESSION_TIMEOUT_MINUTES, TRASH_AUTO_DELETE_DAYS
from .schema import BOOL_CONFIG_KEYS, BoolConfigKey, ConfigData, INT_CONFIG_KEYS, IntConfigKey, LIST_STR_CONFIG_KEYS, ListStrConfigKey, NullableStrConfigKey, StrConfigKey, _T



# ==========================================
# ConfigManager 클래스
# ==========================================
class ConfigManager:
    """설정 파일 관리 (JSON)"""

    def __init__(self):
        self.config: ConfigData = {
            'folder': os.path.abspath(os.path.join(os.getcwd(), 'shared_files')),
            'port': DEFAULT_PORT,
            'admin_pw': "1234",
            'guest_pw': "0000",
            'allow_guest_upload': False,
            'display_host': '0.0.0.0',
            'use_https': False,
            'session_timeout': SESSION_TIMEOUT_MINUTES,
            'enable_notifications': True,
            'enable_versioning': True,
            'minimize_to_tray': True,
            'language': 'ko',
            'ip_whitelist': [],
            'daily_download_limit': 0,
            'daily_bandwidth_limit_mb': 0,
            'disk_warning_threshold': 90,
            'trash_auto_delete_days': TRASH_AUTO_DELETE_DAYS,
            'close_to_tray': True,
            'autostart': False,
            # 신뢰 프록시 설정 (비어있으면 X-Forwarded-For 미신뢰)
            'trusted_proxies': [],
            'trusted_hops': 1,
            # WebDAV 비TLS 쓰기 허용 여부 (기본: 거부)
            'webdav_allow_insecure': False,
            'secret_key': None,
        }
        self.load()

    def _ensure_shared_folder_exists(self):
        folder = self.config.get('folder', '')
        if not folder:
            return
        try:
            os.makedirs(folder, exist_ok=True)
        except Exception as exc:
            logger.add(f"공유 폴더 생성 실패: {exc}", "ERROR")

    def load(self):
        import json
        self._ensure_shared_folder_exists()

        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    for key, value in loaded.items():
                        if key not in self.config:
                            logger.add(f"알 수 없는 설정 키 무시: {key}", "WARN")
                            continue
                        try:
                            if key == 'secret_key':
                                if value is not None and not isinstance(value, str):
                                    raise ValueError("secret_key는 문자열 또는 null이어야 합니다")
                                cast(dict[str, object], self.config)[key] = value
                            else:
                                self.set(str(key), value)
                        except Exception as exc:
                            logger.add(f"설정 로드 무시 ({key}): {exc}", "WARN")
            except (json.JSONDecodeError, IOError) as e:
                logger.add(f"설정 로드 실패: {e}", "ERROR")
        self._ensure_shared_folder_exists()
        self._ensure_secret_key()

    def _ensure_secret_key(self):
        try:
            from webshare_app.core.app_paths import ensure_config_secret_key

            ensure_config_secret_key(self)
        except Exception as exc:
            logger.add(f"secret_key 초기화 실패: {exc}", "WARN")

    def save(self):
        """설정 파일 저장 (원자적 쓰기)"""
        import json
        import tempfile
        try:
            from security.auth import hash_password, is_legacy_sha256_hash, is_password_hash

            for password_key in ("admin_pw", "guest_pw"):
                stored_password = self.config.get(password_key)
                if (
                    isinstance(stored_password, str)
                    and stored_password
                    and not is_password_hash(stored_password)
                    and not is_legacy_sha256_hash(stored_password)
                ):
                    self.config[password_key] = hash_password(stored_password)

            # 원자적 쓰기: 임시 파일에 쓴 후 rename
            dir_path = os.path.dirname(os.path.abspath(CONFIG_FILE)) or '.'
            fd, temp_path = tempfile.mkstemp(dir=dir_path, prefix='.webshare_config_', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, indent=4, ensure_ascii=False)
                os.replace(temp_path, CONFIG_FILE)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        except IOError as e:
            logger.add(f"설정 저장 실패: {e}", "ERROR")

    @overload
    def get(self, key: StrConfigKey, default: str | None = None) -> str: ...

    @overload
    def get(self, key: IntConfigKey, default: int | None = None) -> int: ...

    @overload
    def get(self, key: BoolConfigKey, default: bool | None = None) -> bool: ...

    @overload
    def get(self, key: ListStrConfigKey, default: list[str] | None = None) -> list[str]: ...

    @overload
    def get(self, key: NullableStrConfigKey, default: str | None = None) -> str | None: ...

    @overload
    def get(self, key: str, default: _T) -> _T: ...

    @overload
    def get(self, key: str, default: None = None) -> object | None: ...

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key: str, value):
        """설정값 저장 (유효성 검증 포함)"""
        import re

        if key in BOOL_CONFIG_KEYS and not isinstance(value, bool):
            raise ValueError(f"{key}는 bool 값이어야 합니다")

        if key in INT_CONFIG_KEYS:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{key}는 정수여야 합니다")

        if key in LIST_STR_CONFIG_KEYS:
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError(f"{key}는 문자열 리스트여야 합니다")

        # 폴더 경로 검증
        if key == 'folder':
            if not isinstance(value, str) or not value.strip():
                raise ValueError("공유 폴더 경로는 비어있을 수 없습니다")
            value = os.path.abspath(value)
            # 폴더가 없으면 생성 시도
            if not os.path.exists(value):
                try:
                    os.makedirs(value)
                except Exception as e:
                    raise ValueError(f"폴더 생성 실패: {e}")

        # 포트 범위 검증
        if key == 'port':
            if not isinstance(value, int) or value < 1 or value > 65535:
                raise ValueError("포트는 1-65535 범위의 정수여야 합니다")

        # 비밀번호 검증 (빈 문자열 거부)
        if key in ('admin_pw', 'guest_pw'):
            if not isinstance(value, str) or not value:
                raise ValueError("비밀번호는 비어있을 수 없습니다")
            from security.auth import hash_password, is_legacy_sha256_hash, is_password_hash

            if not is_password_hash(value) and not is_legacy_sha256_hash(value):
                value = hash_password(value)

        # 세션 타임아웃 검증
        if key == 'session_timeout':
            if not isinstance(value, int) or value < 1:
                raise ValueError("세션 타임아웃은 1분 이상의 정수여야 합니다")

        if key in {'daily_download_limit', 'daily_bandwidth_limit_mb'}:
            numeric_value = cast(int, value)
            if numeric_value < 0:
                raise ValueError(f"{key}는 0 이상의 정수여야 합니다")

        if key == 'trash_auto_delete_days':
            if not isinstance(value, int) or value < 1:
                raise ValueError("trash_auto_delete_days는 1 이상의 정수여야 합니다")

        # 디스크 경고 임계값 검증
        if key == 'disk_warning_threshold':
            if not isinstance(value, int) or value < 1 or value > 100:
                raise ValueError("디스크 경고 임계값은 1-100 범위여야 합니다")

        # IP 화이트리스트 검증
        if key == 'ip_whitelist':
            if not isinstance(value, list):
                raise ValueError("IP 화이트리스트는 리스트여야 합니다")
            # IPv4/IPv6 간단 검증
            ip_pattern = re.compile(
                r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$|'  # IPv4
                r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'  # IPv6 full
                r'^::$|^::1$'  # IPv6 loopback
            )
            for ip in value:
                if not isinstance(ip, str) or not ip_pattern.match(ip):
                    raise ValueError(f"유효하지 않은 IP 주소: {ip}")

        # 신뢰 프록시 목록 검증
        if key == 'trusted_proxies':
            if not isinstance(value, list):
                raise ValueError("trusted_proxies는 리스트여야 합니다")
            for ip in value:
                if not isinstance(ip, str) or not ip.strip():
                    raise ValueError(f"유효하지 않은 trusted proxy 값: {ip}")

        # 신뢰 홉 수 검증
        if key == 'trusted_hops':
            if not isinstance(value, int) or value < 1:
                raise ValueError("trusted_hops는 1 이상의 정수여야 합니다")

        # WebDAV 비TLS 허용 검증
        if key == 'webdav_allow_insecure':
            if not isinstance(value, bool):
                raise ValueError("webdav_allow_insecure는 bool 값이어야 합니다")

        cast(dict[str, object], self.config)[key] = value



# 전역 설정 인스턴스
conf = ConfigManager()

