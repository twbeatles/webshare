"""
WebShare Pro - Configuration and Constants
설정 및 상수 정의
"""

import os
import threading
from datetime import datetime
from typing import Literal, NotRequired, TypeVar, TypedDict, cast, overload

from utils.log_manager import logger


class ConfigData(TypedDict):
    folder: str
    port: int
    admin_pw: str
    guest_pw: str
    allow_guest_upload: bool
    display_host: str
    use_https: bool
    session_timeout: int
    enable_notifications: bool
    enable_versioning: bool
    minimize_to_tray: bool
    language: str
    ip_whitelist: list[str]
    daily_download_limit: int
    daily_bandwidth_limit_mb: int
    disk_warning_threshold: int
    close_to_tray: bool
    autostart: bool
    trusted_proxies: list[str]
    trusted_hops: int
    webdav_allow_insecure: bool
    trash_auto_delete_days: int
    secret_key: NotRequired[str | None]


StrConfigKey = Literal["folder", "admin_pw", "guest_pw", "display_host", "language"]
IntConfigKey = Literal[
    "port",
    "session_timeout",
    "daily_download_limit",
    "daily_bandwidth_limit_mb",
    "disk_warning_threshold",
    "trusted_hops",
    "trash_auto_delete_days",
]
BoolConfigKey = Literal[
    "allow_guest_upload",
    "use_https",
    "enable_notifications",
    "enable_versioning",
    "minimize_to_tray",
    "close_to_tray",
    "autostart",
    "webdav_allow_insecure",
]
ListStrConfigKey = Literal["ip_whitelist", "trusted_proxies"]
NullableStrConfigKey = Literal["secret_key"]
_T = TypeVar("_T")

BOOL_CONFIG_KEYS = {
    "allow_guest_upload",
    "use_https",
    "enable_notifications",
    "enable_versioning",
    "minimize_to_tray",
    "close_to_tray",
    "autostart",
    "webdav_allow_insecure",
}
INT_CONFIG_KEYS = {
    "port",
    "session_timeout",
    "daily_download_limit",
    "daily_bandwidth_limit_mb",
    "disk_warning_threshold",
    "trusted_hops",
    "trash_auto_delete_days",
}
LIST_STR_CONFIG_KEYS = {"ip_whitelist", "trusted_proxies"}

# ==========================================
# 앱 정보
# ==========================================
APP_TITLE = "WebShare Pro v7.2.4"
APP_VERSION = "7.2.4"
CONFIG_FILE = "webshare_config.json"
USERS_FILE = "webshare_users.json"
DEFAULT_PORT = 5000
AUTH_LOGIN_MODE = "password_only"
USER_API_ENABLED = False
JOBS_FILE = ".webshare_jobs.json"
SEARCH_INDEX_FILE = ".webshare_search_index.json"

# ==========================================
# 파일 타입 확장자 정의
# ==========================================
TEXT_EXTENSIONS = {
    '.txt', '.py', '.html', '.css', '.js', '.json', '.md', '.log', '.xml', '.ini', '.conf',
    '.c', '.cpp', '.h', '.java', '.sh', '.bat', '.ps1', '.yaml', '.yml', '.toml', '.cfg',
    '.sql', '.php', '.rb', '.go', '.rs', '.ts', '.tsx', '.jsx', '.vue', '.svelte'
}

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico', '.tiff'}
VIDEO_EXTENSIONS = {'.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpeg'}
AUDIO_EXTENSIONS = {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma', '.opus'}
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz'}

# ==========================================
# 서버 설정
# ==========================================
SESSION_TIMEOUT_MINUTES = 60
MAX_LOG_LINES = 1000
SHARE_LINK_EXPIRY_HOURS = 24

# v6.0: 6.0 대용량 파일 청크 업로드 설정
CHUNK_SIZE = 10 * 1024 * 1024  # 10MB
MAX_CHUNK_UPLOAD_SIZE = 10 * 1024 * 1024 * 1024  # 10GB (총 파일 크기)

# v7.0: 휴지통 설정
TRASH_FOLDER_NAME = ".webshare_trash"
TRASH_AUTO_DELETE_DAYS = 30
VERSION_FOLDER_NAME = ".webshare_versions"
MAX_VERSIONS = 5
VIDEO_THUMB_FOLDER = ".webshare_thumbs"

# v7.0: 로그인 보안
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_MINUTES = 15

# v7.2: 감사 로그
MAX_AUDIT_LOG = 10000
AUDIT_LOG_FILE = ".webshare_audit.json"
PERMISSIONS_FILE = ".webshare_permissions.json"
CLOUD_SYNC_FILE = ".webshare_cloud.json"
SHARE_LINKS_FILE = ".webshare_share_links.json"

# ==========================================
# 스레드 동기화 락
# ==========================================
_stats_lock = threading.Lock()
_share_links_lock = threading.Lock()
_access_log_lock = threading.Lock()
_login_attempts_lock = threading.Lock()
_metadata_lock = threading.Lock()
_cache_lock = threading.Lock()
_session_lock = threading.Lock()
_download_tracker_lock = threading.Lock()
_recent_files_lock = threading.Lock()
_upload_session_lock = threading.Lock()
_audit_lock = threading.Lock()
_permissions_lock = threading.Lock()
_duplicate_scan_lock = threading.Lock()
_cloud_sync_lock = threading.Lock()

# 하위 호환성을 위한 별칭 (deprecated)
stats_lock = _stats_lock
share_links_lock = _share_links_lock
access_log_lock = _access_log_lock
login_attempts_lock = _login_attempts_lock
metadata_lock = _metadata_lock
cache_lock = _cache_lock
session_lock = _session_lock
download_tracker_lock = _download_tracker_lock
recent_files_lock = _recent_files_lock
upload_session_lock = _upload_session_lock
audit_lock = _audit_lock
permissions_lock = _permissions_lock
duplicate_scan_lock = _duplicate_scan_lock
cloud_sync_lock = _cloud_sync_lock

# ==========================================
# 전역 상태 변수
# ==========================================
SERVER_START_TIME = datetime.now()

STATS = {
    'requests': 0,
    'bytes_sent': 0,
    'bytes_received': 0,
    'errors': 0,
    'active_connections': 0
}

SHARE_LINKS = {}
ACTIVE_SESSIONS = {}
ACCESS_LOG = []
LOGIN_ATTEMPTS = {}
FILE_TAGS = {}
FAVORITE_FOLDERS = []
FILE_MEMOS = {}
BOOKMARKS = []
DOWNLOAD_TRACKER = {}
RECENT_FILES = {}

# v7.2: 신규 전역 변수
AUDIT_LOG = []
FOLDER_PERMISSIONS = {}
DUPLICATE_SCAN_PROGRESS = {'running': False, 'progress': 0, 'total': 0, 'results': []}
CLOUD_SYNC_CONFIG = {
    'google_drive': {
        'enabled': False,
        'client_id': '',
        'client_secret': '',
        'token': None,
        'folder_id': '',
        'last_sync': None,
        'last_job_id': '',
    },
    'dropbox': {
        'enabled': False,
        'client_id': '',
        'client_secret': '',
        'app_key': '',
        'app_secret': '',
        'token': None,
        'folder_id': '',
        'last_sync': None,
        'last_job_id': '',
    },
}

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
