"""Built-in default constants (ports, limits, file names, update URLs)."""

import os



# ==========================================
# 앱 정보
# ==========================================
APP_TITLE = "WebShare Pro v7.3.0"

APP_VERSION = "7.3.0"

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
# 자동 업데이트 설정
# ==========================================
UPDATE_MANIFEST_URL = os.environ.get(
    "WEBSHARE_UPDATE_MANIFEST_URL",
    "https://raw.githubusercontent.com/twbeatles/webshare/main/updates/latest.json",
)

UPDATE_PUBLIC_KEY_B64_DEFAULT = "9NXSv7t42FGsieOCYHKbWrI5aORhT6qOQMxb9BZrTnk="

UPDATE_PUBLIC_KEY_B64 = os.environ.get(
    "WEBSHARE_UPDATE_PUBLIC_KEY_B64",
    UPDATE_PUBLIC_KEY_B64_DEFAULT,
)

UPDATE_RELEASES_URL = "https://github.com/twbeatles/webshare/releases/latest"

UPDATE_MANIFEST_MAX_BYTES = 256 * 1024

UPDATE_ARTIFACT_MAX_BYTES = 500 * 1024 * 1024

UPDATE_REQUEST_TIMEOUT_SECONDS = 20

UPDATE_BACKUP_KEEP_COUNT = 2

