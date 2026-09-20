"""Runtime state: locks and shared in-memory stores."""

import threading
from datetime import datetime



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

