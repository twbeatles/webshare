from datetime import datetime
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import server as server_module

from config import (
    ACCESS_LOG,
    ACTIVE_SESSIONS,
    AUDIT_LOG,
    BOOKMARKS,
    CLOUD_SYNC_CONFIG,
    DOWNLOAD_TRACKER,
    DUPLICATE_SCAN_PROGRESS,
    FAVORITE_FOLDERS,
    FILE_MEMOS,
    FILE_TAGS,
    FOLDER_PERMISSIONS,
    LOGIN_ATTEMPTS,
    RECENT_FILES,
    SHARE_LINKS,
    access_log_lock,
    audit_lock,
    cloud_sync_lock,
    duplicate_scan_lock,
    conf,
    download_tracker_lock,
    login_attempts_lock,
    metadata_lock,
    permissions_lock,
    recent_files_lock,
    session_lock,
    share_links_lock,
)
from features.cloud_sync import reset_cloud_sync_runtime_state
from features.job_store import reset_jobs_runtime_state
from features.search_indexer import indexer
from server import create_app
from webshare_app.services.upload_service import reset_upload_runtime_state


@pytest.fixture
def app(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("WEBSHARE_CONFIG_DIR", str(tmp_path / "app_config"))

    conf.set("folder", str(shared))
    conf.set("allow_guest_upload", False)
    conf.set("ip_whitelist", [])
    conf.set("daily_download_limit", 0)
    conf.set("daily_bandwidth_limit_mb", 0)
    conf.set("trusted_proxies", [])
    conf.set("trusted_hops", 1)
    conf.set("webdav_allow_insecure", False)
    conf.set("session_timeout", 60)
    conf.config["admin_pw"] = "1234"
    conf.config["guest_pw"] = "0000"

    with permissions_lock:
        FOLDER_PERMISSIONS.clear()
    with share_links_lock:
        SHARE_LINKS.clear()
    with download_tracker_lock:
        DOWNLOAD_TRACKER.clear()
    with session_lock:
        ACTIVE_SESSIONS.clear()
    with audit_lock:
        AUDIT_LOG.clear()
    with login_attempts_lock:
        LOGIN_ATTEMPTS.clear()
    with recent_files_lock:
        RECENT_FILES.clear()
    with metadata_lock:
        FILE_TAGS.clear()
        FAVORITE_FOLDERS.clear()
        FILE_MEMOS.clear()
        BOOKMARKS.clear()
    with access_log_lock:
        ACCESS_LOG.clear()
    with cloud_sync_lock:
        CLOUD_SYNC_CONFIG["google_drive"].clear()
        CLOUD_SYNC_CONFIG["google_drive"].update(
            {
                "enabled": False,
                "client_id": "",
                "client_secret": "",
                "token": None,
                "folder_id": "",
                "last_sync": None,
                "last_job_id": "",
            }
        )
        CLOUD_SYNC_CONFIG["dropbox"].clear()
        CLOUD_SYNC_CONFIG["dropbox"].update(
            {
                "enabled": False,
                "client_id": "",
                "client_secret": "",
                "app_key": "",
                "app_secret": "",
                "token": None,
                "folder_id": "",
                "last_sync": None,
                "last_job_id": "",
            }
        )
    with duplicate_scan_lock:
        DUPLICATE_SCAN_PROGRESS.clear()
        DUPLICATE_SCAN_PROGRESS.update(
            {
                "running": False,
                "progress": 0,
                "total": 0,
                "results": [],
                "last_scan": "",
                "job_id": "",
                "phase": "",
                "cancelled": False,
            }
        )
    reset_jobs_runtime_state()
    reset_cloud_sync_runtime_state()
    reset_upload_runtime_state()
    indexer.reset_runtime_state()
    server_module._runtime_initialized = False

    flask_app = create_app()
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def login(client):
    def _login(role="admin"):
        token = f"csrf-{role}"
        sid = f"sid-{role}"
        now = datetime.now()

        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["role"] = role
            sess["session_id"] = sid
            sess["last_active"] = now.timestamp()
            sess["_csrf_token"] = token

        with session_lock:
            ACTIVE_SESSIONS[sid] = {
                "ip": "127.0.0.1",
                "role": role,
                "login_time": now,
                "last_active": now,
            }
        return token

    return _login


@pytest.fixture
def csrf_headers():
    def _headers(token: str):
        return {"X-CSRF-Token": token}

    return _headers
