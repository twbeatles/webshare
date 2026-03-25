"""
WebShare Pro - Cloud Sync
Google Drive OAuth + manual upload/download jobs.
"""

from __future__ import annotations

import json
import mimetypes
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from config import CLOUD_SYNC_CONFIG, CLOUD_SYNC_FILE, cloud_sync_lock, conf
from utils.helpers import atomic_write_bytes
from utils.log_manager import logger


GOOGLE_DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"
GOOGLE_DRIVE_FILES_API = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files"
GOOGLE_OAUTH_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"

_cloud_jobs_lock = threading.Lock()
_cloud_jobs: dict[str, dict[str, Any]] = {}
_provider_active_jobs: dict[str, str] = {}


class CloudSyncError(RuntimeError):
    """Recoverable cloud sync error."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _copy_provider_config(provider: str) -> dict[str, Any]:
    with cloud_sync_lock:
        return dict(CLOUD_SYNC_CONFIG.get(provider, {}))


def update_cloud_provider(provider: str, updates: dict[str, Any]) -> dict[str, Any]:
    with cloud_sync_lock:
        if provider not in CLOUD_SYNC_CONFIG:
            raise CloudSyncError("unsupported provider")
        CLOUD_SYNC_CONFIG[provider].update(updates)
        snapshot = dict(CLOUD_SYNC_CONFIG[provider])
    save_cloud_config()
    return snapshot


def save_cloud_config():
    """클라우드 설정 저장 (스레드 안전, 원자적 쓰기)."""
    base_dir = conf.get("folder")
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)

    with cloud_sync_lock:
        payload = {}
        for provider, cfg in CLOUD_SYNC_CONFIG.items():
            payload[provider] = dict(cfg)

    try:
        fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix=".webshare_cloud_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            os.replace(temp_path, cloud_path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
    except Exception as exc:
        logger.add(f"클라우드 설정 저장 실패: {exc}", "ERROR")


def load_cloud_config():
    """클라우드 설정 로드 (스레드 안전)."""
    base_dir = conf.get("folder")
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)

    if not os.path.exists(cloud_path):
        return

    with cloud_sync_lock:
        try:
            with open(cloud_path, "r", encoding="utf-8") as handle:
                saved = json.load(handle)

            for provider, cfg in saved.items():
                if provider in CLOUD_SYNC_CONFIG and isinstance(cfg, dict):
                    CLOUD_SYNC_CONFIG[provider].update(cfg)

            logger.add("클라우드 설정 로드 완료")
        except Exception as exc:
            logger.add(f"클라우드 설정 로드 실패: {exc}", "ERROR")


def get_cloud_job(job_id: str) -> dict[str, Any] | None:
    with _cloud_jobs_lock:
        job = _cloud_jobs.get(job_id)
        return dict(job) if isinstance(job, dict) else None


def get_provider_last_job(provider: str) -> dict[str, Any] | None:
    with _cloud_jobs_lock:
        job_id = _provider_active_jobs.get(provider, "")
        if job_id and job_id in _cloud_jobs:
            return dict(_cloud_jobs[job_id])
        latest = None
        for item in _cloud_jobs.values():
            if item.get("provider") != provider:
                continue
            if latest is None or item.get("created_at", "") > latest.get("created_at", ""):
                latest = item
        return dict(latest) if latest else None


def reset_cloud_sync_runtime_state():
    with _cloud_jobs_lock:
        _cloud_jobs.clear()
        _provider_active_jobs.clear()


def _set_job_state(job_id: str, **updates: Any) -> dict[str, Any]:
    with _cloud_jobs_lock:
        job = _cloud_jobs.get(job_id)
        if not job:
            raise CloudSyncError("job not found")
        job.update(updates)
        snapshot = dict(job)
    return snapshot


def create_cloud_job(provider: str, direction: str, path: str) -> dict[str, Any]:
    with _cloud_jobs_lock:
        active_id = _provider_active_jobs.get(provider, "")
        active_job = _cloud_jobs.get(active_id, {})
        if active_job.get("state") in {"accepted", "running"}:
            raise CloudSyncError("provider already has an active sync job")

        job_id = f"{provider}-{uuid.uuid4().hex[:12]}"
        job = {
            "job_id": job_id,
            "provider": provider,
            "path": path,
            "direction": direction,
            "state": "accepted",
            "progress": 0,
            "error": None,
            "created_at": _utc_now_iso(),
            "started_at": None,
            "finished_at": None,
            "stats": {"files": 0},
        }
        _cloud_jobs[job_id] = job
        _provider_active_jobs[provider] = job_id

    update_cloud_provider(provider, {"last_job_id": job_id})
    return dict(job)


def _finish_cloud_job(job_id: str, provider: str, *, state: str, error: str | None = None, progress: int = 100, stats: dict[str, Any] | None = None):
    _set_job_state(
        job_id,
        state=state,
        error=error,
        progress=max(0, min(100, int(progress))),
        finished_at=_utc_now_iso(),
        stats=stats or {"files": 0},
    )
    with _cloud_jobs_lock:
        if _provider_active_jobs.get(provider) == job_id:
            _provider_active_jobs.pop(provider, None)

    updates = {"last_job_id": job_id}
    if state == "completed":
        updates["last_sync"] = _utc_now_iso()
    update_cloud_provider(provider, updates)


class GoogleDriveClient:
    def __init__(self):
        self.provider = "google_drive"

    def _config(self) -> dict[str, Any]:
        return _copy_provider_config(self.provider)

    def is_connected(self) -> bool:
        token = self._config().get("token")
        return isinstance(token, dict) and bool(token.get("access_token") or token.get("refresh_token"))

    def build_auth_url(self, redirect_uri: str, state: str) -> str:
        cfg = self._config()
        client_id = cfg.get("client_id", "")
        if not client_id:
            raise CloudSyncError("google_drive client_id is not configured")

        query = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": GOOGLE_DRIVE_SCOPE,
                "access_type": "offline",
                "prompt": "consent",
                "state": state,
            }
        )
        return f"{GOOGLE_OAUTH_AUTHORIZE_URL}?{query}"

    def exchange_code(self, code: str, redirect_uri: str) -> dict[str, Any]:
        cfg = self._config()
        client_id = cfg.get("client_id", "")
        client_secret = cfg.get("client_secret", "")
        if not client_id or not client_secret:
            raise CloudSyncError("google_drive credentials are incomplete")

        payload = urllib.parse.urlencode(
            {
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
        ).encode("utf-8")

        token = self._request_json(
            "POST",
            GOOGLE_OAUTH_TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            authenticated=False,
        )
        self._store_token_bundle(token)
        return token

    def disconnect(self):
        update_cloud_provider(self.provider, {"token": None, "last_job_id": ""})

    def sync_upload(self, local_path: str, drive_folder_id: str, progress_callback: Callable[[int, int], None]) -> dict[str, Any]:
        if os.path.isfile(local_path):
            self.upload_file(drive_folder_id, os.path.basename(local_path), local_path)
            progress_callback(1, 1)
            return {"files": 1}

        file_paths = []
        folder_cache = {"": drive_folder_id}

        for root, dirs, files in os.walk(local_path):
            dirs[:] = [name for name in dirs if not name.startswith(".")]
            rel_root = os.path.relpath(root, local_path).replace("\\", "/")
            if rel_root == ".":
                rel_root = ""

            if rel_root:
                parent_rel = os.path.dirname(rel_root).replace("\\", "/")
                if parent_rel == ".":
                    parent_rel = ""
                parent_drive_id = folder_cache[parent_rel]
                folder_cache[rel_root] = self.ensure_folder(parent_drive_id, os.path.basename(rel_root))

            for file_name in files:
                if file_name.startswith("."):
                    continue
                rel_file = "/".join(part for part in [rel_root, file_name] if part)
                file_paths.append(rel_file)

        total = max(1, len(file_paths))
        if not file_paths:
            progress_callback(1, 1)
            return {"files": 0}

        for index, rel_file in enumerate(file_paths, start=1):
            parent_rel = os.path.dirname(rel_file).replace("\\", "/")
            if parent_rel == ".":
                parent_rel = ""
            drive_parent_id = folder_cache.get(parent_rel, drive_folder_id)
            abs_file = os.path.join(local_path, rel_file.replace("/", os.sep))
            self.upload_file(drive_parent_id, os.path.basename(rel_file), abs_file)
            progress_callback(index, total)

        return {"files": len(file_paths)}

    def sync_download(self, target_dir: str, drive_folder_id: str, progress_callback: Callable[[int, int], None]) -> dict[str, Any]:
        os.makedirs(target_dir, exist_ok=True)
        entries = self._collect_remote_entries(drive_folder_id, prefix="")
        file_entries = [item for item in entries if item.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME]
        total = max(1, len(file_entries))

        for entry in entries:
            if entry.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME:
                continue
            local_dir = os.path.join(target_dir, entry["rel_path"].replace("/", os.sep))
            os.makedirs(local_dir, exist_ok=True)

        for index, entry in enumerate(file_entries, start=1):
            local_path = os.path.join(target_dir, entry["rel_path"].replace("/", os.sep))
            parent_dir = os.path.dirname(local_path) or target_dir
            os.makedirs(parent_dir, exist_ok=True)
            self.download_file(entry["id"], local_path)
            progress_callback(index, total)

        if not file_entries:
            progress_callback(1, 1)
        return {"files": len(file_entries)}

    def list_children(self, parent_id: str) -> list[dict[str, Any]]:
        children = []
        page_token = ""

        while True:
            params = {
                "q": f"'{parent_id}' in parents and trashed = false",
                "fields": "nextPageToken,files(id,name,mimeType)",
                "pageSize": "1000",
                "supportsAllDrives": "false",
            }
            if page_token:
                params["pageToken"] = page_token
            response = self._request_json("GET", GOOGLE_DRIVE_FILES_API, params=params)
            children.extend(response.get("files", []) or [])
            page_token = response.get("nextPageToken", "")
            if not page_token:
                return children

    def ensure_folder(self, parent_id: str, name: str) -> str:
        existing = self.find_child(parent_id, name, GOOGLE_DRIVE_FOLDER_MIME)
        if existing:
            return str(existing["id"])

        payload = {
            "name": name,
            "mimeType": GOOGLE_DRIVE_FOLDER_MIME,
            "parents": [parent_id],
        }
        created = self._request_json("POST", GOOGLE_DRIVE_FILES_API, json_body=payload)
        return str(created["id"])

    def find_child(self, parent_id: str, name: str, mime_type: str | None = None) -> dict[str, Any] | None:
        for item in self.list_children(parent_id):
            if item.get("name") != name:
                continue
            if mime_type and item.get("mimeType") != mime_type:
                continue
            return item
        return None

    def upload_file(self, parent_id: str, name: str, local_path: str) -> dict[str, Any]:
        metadata = {"name": name, "parents": [parent_id]}
        mime_type = mimetypes.guess_type(local_path)[0] or "application/octet-stream"
        with open(local_path, "rb") as handle:
            file_bytes = handle.read()

        body, content_type = self._build_multipart_body(metadata, file_bytes, mime_type)
        existing = self.find_child(parent_id, name, mime_type=None)
        if existing and existing.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME:
            file_id = existing["id"]
            return self._request_json(
                "PATCH",
                f"{GOOGLE_DRIVE_UPLOAD_API}/{file_id}",
                params={"uploadType": "multipart"},
                data=body,
                headers={"Content-Type": content_type},
            )

        return self._request_json(
            "POST",
            GOOGLE_DRIVE_UPLOAD_API,
            params={"uploadType": "multipart"},
            data=body,
            headers={"Content-Type": content_type},
        )

    def download_file(self, file_id: str, target_path: str):
        payload = self._request_bytes(
            "GET",
            f"{GOOGLE_DRIVE_FILES_API}/{file_id}",
            params={"alt": "media"},
        )
        atomic_write_bytes(target_path, payload)

    def _collect_remote_entries(self, folder_id: str, prefix: str) -> list[dict[str, Any]]:
        items = []
        for child in self.list_children(folder_id):
            name = str(child.get("name", ""))
            rel_path = "/".join(part for part in [prefix, name] if part)
            entry = {
                "id": child.get("id", ""),
                "name": name,
                "mimeType": child.get("mimeType", ""),
                "rel_path": rel_path,
            }
            items.append(entry)
            if child.get("mimeType") == GOOGLE_DRIVE_FOLDER_MIME:
                items.extend(self._collect_remote_entries(str(child.get("id", "")), rel_path))
        return items

    def _token(self) -> dict[str, Any]:
        cfg = self._config()
        token = cfg.get("token")
        if not isinstance(token, dict):
            raise CloudSyncError("google_drive is not connected")
        return dict(token)

    def _store_token_bundle(self, token_payload: dict[str, Any]):
        token = dict(token_payload)
        expires_in = int(token.get("expires_in", 3600) or 3600)
        token["expires_at"] = (_utc_now() + timedelta(seconds=expires_in - 30)).isoformat()

        old_token = self._config().get("token")
        if isinstance(old_token, dict) and not token.get("refresh_token"):
            token["refresh_token"] = old_token.get("refresh_token")

        update_cloud_provider(self.provider, {"token": token})

    def _ensure_access_token(self) -> str:
        token = self._token()
        expires_at = token.get("expires_at")
        if expires_at:
            try:
                expires_dt = datetime.fromisoformat(str(expires_at))
            except Exception:
                expires_dt = _utc_now() - timedelta(seconds=1)
            if expires_dt <= _utc_now():
                token = self._refresh_access_token(token)

        access_token = str(token.get("access_token", "") or "")
        if not access_token:
            raise CloudSyncError("google_drive access token is missing")
        return access_token

    def _refresh_access_token(self, token: dict[str, Any]) -> dict[str, Any]:
        refresh_token = str(token.get("refresh_token", "") or "")
        cfg = self._config()
        if not refresh_token:
            raise CloudSyncError("google_drive refresh token is missing")

        payload = urllib.parse.urlencode(
            {
                "client_id": cfg.get("client_id", ""),
                "client_secret": cfg.get("client_secret", ""),
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
        ).encode("utf-8")
        refreshed = self._request_json(
            "POST",
            GOOGLE_OAUTH_TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            authenticated=False,
        )
        if "refresh_token" not in refreshed:
            refreshed["refresh_token"] = refresh_token
        self._store_token_bundle(refreshed)
        return refreshed

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> dict[str, Any]:
        raw = self._request_bytes(
            method,
            url,
            params=params,
            json_body=json_body,
            data=data,
            headers=headers,
            authenticated=authenticated,
        )
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _request_bytes(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> bytes:
        final_url = url
        if params:
            final_url = f"{url}?{urllib.parse.urlencode(params)}"

        request_headers = dict(headers or {})
        payload = data
        if json_body is not None:
            payload = json.dumps(json_body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json; charset=utf-8")

        if authenticated:
            request_headers["Authorization"] = f"Bearer {self._ensure_access_token()}"

        req = urllib.request.Request(final_url, data=payload, headers=request_headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                detail = str(exc)
            raise CloudSyncError(f"google_drive request failed: {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            raise CloudSyncError(f"google_drive request failed: {exc.reason}") from exc

    @staticmethod
    def _build_multipart_body(metadata: dict[str, Any], file_bytes: bytes, mime_type: str) -> tuple[bytes, str]:
        boundary = f"webshare-{uuid.uuid4().hex}"
        parts = [
            f"--{boundary}\r\n".encode("utf-8"),
            b"Content-Type: application/json; charset=UTF-8\r\n\r\n",
            json.dumps(metadata).encode("utf-8"),
            b"\r\n",
            f"--{boundary}\r\n".encode("utf-8"),
            f"Content-Type: {mime_type}\r\n\r\n".encode("utf-8"),
            file_bytes,
            b"\r\n",
            f"--{boundary}--\r\n".encode("utf-8"),
        ]
        return b"".join(parts), f"multipart/related; boundary={boundary}"


def run_google_drive_job(job_id: str, direction: str, abs_path: str):
    provider = "google_drive"
    try:
        client = GoogleDriveClient()
        cfg = _copy_provider_config(provider)
        folder_id = str(cfg.get("folder_id", "") or "")
        if not cfg.get("enabled", False):
            raise CloudSyncError("google_drive sync is disabled")
        if not folder_id:
            raise CloudSyncError("google_drive folder_id is not configured")
        if not client.is_connected():
            raise CloudSyncError("google_drive is not connected")

        _set_job_state(job_id, state="running", started_at=_utc_now_iso(), progress=0, error=None)

        def _progress(current: int, total: int):
            total_items = max(1, int(total or 1))
            percent = int((max(0, current) / total_items) * 100)
            _set_job_state(job_id, progress=max(0, min(100, percent)))

        if direction == "upload":
            stats = client.sync_upload(abs_path, folder_id, _progress)
        elif direction == "download":
            if os.path.exists(abs_path) and not os.path.isdir(abs_path):
                raise CloudSyncError("download target path must be a directory")
            stats = client.sync_download(abs_path, folder_id, _progress)
        else:
            raise CloudSyncError("unsupported sync direction")

        _finish_cloud_job(job_id, provider, state="completed", progress=100, stats=stats)
    except Exception as exc:
        logger.add(f"Google Drive sync failed: {exc}", "ERROR")
        _finish_cloud_job(job_id, provider, state="failed", error=str(exc), progress=0)


def start_google_drive_job(direction: str, abs_path: str, rel_path: str) -> dict[str, Any]:
    job = create_cloud_job("google_drive", direction, rel_path)
    thread = threading.Thread(target=run_google_drive_job, args=(job["job_id"], direction, abs_path), daemon=True)
    thread.start()
    return job
