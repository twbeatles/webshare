"""
WebShare Pro - Cloud Sync
Google Drive OAuth + manual upload/download jobs.
"""

from __future__ import annotations

import http.client
import json
import mimetypes
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from config import CLOUD_SYNC_CONFIG, CLOUD_SYNC_FILE, cloud_sync_lock, conf
from features.job_store import (
    create_job,
    get_active_job,
    get_job,
    get_last_job,
    load_jobs,
    mark_incomplete_jobs,
    reset_jobs_runtime_state,
    update_job,
)
from utils.log_manager import logger


GOOGLE_DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"
GOOGLE_DRIVE_FILES_API = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files"
GOOGLE_OAUTH_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
CLOUD_SYNC_JOB_KIND = "cloud_sync"
CLOUD_SYNC_CONFLICT_POLICY = "skip"


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


def load_cloud_runtime_state():
    load_jobs()
    mark_incomplete_jobs(
        kind=CLOUD_SYNC_JOB_KIND,
        state="failed",
        error="cloud sync interrupted by restart",
    )


def get_cloud_job(job_id: str) -> dict[str, Any] | None:
    job = get_job(job_id)
    if not job or job.get("kind") != CLOUD_SYNC_JOB_KIND:
        return None
    return job


def get_provider_last_job(provider: str) -> dict[str, Any] | None:
    return get_last_job(kind=CLOUD_SYNC_JOB_KIND, scope=provider)


def reset_cloud_sync_runtime_state():
    reset_jobs_runtime_state(kind=CLOUD_SYNC_JOB_KIND)


def _set_job_state(job_id: str, *, persist: bool = False, **updates: Any) -> dict[str, Any]:
    snapshot = update_job(job_id, persist=persist, **updates)
    if snapshot is None:
        raise CloudSyncError("job not found")
    return snapshot


def create_cloud_job(provider: str, direction: str, path: str) -> dict[str, Any]:
    active_job = get_active_job(kind=CLOUD_SYNC_JOB_KIND, scope=provider)
    if active_job and active_job.get("state") in {"accepted", "running"}:
        raise CloudSyncError("provider already has an active sync job")

    job = create_job(
        CLOUD_SYNC_JOB_KIND,
        provider,
        provider=provider,
        path=path,
        direction=direction,
        state="accepted",
        progress=0,
        error=None,
        started_at=None,
        finished_at=None,
        supported=(provider == "google_drive"),
        visible=(provider == "google_drive"),
        conflict_policy=CLOUD_SYNC_CONFLICT_POLICY,
        job_persisted=True,
        stats={"files": 0, "uploaded": 0, "downloaded": 0, "skipped": 0},
    )
    job_id = str(job.get("job_id", "") or "")
    update_cloud_provider(provider, {"last_job_id": job_id})
    return dict(job)


def _finish_cloud_job(job_id: str, provider: str, *, state: str, error: str | None = None, progress: int = 100, stats: dict[str, Any] | None = None):
    _set_job_state(
        job_id,
        persist=True,
        state=state,
        error=error,
        progress=max(0, min(100, int(progress))),
        finished_at=_utc_now_iso(),
        stats=stats or {"files": 0, "uploaded": 0, "downloaded": 0, "skipped": 0},
    )
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
        stats = {"files": 0, "uploaded": 0, "downloaded": 0, "skipped": 0}
        if os.path.isfile(local_path):
            stats["files"] = 1
            result = self.upload_file(drive_folder_id, os.path.basename(local_path), local_path)
            if result.get("status") == "skipped":
                stats["skipped"] += 1
            else:
                stats["uploaded"] += 1
            progress_callback(1, 1)
            return stats

        file_paths = []
        folder_cache = {"": drive_folder_id}
        blocked_prefixes: set[str] = set()

        for root, dirs, files in os.walk(local_path):
            dirs[:] = [name for name in dirs if not name.startswith(".")]
            rel_root = os.path.relpath(root, local_path).replace("\\", "/")
            if rel_root == ".":
                rel_root = ""

            if rel_root:
                if self._is_blocked_prefix(rel_root, blocked_prefixes):
                    dirs[:] = []
                    continue
                parent_rel = os.path.dirname(rel_root).replace("\\", "/")
                if parent_rel == ".":
                    parent_rel = ""
                parent_drive_id = folder_cache[parent_rel]
                folder_result = self.ensure_folder(parent_drive_id, os.path.basename(rel_root))
                if folder_result.get("status") == "skipped":
                    blocked_prefixes.add(rel_root)
                    dirs[:] = []
                    continue
                folder_cache[rel_root] = str(folder_result["id"])

            for file_name in files:
                if file_name.startswith("."):
                    continue
                rel_file = "/".join(part for part in [rel_root, file_name] if part)
                if self._is_blocked_prefix(rel_file, blocked_prefixes):
                    continue
                file_paths.append(rel_file)

        total = max(1, len(file_paths))
        stats["files"] = len(file_paths)
        if not file_paths:
            progress_callback(1, 1)
            return stats

        for index, rel_file in enumerate(file_paths, start=1):
            parent_rel = os.path.dirname(rel_file).replace("\\", "/")
            if parent_rel == ".":
                parent_rel = ""
            drive_parent_id = folder_cache.get(parent_rel, drive_folder_id)
            abs_file = os.path.join(local_path, rel_file.replace("/", os.sep))
            result = self.upload_file(drive_parent_id, os.path.basename(rel_file), abs_file)
            if result.get("status") == "skipped":
                stats["skipped"] += 1
            else:
                stats["uploaded"] += 1
            progress_callback(index, total)

        return stats

    def sync_download(self, target_dir: str, drive_folder_id: str, progress_callback: Callable[[int, int], None]) -> dict[str, Any]:
        os.makedirs(target_dir, exist_ok=True)
        entries = self._collect_remote_entries(drive_folder_id, prefix="")
        file_entries = [item for item in entries if item.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME]
        total = max(1, len(file_entries))
        stats = {"files": len(file_entries), "uploaded": 0, "downloaded": 0, "skipped": 0}
        blocked_prefixes: set[str] = set()

        for entry in entries:
            if entry.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME:
                continue
            local_dir = os.path.join(target_dir, entry["rel_path"].replace("/", os.sep))
            if self._is_blocked_prefix(entry["rel_path"], blocked_prefixes):
                continue
            if os.path.exists(local_dir) and not os.path.isdir(local_dir):
                blocked_prefixes.add(entry["rel_path"])
                logger.add(f"Google Drive 다운로드 충돌 skip: {entry['rel_path']}", "WARN")
                continue
            os.makedirs(local_dir, exist_ok=True)

        for index, entry in enumerate(file_entries, start=1):
            if self._is_blocked_prefix(entry["rel_path"], blocked_prefixes):
                stats["skipped"] += 1
                progress_callback(index, total)
                continue
            local_path = os.path.join(target_dir, entry["rel_path"].replace("/", os.sep))
            parent_dir = os.path.dirname(local_path) or target_dir
            os.makedirs(parent_dir, exist_ok=True)
            result = self.download_file(entry["id"], local_path)
            if result.get("status") == "skipped":
                stats["skipped"] += 1
            else:
                stats["downloaded"] += 1
            progress_callback(index, total)

        if not file_entries:
            progress_callback(1, 1)
        return stats

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

    def ensure_folder(self, parent_id: str, name: str) -> dict[str, Any]:
        existing_any = self.find_child(parent_id, name, mime_type=None)
        if existing_any and existing_any.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME:
            logger.add(f"Google Drive 폴더 충돌 skip: {name}", "WARN")
            return {"status": "skipped", "reason": "conflict", "id": existing_any.get("id", "")}

        existing = self.find_child(parent_id, name, GOOGLE_DRIVE_FOLDER_MIME)
        if existing:
            return {"status": "exists", "id": str(existing["id"])}

        payload = {
            "name": name,
            "mimeType": GOOGLE_DRIVE_FOLDER_MIME,
            "parents": [parent_id],
        }
        created = self._request_json("POST", GOOGLE_DRIVE_FILES_API, json_body=payload)
        return {"status": "created", "id": str(created["id"])}

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
        existing = self.find_child(parent_id, name, mime_type=None)
        if existing:
            logger.add(f"Google Drive 업로드 충돌 skip: {name}", "WARN")
            return {"status": "skipped", "reason": "conflict", "id": existing.get("id", "")}

        file_size = int(os.path.getsize(local_path) or 0)
        _body, headers, _status = self._request_response(
            "POST",
            GOOGLE_DRIVE_UPLOAD_API,
            params={"uploadType": "resumable"},
            json_body=metadata,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-Upload-Content-Type": mime_type,
                "X-Upload-Content-Length": str(file_size),
            },
        )
        upload_url = str(headers.get("Location", "") or "")
        if not upload_url:
            raise CloudSyncError("google_drive resumable upload url is missing")

        uploaded = self._stream_upload_file(upload_url, local_path, mime_type, file_size)
        uploaded["status"] = "uploaded"
        return uploaded

    def download_file(self, file_id: str, target_path: str) -> dict[str, Any]:
        if os.path.exists(target_path):
            logger.add(f"Google Drive 다운로드 충돌 skip: {target_path}", "WARN")
            return {"status": "skipped", "reason": "conflict"}

        self._stream_download_to_file(
            "GET",
            f"{GOOGLE_DRIVE_FILES_API}/{file_id}",
            target_path=target_path,
            params={"alt": "media"},
        )
        return {"status": "downloaded"}

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

    @staticmethod
    def _is_blocked_prefix(path: str, blocked_prefixes: set[str]) -> bool:
        normalized = str(path or "").strip("/")
        if not normalized:
            return False
        for prefix in blocked_prefixes:
            current = str(prefix or "").strip("/")
            if not current:
                continue
            if normalized == current or normalized.startswith(f"{current}/"):
                return True
        return False

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
        raw, _headers, _status = self._request_response(
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
        raw, _headers, _status = self._request_response(
            method,
            url,
            params=params,
            json_body=json_body,
            data=data,
            headers=headers,
            authenticated=authenticated,
        )
        return raw

    def _request_response(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> tuple[bytes, dict[str, str], int]:
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
                return response.read(), dict(response.headers.items()), int(getattr(response, "status", 200) or 200)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                detail = str(exc)
            raise CloudSyncError(f"google_drive request failed: {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            raise CloudSyncError(f"google_drive request failed: {exc.reason}") from exc

    def _stream_upload_file(self, upload_url: str, local_path: str, mime_type: str, file_size: int) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(upload_url)
        if parsed.scheme not in {"http", "https"}:
            raise CloudSyncError("google_drive resumable upload url is invalid")

        connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"

        connection = connection_cls(host, port, timeout=120)
        try:
            connection.putrequest("PUT", target)
            connection.putheader("Authorization", f"Bearer {self._ensure_access_token()}")
            connection.putheader("Content-Length", str(max(0, int(file_size or 0))))
            connection.putheader("Content-Type", mime_type)
            connection.endheaders()

            with open(local_path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    connection.send(chunk)

            response = connection.getresponse()
            body = response.read()
            if response.status not in {200, 201}:
                detail = body.decode("utf-8", errors="ignore") if body else ""
                raise CloudSyncError(f"google_drive upload failed: {response.status} {detail}".strip())
            return json.loads(body.decode("utf-8")) if body else {}
        except CloudSyncError:
            raise
        except Exception as exc:
            raise CloudSyncError(f"google_drive upload failed: {exc}") from exc
        finally:
            connection.close()

    def _stream_download_to_file(
        self,
        method: str,
        url: str,
        *,
        target_path: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> None:
        final_url = url
        if params:
            final_url = f"{url}?{urllib.parse.urlencode(params)}"

        request_headers = dict(headers or {})
        if authenticated:
            request_headers["Authorization"] = f"Bearer {self._ensure_access_token()}"

        directory = os.path.dirname(target_path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_dl_", suffix=".tmp")

        req = urllib.request.Request(final_url, headers=request_headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=120) as response, os.fdopen(fd, "wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
            os.replace(temp_path, target_path)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                detail = str(exc)
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise CloudSyncError(f"google_drive request failed: {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise CloudSyncError(f"google_drive request failed: {exc.reason}") from exc
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise


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

        _set_job_state(job_id, persist=True, state="running", started_at=_utc_now_iso(), progress=0, error=None)

        progress_state = {"persisted": -10}

        def _progress(current: int, total: int):
            total_items = max(1, int(total or 1))
            percent = int((max(0, current) / total_items) * 100)
            normalized = max(0, min(100, percent))
            should_persist = normalized in {0, 100} or normalized - progress_state["persisted"] >= 10
            if should_persist:
                progress_state["persisted"] = normalized
            _set_job_state(job_id, persist=should_persist, progress=normalized)

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
