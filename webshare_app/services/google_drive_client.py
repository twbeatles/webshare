"""Google Drive client for WebShare cloud sync."""

from __future__ import annotations

import http.client
import json
import mimetypes
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Callable

from config import conf
from utils.file_utils import safe_filename, validate_path
from utils.log_manager import logger
from utils.request_policy import is_protected_system_path

from .cloud_sync_config import _copy_provider_config, update_cloud_provider
from .cloud_sync_constants import (
    CLOUD_SYNC_CONFLICT_POLICY,
    CLOUD_SYNC_RETRY_ATTEMPTS,
    GOOGLE_DRIVE_FILES_API,
    GOOGLE_DRIVE_FOLDER_MIME,
    GOOGLE_DRIVE_SCOPE,
    GOOGLE_DRIVE_UPLOAD_API,
    GOOGLE_OAUTH_AUTHORIZE_URL,
    GOOGLE_OAUTH_TOKEN_URL,
    CloudSyncCancelled,
    CloudSyncError,
    _utc_now,
    normalize_cloud_conflict_policy,
)


class GoogleDriveClient:
    def __init__(self, conflict_policy: str = CLOUD_SYNC_CONFLICT_POLICY, should_cancel: Callable[[], bool] | None = None):
        self.provider = "google_drive"
        self.conflict_policy = normalize_cloud_conflict_policy(conflict_policy)
        self.should_cancel = should_cancel or (lambda: False)

    def _config(self) -> dict[str, Any]:
        return _copy_provider_config(self.provider)

    def _check_cancelled(self):
        if self.should_cancel():
            raise CloudSyncCancelled("cloud sync cancelled")

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
        stats = {"files": 0, "uploaded": 0, "downloaded": 0, "skipped": 0, "renamed": 0, "overwritten": 0, "dry_run": 0}
        self._check_cancelled()
        if os.path.isfile(local_path):
            stats["files"] = 1
            if self.conflict_policy == "dry_run":
                stats["dry_run"] = 1
                progress_callback(1, 1)
                return stats
            result = self.upload_file(drive_folder_id, os.path.basename(local_path), local_path)
            if result.get("status") == "skipped":
                stats["skipped"] += 1
            elif result.get("status") == "renamed":
                stats["renamed"] += 1
                stats["uploaded"] += 1
            elif result.get("status") == "overwritten":
                stats["overwritten"] += 1
                stats["uploaded"] += 1
            else:
                stats["uploaded"] += 1
            progress_callback(1, 1)
            return stats

        file_paths = []
        folder_cache = {"": drive_folder_id}
        blocked_prefixes: set[str] = set()

        for root, dirs, files in os.walk(local_path):
            self._check_cancelled()
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
        if self.conflict_policy == "dry_run":
            stats["dry_run"] = len(file_paths)
            progress_callback(1, 1)
            return stats
        if not file_paths:
            progress_callback(1, 1)
            return stats

        for index, rel_file in enumerate(file_paths, start=1):
            self._check_cancelled()
            parent_rel = os.path.dirname(rel_file).replace("\\", "/")
            if parent_rel == ".":
                parent_rel = ""
            drive_parent_id = folder_cache.get(parent_rel, drive_folder_id)
            abs_file = os.path.join(local_path, rel_file.replace("/", os.sep))
            result = self.upload_file(drive_parent_id, os.path.basename(rel_file), abs_file)
            if result.get("status") == "skipped":
                stats["skipped"] += 1
            elif result.get("status") == "renamed":
                stats["renamed"] += 1
                stats["uploaded"] += 1
            elif result.get("status") == "overwritten":
                stats["overwritten"] += 1
                stats["uploaded"] += 1
            else:
                stats["uploaded"] += 1
            progress_callback(index, total)

        return stats

    def sync_download(self, target_dir: str, drive_folder_id: str, progress_callback: Callable[[int, int], None]) -> dict[str, Any]:
        os.makedirs(target_dir, exist_ok=True)
        self._check_cancelled()
        entries = self._collect_remote_entries(drive_folder_id, prefix="")
        file_entries = [item for item in entries if item.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME]
        total = max(1, len(file_entries))
        stats = {"files": len(file_entries), "uploaded": 0, "downloaded": 0, "skipped": 0, "renamed": 0, "overwritten": 0, "dry_run": 0}
        blocked_prefixes: set[str] = set()

        if self.conflict_policy == "dry_run":
            stats["dry_run"] = len(file_entries)
            progress_callback(1, 1)
            return stats

        for entry in entries:
            self._check_cancelled()
            if entry.get("mimeType") != GOOGLE_DRIVE_FOLDER_MIME:
                continue
            ok, local_dir, error = self._resolve_download_target(target_dir, entry["rel_path"])
            if self._is_blocked_prefix(entry["rel_path"], blocked_prefixes):
                continue
            if not ok:
                blocked_prefixes.add(entry["rel_path"])
                logger.add(f"Google Drive download path rejected: {entry['rel_path']} ({error})", "WARN")
                continue
            if os.path.exists(local_dir) and not os.path.isdir(local_dir):
                blocked_prefixes.add(entry["rel_path"])
                logger.add(f"Google Drive 다운로드 충돌 skip: {entry['rel_path']}", "WARN")
                continue
            os.makedirs(local_dir, exist_ok=True)

        for index, entry in enumerate(file_entries, start=1):
            self._check_cancelled()
            if self._is_blocked_prefix(entry["rel_path"], blocked_prefixes):
                stats["skipped"] += 1
                progress_callback(index, total)
                continue
            ok, local_path, error = self._resolve_download_target(target_dir, entry["rel_path"])
            if not ok:
                stats["skipped"] += 1
                logger.add(f"Google Drive download path rejected: {entry['rel_path']} ({error})", "WARN")
                progress_callback(index, total)
                continue
            parent_dir = os.path.dirname(local_path) or target_dir
            os.makedirs(parent_dir, exist_ok=True)
            result = self.download_file(entry["id"], local_path)
            if result.get("status") == "skipped":
                stats["skipped"] += 1
            elif result.get("status") == "renamed":
                stats["renamed"] += 1
                stats["downloaded"] += 1
            elif result.get("status") == "overwritten":
                stats["overwritten"] += 1
                stats["downloaded"] += 1
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
            if self.conflict_policy == "rename":
                name = self._unique_remote_name(parent_id, name)
                existing_any = None
            elif self.conflict_policy == "dry_run":
                return {"status": "dry_run", "id": f"dry-run-folder:{name}"}
            else:
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

    def _unique_remote_name(self, parent_id: str, name: str) -> str:
        existing_names = {str(item.get("name", "") or "") for item in self.list_children(parent_id)}
        if name not in existing_names:
            return name
        stem, ext = os.path.splitext(name)
        counter = 1
        while True:
            candidate = f"{stem}_{counter}{ext}"
            if candidate not in existing_names:
                return candidate
            counter += 1

    @staticmethod
    def _unique_local_path(path: str) -> str:
        if not os.path.exists(path):
            return path
        stem, ext = os.path.splitext(path)
        counter = 1
        while os.path.exists(f"{stem}_{counter}{ext}"):
            counter += 1
        return f"{stem}_{counter}{ext}"

    @staticmethod
    def _safe_remote_segment(name: str) -> str:
        return safe_filename(str(name or "unnamed"))

    @staticmethod
    def _resolve_download_target(target_dir: str, rel_path: str) -> tuple[bool, str, str]:
        normalized_rel = str(rel_path or "").replace("\\", "/").strip("/")
        if not normalized_rel or is_protected_system_path(normalized_rel):
            return False, "", "protected remote path"
        valid, local_path, error = validate_path(target_dir, normalized_rel)
        if not valid:
            return False, "", error
        shared_root = conf.get("folder")
        shared_rel = os.path.relpath(local_path, shared_root).replace("\\", "/")
        valid_shared, _shared_abs, error = validate_path(shared_root, shared_rel)
        if not valid_shared or is_protected_system_path(shared_rel):
            return False, "", error or "protected system path"
        return True, local_path, ""

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
        existing_id = str(existing.get("id", "") or "") if existing else ""
        if existing:
            if self.conflict_policy == "skip":
                logger.add(f"Google Drive 업로드 충돌 skip: {name}", "WARN")
                return {"status": "skipped", "reason": "conflict", "id": existing.get("id", "")}
            if self.conflict_policy == "rename":
                name = self._unique_remote_name(parent_id, name)
                metadata["name"] = name
                existing_id = ""
            elif self.conflict_policy == "dry_run":
                return {"status": "dry_run", "reason": "conflict", "id": existing.get("id", "")}
            elif self.conflict_policy != "overwrite":
                return {"status": "skipped", "reason": "conflict", "id": existing.get("id", "")}

        file_size = int(os.path.getsize(local_path) or 0)
        init_method = "PATCH" if existing_id else "POST"
        init_url = f"{GOOGLE_DRIVE_UPLOAD_API}/{existing_id}" if existing_id else GOOGLE_DRIVE_UPLOAD_API
        upload_metadata = {"name": name} if existing_id else metadata
        _body, headers, _status = self._request_response(
            init_method,
            init_url,
            params={"uploadType": "resumable"},
            json_body=upload_metadata,
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
        if existing_id:
            uploaded["status"] = "overwritten"
        elif existing and self.conflict_policy == "rename":
            uploaded["status"] = "renamed"
            uploaded["name"] = name
        else:
            uploaded["status"] = "uploaded"
        return uploaded

    def download_file(self, file_id: str, target_path: str) -> dict[str, Any]:
        if os.path.exists(target_path):
            if self.conflict_policy == "skip":
                logger.add(f"Google Drive 다운로드 충돌 skip: {target_path}", "WARN")
                return {"status": "skipped", "reason": "conflict"}
            if self.conflict_policy == "rename":
                target_path = self._unique_local_path(target_path)
                status = "renamed"
            elif self.conflict_policy == "overwrite":
                if os.path.isdir(target_path) and not os.path.islink(target_path):
                    return {"status": "skipped", "reason": "directory_conflict"}
                status = "overwritten"
            elif self.conflict_policy == "dry_run":
                return {"status": "dry_run", "reason": "conflict"}
            else:
                return {"status": "skipped", "reason": "conflict"}
        else:
            status = "downloaded"

        self._stream_download_to_file(
            "GET",
            f"{GOOGLE_DRIVE_FILES_API}/{file_id}",
            target_path=target_path,
            params={"alt": "media"},
        )
        return {"status": status, "path": target_path}

    def _collect_remote_entries(self, folder_id: str, prefix: str) -> list[dict[str, Any]]:
        self._check_cancelled()
        items = []
        for child in self.list_children(folder_id):
            self._check_cancelled()
            name = self._safe_remote_segment(str(child.get("name", "")))
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
        last_error: Exception | None = None
        for attempt in range(1, CLOUD_SYNC_RETRY_ATTEMPTS + 1):
            self._check_cancelled()
            try:
                return self._request_response_once(
                    method,
                    url,
                    params=params,
                    json_body=json_body,
                    data=data,
                    headers=headers,
                    authenticated=authenticated,
                )
            except CloudSyncCancelled:
                raise
            except CloudSyncError as exc:
                last_error = exc
                if attempt >= CLOUD_SYNC_RETRY_ATTEMPTS or " 4" in str(exc):
                    raise
                time.sleep(0.3 * attempt)
        raise last_error or CloudSyncError("google_drive request failed")

    def _request_response_once(
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
                    self._check_cancelled()
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
                    self._check_cancelled()
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
