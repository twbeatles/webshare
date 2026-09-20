"""Remote file/folder operations with conflict handling."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import mimetypes
import os
from typing import Any
from config import conf
from utils.file_utils import safe_filename, validate_path
from utils.log_manager import logger
from utils.request_policy import is_protected_system_path
from ..cloud_sync_constants import GOOGLE_DRIVE_FILES_API, GOOGLE_DRIVE_FOLDER_MIME, GOOGLE_DRIVE_UPLOAD_API, CloudSyncError


class GoogleDriveFilesMixin:
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

