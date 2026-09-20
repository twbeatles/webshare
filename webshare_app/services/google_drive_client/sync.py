"""Upload/download sync orchestration."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import os
from typing import Any, Callable
from utils.log_manager import logger
from ..cloud_sync_constants import GOOGLE_DRIVE_FOLDER_MIME


class GoogleDriveSyncMixin:
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

