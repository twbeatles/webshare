"""Filesystem scanning and index building."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import os
from datetime import datetime
from typing import Any
from utils.log_manager import logger


class ScanningMixin:

    @staticmethod
    def _should_skip_dir(name: str) -> bool:
        lower = name.lower()
        if lower.startswith(".webshare"):
            return True
        if lower.startswith("."):
            return True
        if lower == "__pycache__":
            return True
        return False


    @staticmethod
    def _normalize_item(name: str, path: str, is_dir: bool) -> dict[str, Any]:
        lower_name = str(name or "").lower()
        return {
            "name": str(name or ""),
            "path": str(path or ""),
            "is_dir": bool(is_dir),
            "lower_name": lower_name,
        }


    @staticmethod
    def _normalize_documents(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or "")
            path = str(item.get("path", "") or "")
            if not name or not path:
                continue
            normalized.append(ScanningMixin._normalize_item(name, path, bool(item.get("is_dir", False))))
        return normalized


    @staticmethod
    def _rebuild_buckets(documents: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = {}
        doc_index: list[dict[str, Any]] = []
        for item in documents:
            normalized = ScanningMixin._normalize_item(
                item.get("name", ""),
                item.get("path", ""),
                bool(item.get("is_dir", False)),
            )
            bucket = index.setdefault(normalized["lower_name"], [])
            bucket.append(
                {
                    "name": normalized["name"],
                    "path": normalized["path"],
                    "is_dir": normalized["is_dir"],
                }
            )
            doc_index.append(normalized)
        return index, doc_index


    def build_index(self, root_path: str, rebuild_reason: str = "full_scan"):
        with self.index_lock:
            if self.is_indexing:
                self.pending_update = True
                self._pending_rebuild_reason = rebuild_reason or self._pending_rebuild_reason or "full_scan"
                return
            self.is_indexing = True
            self.pending_update = False
            self._pending_rebuild_reason = rebuild_reason or self._pending_rebuild_reason or "full_scan"

        try:
            while True:
                with self.index_lock:
                    current_reason = self._pending_rebuild_reason or "full_scan"

                logger.add(f"파일 인덱싱 시작: {root_path} ({current_reason})")
                start_time = datetime.now()

                documents: list[dict[str, Any]] = []

                for root, dirs, files in os.walk(root_path):
                    dirs[:] = [directory for directory in dirs if not self._should_skip_dir(directory)]

                    for name in dirs:
                        try:
                            rel_path = os.path.relpath(os.path.join(root, name), root_path).replace("\\", "/")
                            documents.append(self._normalize_item(name, rel_path, True))
                        except Exception:
                            continue

                    for name in files:
                        if self._should_skip_dir(name):
                            continue
                        try:
                            rel_path = os.path.relpath(os.path.join(root, name), root_path).replace("\\", "/")
                            documents.append(self._normalize_item(name, rel_path, False))
                        except Exception:
                            continue

                new_index, new_doc_index = self._rebuild_buckets(documents)
                elapsed = (datetime.now() - start_time).total_seconds()

                with self.index_lock:
                    self.index = new_index
                    self.doc_index = new_doc_index
                    self.last_indexed = datetime.now()
                    self.last_build_seconds = elapsed
                    self.last_item_count = len(new_doc_index)
                    self.last_error = ""
                    self.snapshot_loaded = True
                    self.last_rebuild_reason = current_reason
                    rerun = self.pending_update
                    if rerun:
                        self.pending_update = False
                    else:
                        self.is_indexing = False
                        self._pending_rebuild_reason = ""

                self.save_snapshot(root_path)
                logger.add(f"파일 인덱싱 완료: {len(new_doc_index)}개 항목 ({elapsed:.2f}초)")

                if rerun:
                    continue
                break

        except Exception as exc:
            logger.add(f"인덱싱 중 오류 발생: {exc}", "ERROR")
            with self.index_lock:
                self.is_indexing = False
                self.last_error = str(exc)

