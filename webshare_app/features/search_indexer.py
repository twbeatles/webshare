"""
WebShare Pro - Search Indexer
Snapshot-backed in-memory search index with optional watchdog-triggered refresh.
"""

from __future__ import annotations

import importlib
import json
import os
import threading
import time
from datetime import datetime
from typing import Any

from config import SEARCH_INDEX_FILE
from utils.helpers import atomic_write_bytes
from utils.log_manager import logger


class SearchIndexer:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(SearchIndexer, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.index: dict[str, list[dict[str, Any]]] = {}
        self.doc_index: list[dict[str, Any]] = []
        self.is_indexing = False
        self.pending_update = False
        self.last_indexed: datetime | None = None
        self.last_build_seconds = 0.0
        self.last_item_count = 0
        self.last_error = ""
        self.snapshot_loaded = False
        self.watcher_active = False
        self.last_rebuild_reason = "startup"
        self.index_lock = threading.RLock()
        self._debounce_timer: threading.Timer | None = None
        self._pending_rebuild_reason = "startup"
        self._observer = None
        self._watch_root = ""
        self._initialized = True
        logger.add("SearchIndexer 초기화됨")

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
    def _snapshot_path(root_path: str) -> str:
        return os.path.join(root_path, SEARCH_INDEX_FILE)

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
            normalized.append(SearchIndexer._normalize_item(name, path, bool(item.get("is_dir", False))))
        return normalized

    @staticmethod
    def _rebuild_buckets(documents: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = {}
        doc_index: list[dict[str, Any]] = []
        for item in documents:
            normalized = SearchIndexer._normalize_item(
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

    @staticmethod
    def _load_watchdog_components():
        try:
            observers_module = importlib.import_module("watchdog.observers")
            events_module = importlib.import_module("watchdog.events")
        except ImportError:
            return None, None
        return getattr(observers_module, "Observer", None), getattr(events_module, "FileSystemEventHandler", None)

    def _serialize_snapshot(self) -> bytes:
        documents = [
            {
                "name": item.get("name", ""),
                "path": item.get("path", ""),
                "is_dir": bool(item.get("is_dir", False)),
            }
            for item in self.doc_index
        ]
        payload = {
            "updated": datetime.now().isoformat(),
            "last_indexed": self.last_indexed.isoformat() if self.last_indexed else None,
            "last_build_seconds": self.last_build_seconds,
            "document_count": len(documents),
            "documents": documents,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    def _should_ignore_event_path(self, root_path: str, event_path: str) -> bool:
        absolute_root = os.path.abspath(root_path)
        absolute_event = os.path.abspath(event_path)
        if not absolute_event.startswith(absolute_root):
            return True
        rel_path = os.path.relpath(absolute_event, absolute_root).replace("\\", "/")
        if rel_path in {".", ""}:
            return False
        for segment in rel_path.split("/"):
            if self._should_skip_dir(segment):
                return True
        return False

    def _run_debounced_build(self, root_path: str) -> None:
        with self.index_lock:
            reason = self._pending_rebuild_reason or "debounced_update"
            self._debounce_timer = None
        self.build_index(root_path, rebuild_reason=reason)

    def load_snapshot(self, root_path: str) -> bool:
        snapshot_path = self._snapshot_path(root_path)
        if not os.path.exists(snapshot_path):
            with self.index_lock:
                self.snapshot_loaded = False
            return False

        try:
            with open(snapshot_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except Exception as exc:
            logger.add(f"검색 인덱스 스냅샷 로드 실패: {exc}", "WARN")
            with self.index_lock:
                self.snapshot_loaded = False
            return False

        raw_documents = raw.get("documents", []) if isinstance(raw, dict) else []
        documents = self._normalize_documents(raw_documents if isinstance(raw_documents, list) else [])
        new_index, new_doc_index = self._rebuild_buckets(documents)
        last_indexed_raw = raw.get("last_indexed") if isinstance(raw, dict) else None
        last_indexed = None
        if last_indexed_raw:
            try:
                last_indexed = datetime.fromisoformat(str(last_indexed_raw))
            except ValueError:
                last_indexed = None

        with self.index_lock:
            self.index = new_index
            self.doc_index = new_doc_index
            self.last_indexed = last_indexed
            self.last_build_seconds = float(raw.get("last_build_seconds", 0.0) or 0.0) if isinstance(raw, dict) else 0.0
            self.last_item_count = len(new_doc_index)
            self.last_error = ""
            self.snapshot_loaded = True
            self.last_rebuild_reason = "snapshot_load"

        logger.add(f"검색 인덱스 스냅샷 로드 완료: {len(new_doc_index)}개 항목")
        return True

    def save_snapshot(self, root_path: str) -> bool:
        snapshot_path = self._snapshot_path(root_path)
        try:
            atomic_write_bytes(snapshot_path, self._serialize_snapshot())
            return True
        except Exception as exc:
            logger.add(f"검색 인덱스 스냅샷 저장 실패: {exc}", "WARN")
            return False

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

    def search(self, query: str, max_results: int = 100):
        if not query:
            return []

        normalized_query = query.lower().strip()
        results = []

        with self.index_lock:
            seen_paths = set()
            if normalized_query in self.index:
                for item in self.index[normalized_query]:
                    path = item.get("path", "")
                    if not path:
                        continue
                    seen_paths.add(path)
                    results.append(
                        {
                            "name": item.get("name", os.path.basename(path)),
                            "path": path,
                            "is_dir": bool(item.get("is_dir", False)),
                        }
                    )

            count = 0
            for doc in self.doc_index:
                if normalized_query not in doc.get("lower_name", ""):
                    continue
                path = str(doc.get("path", "") or "")
                if not path or path in seen_paths:
                    continue
                seen_paths.add(path)
                results.append(
                    {
                        "name": doc.get("name", ""),
                        "path": path,
                        "is_dir": bool(doc.get("is_dir", False)),
                    }
                )
                count += 1
                if count >= max_results:
                    break

        return results[:max_results]

    def get_status(self):
        with self.index_lock:
            return {
                "is_indexing": self.is_indexing,
                "pending_update": self.pending_update,
                "last_indexed": self.last_indexed.isoformat() if self.last_indexed else None,
                "last_build_seconds": self.last_build_seconds,
                "indexed_items": self.last_item_count,
                "name_bucket_count": len(self.index),
                "document_count": len(self.doc_index),
                "last_error": self.last_error,
                "snapshot_loaded": self.snapshot_loaded,
                "watcher_active": self.watcher_active,
                "last_rebuild_reason": self.last_rebuild_reason,
            }

    def start_watcher(self, root_path: str) -> bool:
        absolute_root = os.path.abspath(root_path)
        with self.index_lock:
            if self.watcher_active and self._watch_root == absolute_root and self._observer is not None:
                return True

        self.stop_watcher()
        observer_cls, handler_cls = self._load_watchdog_components()
        if observer_cls is None or handler_cls is None:
            logger.add("watchdog 미설치: debounce 재빌드로 fallback", "WARN")
            with self.index_lock:
                self.watcher_active = False
            return False

        outer = self

        class _EventHandler(handler_cls):
            def on_any_event(self, event):
                if getattr(event, "is_directory", False):
                    path = getattr(event, "src_path", "")
                else:
                    path = getattr(event, "src_path", "")
                if path and outer._should_ignore_event_path(absolute_root, path):
                    return
                dest_path = getattr(event, "dest_path", "")
                if dest_path and outer._should_ignore_event_path(absolute_root, dest_path):
                    return
                event_type = str(getattr(event, "event_type", "changed") or "changed")
                outer.update_event(absolute_root, reason=f"watchdog:{event_type}")

        try:
            observer = observer_cls()
            observer.schedule(_EventHandler(), absolute_root, recursive=True)
            observer.start()
        except Exception as exc:
            logger.add(f"watchdog 시작 실패: {exc}", "WARN")
            with self.index_lock:
                self.watcher_active = False
            return False

        with self.index_lock:
            self._observer = observer
            self._watch_root = absolute_root
            self.watcher_active = True
        logger.add(f"검색 인덱스 watcher 시작: {absolute_root}")
        return True

    def stop_watcher(self):
        observer = None
        with self.index_lock:
            observer = self._observer
            self._observer = None
            self._watch_root = ""
            self.watcher_active = False

        if observer is None:
            return

        try:
            observer.stop()
        except Exception:
            pass
        try:
            observer.join(timeout=2)
        except Exception:
            pass

    def update_event(self, root_path: str, reason: str = "change"):
        with self.index_lock:
            self._pending_rebuild_reason = reason or "change"
            if self.is_indexing:
                self.pending_update = True
                return

            if self._debounce_timer is not None:
                self._debounce_timer.cancel()

            self._debounce_timer = threading.Timer(5.0, self._run_debounced_build, args=[root_path])
            self._debounce_timer.daemon = True
            self._debounce_timer.start()

    def reset_runtime_state(self):
        self.stop_watcher()
        with self.index_lock:
            if self._debounce_timer is not None:
                self._debounce_timer.cancel()
                self._debounce_timer = None
            self.index = {}
            self.doc_index = []
            self.is_indexing = False
            self.pending_update = False
            self.last_indexed = None
            self.last_build_seconds = 0.0
            self.last_item_count = 0
            self.last_error = ""
            self.snapshot_loaded = False
            self.last_rebuild_reason = "startup"
            self._pending_rebuild_reason = "startup"


indexer = SearchIndexer()
