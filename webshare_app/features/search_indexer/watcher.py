"""Filesystem watcher and debounced rebuilds."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import importlib
import os
import threading
from utils.log_manager import logger


class WatcherMixin:

    @staticmethod
    def _load_watchdog_components():
        try:
            observers_module = importlib.import_module("watchdog.observers")
            events_module = importlib.import_module("watchdog.events")
        except ImportError:
            return None, None
        return getattr(observers_module, "Observer", None), getattr(events_module, "FileSystemEventHandler", None)


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

