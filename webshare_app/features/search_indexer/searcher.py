"""Composed SearchIndexer with singleton construction."""

from __future__ import annotations
import threading
from datetime import datetime
from typing import Any
from utils.log_manager import logger
from .snapshot import SnapshotMixin
from .scanning import ScanningMixin
from .query import QueryMixin
from .watcher import WatcherMixin


class SearchIndexer(SnapshotMixin, ScanningMixin, QueryMixin, WatcherMixin):
    """Composed search index (behavior unchanged; see responsibility mixins)."""
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
