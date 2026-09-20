"""Index snapshot persistence (load/save/serialize)."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import json
import os
from datetime import datetime
from config import SEARCH_INDEX_FILE
from utils.helpers import atomic_write_bytes
from utils.log_manager import logger


class SnapshotMixin:

    @staticmethod
    def _snapshot_path(root_path: str) -> str:
        return os.path.join(root_path, SEARCH_INDEX_FILE)


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

