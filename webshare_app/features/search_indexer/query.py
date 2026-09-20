"""Index search and status queries."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import os


class QueryMixin:

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

