"""
WebShare Pro - Search Indexer.

Split package (SRP): snapshot persistence, filesystem scanning, queries,
and the file watcher each live in their own mixin module. `SearchIndexer`
composes them with behavior unchanged; `indexer` remains the shared
singleton instance.
"""

from .searcher import SearchIndexer

indexer = SearchIndexer()

__all__ = ["SearchIndexer", "indexer"]
