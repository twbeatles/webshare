"""
WebShare Pro - Upload Routes
Chunk upload endpoints.

Split package (SRP): session init, chunk transfer, and finalization each
live in their own module. Importing this package registers all upload
routes on `upload_bp`.
"""

from ._common import upload_bp
from .chunk_init import init_chunk_upload
from .chunk_transfer import upload_chunk
from .chunk_finalize import (
    cancel_chunk_upload,
    cleanup_expired_upload_sessions,
    complete_chunk_upload,
)
from features.search_indexer import indexer
from webshare_app.services.upload_service import UPLOAD_SESSIONS

__all__ = [
    "UPLOAD_SESSIONS",
    "cancel_chunk_upload",
    "cleanup_expired_upload_sessions",
    "complete_chunk_upload",
    "indexer",
    "init_chunk_upload",
    "upload_bp",
    "upload_chunk",
]
