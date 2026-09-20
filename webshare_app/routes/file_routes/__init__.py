"""
WebShare Pro - File Routes
파일 다운로드, 업로드, 관리 라우트

Split package (SRP): path helpers, download endpoints, mutation endpoints,
and browsing endpoints each live in their own module. Importing this
package registers all file routes on `file_bp`.
"""

from ._common import (
    MAX_CLIPBOARD_CONTENT_BYTES,
    MAX_CLIPBOARD_ENTRIES,
    _clipboard_lock,
    _clipboard_store,
    file_bp,
)
from .path_utils import (
    _create_overwrite_versions_if_needed,
    _is_descendant_path,
    _normcase_path,
)
from .download_handlers import batch_download, download, download_zip
from .mutation_handlers import (
    batch_delete,
    copy_item,
    delete,
    mkdir,
    move_item,
    rename,
    unzip_file,
    upload,
)
from .browse_handlers import clipboard_handler, get_file_info, search_files, zip_preview
from features.search_indexer import indexer
from utils.zip_utils import create_temp_zip_from_items

__all__ = [
    "MAX_CLIPBOARD_CONTENT_BYTES",
    "MAX_CLIPBOARD_ENTRIES",
    "batch_delete",
    "batch_download",
    "clipboard_handler",
    "copy_item",
    "create_temp_zip_from_items",
    "delete",
    "download",
    "download_zip",
    "file_bp",
    "get_file_info",
    "indexer",
    "mkdir",
    "move_item",
    "rename",
    "search_files",
    "unzip_file",
    "upload",
    "zip_preview",
]
