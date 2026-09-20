"""
WebShare Pro - Helper Functions.

Split package (SRP): recent files, file versions, expiry cleanup,
download quota, and atomic IO each live in their own module.
This package re-exports the original public surface so existing
`from utils.helpers import ...` imports keep working unchanged.
"""

from .recent_files import (
    add_recent_file,
    build_recent_owner_key,
    get_recent_files,
)
from .file_versions import (
    _decode_version_rel_path,
    _encode_version_rel_path,
    _legacy_version_rel_key,
    build_version_filename,
    cleanup_old_versions,
    create_file_version,
    version_name_matches_rel_path,
)
from .expiry_cleanup import (
    cleanup_expired_sessions,
    cleanup_expired_share_links,
    cleanup_upload_temp_dirs,
)
from .download_quota import (
    build_download_tracker_key,
    check_download_limit,
    cleanup_expired_download_trackers,
    reserve_download_quota,
    rollback_download_quota,
    track_download,
)
from .atomic_io import (
    atomic_copy_file,
    atomic_save_upload,
    atomic_write_bytes,
)

__all__ = [
    "add_recent_file",
    "atomic_copy_file",
    "atomic_save_upload",
    "atomic_write_bytes",
    "build_download_tracker_key",
    "build_recent_owner_key",
    "build_version_filename",
    "check_download_limit",
    "cleanup_expired_download_trackers",
    "cleanup_expired_sessions",
    "cleanup_expired_share_links",
    "cleanup_old_versions",
    "cleanup_upload_temp_dirs",
    "create_file_version",
    "get_recent_files",
    "reserve_download_quota",
    "rollback_download_quota",
    "track_download",
    "version_name_matches_rel_path",
]
