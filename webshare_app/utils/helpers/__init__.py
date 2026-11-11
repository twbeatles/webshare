"""
WebShare Pro - Helper Functions.

Split package (SRP): recent files, file versions, expiry cleanup,
download quota, and atomic IO each live in their own module.
This package re-exports the original public surface so existing
`from utils.helpers import ...` imports keep working unchanged.
"""

from .atomic_io import (
    atomic_copy_file,
    atomic_save_upload,
    atomic_write_bytes,
    commit_no_replace,
)
from .download_quota import (
    QUOTA_DIRECT_NOTE,
    QUOTA_POLICY_NOTE,
    build_download_tracker_key,
    build_quota_key_set,
    check_combined_download_limit,
    check_download_limit,
    cleanup_expired_download_trackers,
    reserve_combined_download_quota,
    reserve_download_quota,
    rollback_download_quota,
    settle_download_quota,
    track_download,
)
from .expiry_cleanup import (
    cleanup_expired_sessions,
    cleanup_expired_share_links,
    cleanup_stale_transcode_dirs,
    cleanup_upload_temp_dirs,
)
from .file_versions import (
    build_version_filename,
    cleanup_old_versions,
    create_file_version,
    version_name_matches_rel_path,
)
from .recent_files import (
    add_recent_file,
    build_recent_owner_key,
    get_recent_files,
)

__all__ = [
    "add_recent_file",
    "atomic_copy_file",
    "atomic_save_upload",
    "atomic_write_bytes",
    "commit_no_replace",
    "QUOTA_DIRECT_NOTE",
    "QUOTA_POLICY_NOTE",
    "build_download_tracker_key",
    "build_quota_key_set",
    "check_combined_download_limit",
    "build_recent_owner_key",
    "build_version_filename",
    "check_download_limit",
    "cleanup_expired_download_trackers",
    "cleanup_expired_sessions",
    "cleanup_expired_share_links",
    "cleanup_old_versions",
    "cleanup_stale_transcode_dirs",
    "cleanup_upload_temp_dirs",
    "create_file_version",
    "get_recent_files",
    "reserve_combined_download_quota",
    "reserve_download_quota",
    "rollback_download_quota",
    "settle_download_quota",
    "track_download",
    "version_name_matches_rel_path",
]
