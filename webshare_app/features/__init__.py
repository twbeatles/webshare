# Features Package
from .audit_log import log_audit, save_audit_log, load_audit_log
from .duplicates import calculate_file_hash, scan_duplicates, cancel_duplicate_scan
from .cloud_sync import save_cloud_config, load_cloud_config
from .trash import auto_cleanup_trash, extract_original_name_from_trash, move_to_trash, restore_from_trash
from .metadata import save_metadata, load_metadata
