"""
WebShare Pro - Admin Routes
사용자 관리, 권한 관리, 감사 로그, 대시보드

Split package (SRP): users, permissions, maintenance, audit log, and
system endpoints each live in their own module. Importing this package
registers all admin routes on `admin_bp`.
"""

import os

from ._common import (
    USER_API_NOTICE,
    USER_API_REASON,
    USER_API_WARNING,
    admin_bp,
)
from .audit import clear_audit_log, export_audit_log, get_audit_log
from .maintenance import cleanup_trash, trash_settings
from .permissions import manage_folder_permission, manage_permissions
from .system import access_dashboard, system_stats
from .users import (
    get_user_usage,
    get_users_file_path,
    load_users,
    manage_single_user,
    manage_users,
    save_users,
)

__all__ = [
    "USER_API_NOTICE",
    "USER_API_REASON",
    "USER_API_WARNING",
    "access_dashboard",
    "admin_bp",
    "clear_audit_log",
    "cleanup_trash",
    "export_audit_log",
    "get_audit_log",
    "get_user_usage",
    "get_users_file_path",
    "load_users",
    "manage_folder_permission",
    "manage_permissions",
    "manage_single_user",
    "manage_users",
    "os",
    "save_users",
    "system_stats",
    "trash_settings",
]
