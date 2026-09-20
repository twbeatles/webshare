"""Configuration schema: ConfigData TypedDict, key literals, key sets."""

from typing import Literal, NotRequired, TypeVar, TypedDict




class ConfigData(TypedDict):
    folder: str
    port: int
    admin_pw: str
    guest_pw: str
    allow_guest_upload: bool
    display_host: str
    use_https: bool
    session_timeout: int
    enable_notifications: bool
    enable_versioning: bool
    minimize_to_tray: bool
    language: str
    ip_whitelist: list[str]
    daily_download_limit: int
    daily_bandwidth_limit_mb: int
    disk_warning_threshold: int
    close_to_tray: bool
    autostart: bool
    trusted_proxies: list[str]
    trusted_hops: int
    webdav_allow_insecure: bool
    trash_auto_delete_days: int
    secret_key: NotRequired[str | None]



StrConfigKey = Literal["folder", "admin_pw", "guest_pw", "display_host", "language"]

IntConfigKey = Literal[
    "port",
    "session_timeout",
    "daily_download_limit",
    "daily_bandwidth_limit_mb",
    "disk_warning_threshold",
    "trusted_hops",
    "trash_auto_delete_days",
]

BoolConfigKey = Literal[
    "allow_guest_upload",
    "use_https",
    "enable_notifications",
    "enable_versioning",
    "minimize_to_tray",
    "close_to_tray",
    "autostart",
    "webdav_allow_insecure",
]

ListStrConfigKey = Literal["ip_whitelist", "trusted_proxies"]

NullableStrConfigKey = Literal["secret_key"]

_T = TypeVar("_T")


BOOL_CONFIG_KEYS = {
    "allow_guest_upload",
    "use_https",
    "enable_notifications",
    "enable_versioning",
    "minimize_to_tray",
    "close_to_tray",
    "autostart",
    "webdav_allow_insecure",
}

INT_CONFIG_KEYS = {
    "port",
    "session_timeout",
    "daily_download_limit",
    "daily_bandwidth_limit_mb",
    "disk_warning_threshold",
    "trusted_hops",
    "trash_auto_delete_days",
}

LIST_STR_CONFIG_KEYS = {"ip_whitelist", "trusted_proxies"}

