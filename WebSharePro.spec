# -*- mode: python ; coding: utf-8 -*-
"""Simplified PyInstaller spec for WebShare Pro.

Synced with the active runtime packaging policy:
- derive APP_VERSION from config.py
- keep optional runtime modules bundled for frozen builds
"""

from pathlib import Path
import re

_spec_version = "7.2.1"
_config_text = Path("config.py").read_text(encoding="utf-8")
_match = re.search(r'^APP_VERSION\s*=\s*"([^\"]+)"', _config_text, re.MULTILINE)
APP_VERSION = _match.group(1) if _match else _spec_version

hiddenimports = [
    # Core
    "flask",
    "werkzeug",
    "werkzeug.security",
    "jinja2",
    "PIL",
    "PyQt6",
    "cryptography",
    "cryptography.fernet",
    # Optional runtime deps
    "miniupnpc",
    "wsgidav",
    "wsgidav.dc.base_dc",
    "wsgidav.fs_dav_provider",
    "wsgidav.wsgidav_app",
    "cheroot",
    "ffmpeg",
    "flask_compress",
    "cachetools",
    "orjson",
    "watchdog",
    "watchdog.events",
    "watchdog.observers",
    "watchdog.observers.polling",
    "watchdog.observers.read_directory_changes",
    "watchdog.observers.winapi",
    # App modules
    "config",
    "i18n",
    "server",
    "utils",
    "security",
    "features",
    "gui",
    "gui.pyqt_gui",
    "utils.log_manager",
    "utils.file_utils",
    "utils.helpers",
    "utils.dashboard_service",
    "utils.listing",
    "utils.zip_utils",
    "utils.request_policy",
    "utils.api_errors",
    "features.audit_log",
    "features.duplicates",
    "features.cloud_sync",
    "features.job_store",
    "features.metadata",
    "features.trash",
    "features.crypto",
    "features.share_links_store",
    "features.search_indexer",
    "features.network",
    "features.webdav_server",
    "features.transcoder",
    "routes",
    "routes.main_routes",
    "routes.file_routes",
    "routes.api_routes",
    "routes.root_api_routes",
    "routes.media_routes",
    "routes.share_routes",
    "routes.trash_routes",
    "routes.metadata_routes",
    "routes.security_routes",
    "routes.admin_routes",
    "routes.upload_routes",
    "routes.duplicate_routes",
    "routes.cloud_routes",
    "routes.network_routes",
    "routes.pwa_routes",
    "routes.templates",
]

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[],
    datas=[
        ("static", "static"),
        ("templates", "templates"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["matplotlib", "numpy", "pandas", "scipy"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f"WebSharePro_v{APP_VERSION}",
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
