# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for WebShare Pro.

Synced with the active runtime packaging policy:
- derive APP_VERSION from webshare_app/core/config.py
- bundle standardized API error utilities and optional network/WebDAV modules
- load UI from the real templates/ and static/ directories, not legacy inline templates
"""

from pathlib import Path
from importlib.util import find_spec
from PyInstaller.utils.hooks import collect_submodules
import re

_spec_version = "7.2.4"
_config_text = Path("webshare_app/core/config.py").read_text(encoding="utf-8")
_match = re.search(r'^APP_VERSION\s*=\s*"([^\"]+)"', _config_text, re.MULTILINE)
APP_VERSION = _match.group(1) if _match else _spec_version

block_cipher = None


def _installed(module_name: str) -> bool:
    try:
        return find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _optional_hiddenimports(*module_names: str) -> list[str]:
    return [module_name for module_name in module_names if _installed(module_name)]

hiddenimports = [
    # Flask/Web
    "flask",
    "flask.json",
    "werkzeug",
    "werkzeug.serving",
    "werkzeug.utils",
    "werkzeug.security",
    "jinja2",
    "jinja2.ext",
    "markupsafe",
    # GUI/Media
    "PIL",
    "PIL.Image",
    "PIL._tkinter_finder",
    "PyQt6",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "PyQt6.sip",
    # Security/Crypto
    "cryptography",
    "cryptography.fernet",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    # App modules
    "webshare_app",
    "config",
    "i18n",
    "server",
    "utils",
    "utils.log_manager",
    "utils.file_utils",
    "utils.helpers",
    "utils.dashboard_service",
    "utils.listing",
    "utils.zip_utils",
    "utils.request_policy",
    "utils.api_errors",
    "utils.app_paths",
    "security",
    "security.auth",
    "security.csrf",
    "security.ip_blocker",
    "security.permissions",
    "features",
    "features.audit_log",
    "features.duplicates",
    "features.cloud_sync",
    "features.job_store",
    "features.runtime_state",
    "features.share_links_store",
    "features.trash",
    "features.metadata",
    "features.crypto",
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
    "gui",
    "gui.pyqt_gui",
    # Optional runtime deps
    "flask_compress",
    "cachetools",
    "orjson",
]

hiddenimports += collect_submodules("webshare_app")

hiddenimports += _optional_hiddenimports(
    "miniupnpc",
    "wsgidav",
    "wsgidav.dc.base_dc",
    "wsgidav.fs_dav_provider",
    "wsgidav.wsgidav_app",
    "cheroot",
    "docx",
    "openpyxl",
    "pptx",
    "psutil",
    "qrcode",
    "ffmpeg",
    "watchdog",
    "watchdog.events",
    "watchdog.observers",
    "watchdog.observers.polling",
    "watchdog.observers.read_directory_changes",
    "watchdog.observers.winapi",
)

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
    excludes=[
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "IPython",
        "jupyter",
        "notebook",
        "pytest",
        "sphinx",
        "setuptools",
        "pip",
        "unittest",
        "pydoc",
        "doctest",
        "distutils",
        "lib2to3",
        "test",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=f"WebSharePro_v{APP_VERSION}",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version=None,
    uac_admin=False,
    uac_uiaccess=False,
)
