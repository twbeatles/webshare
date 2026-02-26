# -*- mode: python ; coding: utf-8 -*-
# ============================================
# WebShare Pro v7.2.x - Simple Spec File
# ============================================
# 간단한 빌드용 spec 파일 (14개 Blueprint)
# 상세 설정은 webshare.spec 참조
# ============================================

a = Analysis(
    ['main.py'],  # 모듈형 진입점
    pathex=['.'],
    binaries=[],
    datas=[
        ('static', 'static'),
        ('templates', 'templates'),
    ],
    hiddenimports=[
        # Flask/Web
        'flask', 'werkzeug', 'werkzeug.security', 'jinja2',
        # GUI/Crypto
        'PIL', 'PyQt6', 'cryptography', 'cryptography.fernet',
        # Optional runtime deps
        'flask_compress', 'cachetools', 'orjson',
        # 앱 모듈
        'config', 'i18n', 'server',
        'utils', 'security', 'features',
        'utils.log_manager', 'utils.file_utils', 'utils.helpers',
        'utils.dashboard_service', 'utils.listing', 'utils.zip_utils', 'utils.request_policy',
        'features.crypto',  # AES-256
        'features.search_indexer',
        'features.network', 'features.webdav_server', 'features.transcoder',
        'gui', 'gui.pyqt_gui',
        # Routes (14개 Blueprint)
        'routes', 'routes.main_routes',
        'routes.file_routes', 'routes.api_routes',
        'routes.root_api_routes', 'routes.media_routes',
        'routes.share_routes', 'routes.trash_routes',
        'routes.metadata_routes', 'routes.security_routes',
        'routes.admin_routes', 'routes.upload_routes',
        'routes.duplicate_routes', 'routes.cloud_routes', 'routes.pwa_routes',
        'routes.templates',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'scipy'],
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
    name='WebSharePro',
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
