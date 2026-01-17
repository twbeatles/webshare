# -*- mode: python ; coding: utf-8 -*-
# ============================================
# WebShare Pro v7.2.2 - Simple Spec File
# ============================================
# 간단한 빌드용 spec 파일 (13개 Blueprint)
# 상세 설정은 webshare.spec 참조
# ============================================

a = Analysis(
    ['main.py'],  # 모듈형 진입점
    pathex=['.'],
    binaries=[],
    datas=[('webshare', 'webshare')],
    hiddenimports=[
        # Flask/Web
        'flask', 'werkzeug', 'werkzeug.security', 'jinja2',
        # GUI/Crypto
        'PIL', 'PyQt6', 'cryptography', 'cryptography.fernet',
        # WebShare 패키지
        'webshare', 'webshare.config', 'webshare.i18n', 'webshare.server',
        'webshare.utils', 'webshare.security', 'webshare.features',
        'webshare.features.crypto',  # AES-256
        'webshare.gui', 'webshare.gui.pyqt_gui',
        # Routes (13개 Blueprint)
        'webshare.routes', 'webshare.routes.main_routes',
        'webshare.routes.file_routes', 'webshare.routes.api_routes',
        'webshare.routes.root_api_routes', 'webshare.routes.media_routes',
        'webshare.routes.share_routes', 'webshare.routes.trash_routes',
        'webshare.routes.metadata_routes', 'webshare.routes.security_routes',
        'webshare.routes.admin_routes', 'webshare.routes.upload_routes',
        'webshare.routes.duplicate_routes', 'webshare.routes.cloud_routes',
        'webshare.routes.templates',
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
