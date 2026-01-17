# -*- mode: python ; coding: utf-8 -*-
# ============================================
# WebShare Pro v7.2.1 - Simple Spec File
# ============================================
# 간단한 빌드용 spec 파일
# 상세 설정은 webshare.spec 참조
# ============================================

a = Analysis(
    ['main.py'],  # 모듈형 진입점
    pathex=['.'],
    binaries=[],
    datas=[('webshare', 'webshare')],
    hiddenimports=[
        'flask', 'werkzeug', 'werkzeug.security', 'jinja2',
        'PIL', 'PyQt6', 'cryptography',
        'webshare', 'webshare.config', 'webshare.i18n',
        'webshare.utils', 'webshare.security', 'webshare.features',
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
