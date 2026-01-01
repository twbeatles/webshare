# -*- mode: python ; coding: utf-8 -*-
# WebShare Pro v6.0 - PyInstaller Spec File

import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Flask, Werkzeug 데이터 파일 수집
flask_datas = collect_data_files('flask')
werkzeug_datas = collect_data_files('werkzeug')

# 추가 데이터 (아이콘 등 있다면 여기에 추가)
added_datas = []
added_datas.extend(flask_datas)
added_datas.extend(werkzeug_datas)

# 제외할 모듈 (용량 최적화)
excluded_modules = [
    'matplotlib', 'numpy', 'pandas', 'scipy', 'tkinter', 
    'test', 'unittest', 'xmlrpc', 'pydoc', 'doctest', 'curses'
]

a = Analysis(
    ['웹서버 프로그램v4.py'],
    pathex=[],
    binaries=[],
    datas=added_datas,
    hiddenimports=[
        'flask',
        'werkzeug',
        'werkzeug.serving',
        'werkzeug.debug', 
        'jinja2',
        'markupsafe',
        'PIL',
        'PIL.Image',
        'PyQt6',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.sip',
        'json',
        'logging',
        'ctypes',
        'ctypes.wintypes', # DPI 설정에 필요할 수 있음
        'shutil',
        'uuid',
        'mimetypes',
        'socket',
        'webbrowser',
        'threading',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excluded_modules,
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
    name='WebSharePro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI 프로그램이므로 콘솔 숨김 (디버깅 시 True로 변경)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # 아이콘 파일이 있다면 경로 지정 (예: 'icon.ico')
)
