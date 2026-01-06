# -*- mode: python ; coding: utf-8 -*-
# WebShare Pro v7.0 - 경량화 PyInstaller Spec File
# 빌드: pyinstaller WebSharePro.spec

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

# Flask 데이터 파일만 수집 (최소화)
datas = collect_data_files('flask') + collect_data_files('werkzeug')

# 제외 모듈 (경량화 - distutils 제외 충돌 해결)
excludes = [
    # 과학 계산 라이브러리
    'matplotlib', 'numpy', 'pandas', 'scipy', 'sympy',
    # 테스트/문서
    'test', 'unittest', 'xmlrpc', 'pydoc', 'doctest',
    # 불필요한 GUI
    'tkinter', 'turtle', 'curses',
    # 기타
    'lib2to3',
    # 주의: distutils, asyncio, multiprocessing은 제외하지 않음 (훅 충돌 방지)
]

a = Analysis(
    ['웹서버 프로그램v4.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        # Flask 핵심
        'flask', 'werkzeug', 'werkzeug.serving', 'jinja2', 'markupsafe',
        # PyQt6
        'PyQt6', 'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.sip',
        # 이미지
        'PIL', 'PIL.Image',
        # 시스템
        'ctypes', 'ctypes.wintypes',
        # 암호화 (선택)
        'cryptography', 'cryptography.fernet',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# 불필요한 바이너리 제거 (추가 경량화)
a.binaries = [x for x in a.binaries if not any(
    skip in x[0].lower() for skip in ['qt6webengine', 'qt6designer', 'qt6quick', 'qt6qml', 'qt6pdf']
)]

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
    strip=True,  # 심볼 제거
    upx=True,    # UPX 압축
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI 모드
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # 아이콘: 'icon.ico'
)
