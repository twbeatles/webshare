# -*- mode: python ; coding: utf-8 -*-
# WebShare Pro v7.1 - 경량화 PyInstaller Spec File
# 빌드: pyinstaller WebSharePro.spec

block_cipher = None

# 제외 모듈 (경량화)
excludes = [
    # 과학 계산 라이브러리 (사용하지 않음)
    'matplotlib', 'numpy', 'pandas', 'scipy', 'sympy',
    # 테스트/개발 도구
    'test', 'unittest', 'xmlrpc', 'pydoc', 'doctest',
    # 불필요한 모듈
    'lib2to3', 'idlelib',
]

a = Analysis(
    ['웹서버 프로그램v4.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Flask 핵심
        'flask', 'werkzeug', 'werkzeug.serving', 'werkzeug.security',
        'jinja2', 'markupsafe', 'click', 'itsdangerous',
        # PyQt6 핵심 (GUI)
        'PyQt6', 'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.sip',
        # Tkinter fallback
        'tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'tkinter.filedialog',
        # 이미지 처리
        'PIL', 'PIL.Image',
        # 시스템
        'ctypes', 'ctypes.wintypes',
        # 암호화
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

# 불필요한 Qt 바이너리 제거 (경량화)
a.binaries = [x for x in a.binaries if not any(
    skip in x[0].lower() for skip in [
        'qt6webengine', 'qt6designer', 'qt6quick', 'qt6qml', 
        'qt6pdf', 'qt63d', 'qt6bluetooth', 'qt6multimedia',
    ]
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
    strip=True,              # 디버그 심볼 제거 (경량화)
    upx=True,                # UPX 압축 사용 (경량화)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # GUI 모드 (콘솔 창 숨김)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
