# -*- mode: python ; coding: utf-8 -*-
# ============================================
# WebShare Pro v5.1 - PyInstaller Spec File
# ============================================
# 빌드 명령어: pyinstaller webshare.spec
# 결과물: dist/WebSharePro.exe
# ============================================

import sys
import os

block_cipher = None

# ============================================
# 분석 설정
# ============================================
a = Analysis(
    ['웹서버 프로그램v4.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Flask 관련
        'flask',
        'flask.json',
        'werkzeug',
        'werkzeug.serving',
        'werkzeug.utils',
        'jinja2',
        'jinja2.ext',
        # 이미지 처리
        'PIL',
        'PIL.Image',
        'PIL._tkinter_finder',
        # PyQt6 GUI
        'PyQt6',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'PyQt6.sip',
        # 표준 라이브러리 (명시적)
        'json',
        'hashlib',
        'secrets',
        'mimetypes',
        'zipfile',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 불필요한 패키지 제외 (경량화)
    # 주의: werkzeug가 필요로 하는 모듈은 제외하면 안됨
    excludes=[
        # 데이터 분석 (대용량)
        'numpy',
        'pandas',
        'scipy',
        'matplotlib',
        # 개발/테스트 도구
        'IPython',
        'jupyter',
        'notebook',
        'pytest',
        'sphinx',
        'setuptools',
        'pip',
        # 기타 미사용
        'tkinter',  # PyQt6 사용 시 불필요
        'unittest',
        'pydoc',
        'doctest',
        'distutils',
        'lib2to3',
        'test',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ============================================
# PYZ 압축 (Python 모듈 번들)
# ============================================
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

# ============================================
# 실행 파일 생성
# ============================================
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
    upx=True,  # UPX 압축 활성화 (경량화)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI 앱 - 콘솔 숨김
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # 윈도우 버전 정보 (선택)
    icon=None,  # 아이콘: 'webshare.ico'
    version=None,  # 버전 정보: 'version_info.txt'
    uac_admin=False,
    uac_uiaccess=False,
)

# ============================================
# 빌드 가이드
# ============================================
# 
# 1. PyInstaller 설치
#    pip install pyinstaller
#
# 2. UPX 설치 (선택, 압축률 향상)
#    https://upx.github.io/ 에서 다운로드 후 PATH에 추가
#
# 3. 빌드 실행
#    pyinstaller webshare.spec
#
# 4. 결과물 확인
#    dist/WebSharePro.exe
#
# 5. 아이콘 추가 (선택)
#    icon='webshare.ico' 로 설정
#
# ============================================
# 의존성 패키지
# ============================================
# 필수: flask, werkzeug, Pillow
# GUI: PyQt6 (권장) 또는 tkinter
# 선택: qrcode (QR 코드 기능)
#
# ============================================
# 문제 해결
# ============================================
# ModuleNotFoundError 발생 시:
#   hiddenimports에 해당 모듈 추가
#
# 파일 크기가 큰 경우:
#   excludes에 미사용 패키지 추가
#
# ============================================
