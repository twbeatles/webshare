# -*- mode: python ; coding: utf-8 -*-
# ============================================
# WebShare Pro v7.2.3 - PyInstaller Spec File
# ============================================
# 빌드 명령어: pyinstaller webshare.spec
# 결과물: dist/WebSharePro.exe
# ============================================
# 모듈형 구조 (v7.2+)
# ============================================

import sys
import os

block_cipher = None

# ============================================
# 분석 설정
# ============================================
a = Analysis(
    ['main.py'],  # 진입점: 모듈형 main.py
    pathex=['.'],  # 현재 디렉토리를 경로에 추가
    binaries=[],
    datas=[
        # 패키지 디렉토리 포함
        ('webshare', 'webshare'),
    ],
    hiddenimports=[
        # =========================================
        # Flask 관련
        # =========================================
        'flask',
        'flask.json',
        'werkzeug',
        'werkzeug.serving',
        'werkzeug.utils',
        'werkzeug.security',
        'jinja2',
        'jinja2.ext',
        
        # =========================================
        # 이미지 처리
        # =========================================
        'PIL',
        'PIL.Image',
        'PIL._tkinter_finder',
        
        # =========================================
        # PyQt6 GUI
        # =========================================
        'PyQt6',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'PyQt6.sip',
        
        # =========================================
        # 암호화 (cryptography)
        # =========================================
        'cryptography',
        'cryptography.fernet',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        
        # =========================================
        # XSS 방지 (v7.2.3)
        # =========================================
        'markupsafe',
        
        # =========================================
        # WebShare 모듈 (v7.2.2 모듈형 구조 - 완성)
        # =========================================
        'webshare',
        'webshare.config',
        'webshare.i18n',
        'webshare.server',  # Flask 앱 팩토리, ServerThread
        # utils 패키지
        'webshare.utils',
        'webshare.utils.log_manager',
        'webshare.utils.file_utils',
        'webshare.utils.helpers',
        # security 패키지
        'webshare.security',
        'webshare.security.auth',
        'webshare.security.csrf',
        'webshare.security.ip_blocker',
        'webshare.security.permissions',
        # features 패키지
        'webshare.features',
        'webshare.features.audit_log',
        'webshare.features.duplicates',
        'webshare.features.cloud_sync',
        'webshare.features.trash',
        'webshare.features.metadata',
        'webshare.features.crypto',  # NEW: AES-256 암호화
        # routes 패키지 (v7.2.2: 13개 Blueprint 완성)
        'webshare.routes',
        'webshare.routes.main_routes',
        'webshare.routes.file_routes',
        'webshare.routes.api_routes',
        'webshare.routes.root_api_routes',   # NEW: 프론트엔드 호환
        'webshare.routes.media_routes',      # NEW: 미디어 스트리밍
        'webshare.routes.share_routes',      # NEW: 공유 링크
        'webshare.routes.trash_routes',      # NEW: 휴지통
        'webshare.routes.metadata_routes',   # NEW: 태그/즐겨찾기
        'webshare.routes.security_routes',   # NEW: 암호화
        'webshare.routes.admin_routes',      # NEW: 관리자
        'webshare.routes.upload_routes',     # NEW: 청크 업로드
        'webshare.routes.duplicate_routes',  # NEW: 중복 검사
        # 'webshare.routes.duplicate_routes', (Removed duplicate)
        'webshare.routes.cloud_routes',      # NEW: 클라우드
        'webshare.routes.pwa_routes',        # NEW: PWA (v7.2.3)
        # 'webshare.routes.templates', (Removed)
        
        # features (v7.2.3)
        'webshare.features.network',         # NEW: UPnP
        'webshare.features.webdav_server',   # NEW: WebDAV
        'webshare.features.transcoder',      # NEW: Transcoder
        
        # External Libs (v7.2.3)
        'miniupnpc',
        'wsgidav',
        'cheroot',
        'ffmpeg', # ffmpeg-python
        # gui 패키지
        'webshare.gui',
        'webshare.gui.pyqt_gui',
        
        # =========================================
        # 표준 라이브러리 (명시적)
        # =========================================
        'json',
        'hashlib',
        'secrets',
        'mimetypes',
        'zipfile',
        'threading',
        'shutil',
        're',
        'unicodedata',
        'tempfile',  # NEW: 원자적 쓰기용
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 불필요한 패키지 제외 (경량화)
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
    name='WebSharePro_v7.2.4',
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
# 필수: flask, werkzeug, Pillow, cryptography
# GUI: PyQt6 (권장) 또는 tkinter
# 선택: qrcode (QR 코드 기능)
#
# ============================================
# v7.2.2 모듈 구조 (완성 - 13개 Blueprint)
# ============================================
# webshare/
#   ├── config.py      # 설정 및 상수
#   ├── i18n.py        # 다국어 지원
#   ├── server.py      # Flask 앱 팩토리, ServerThread
#   ├── utils/         # 유틸리티
#   │   ├── log_manager.py
#   │   ├── file_utils.py
#   │   └── helpers.py
#   ├── security/      # 보안 (인증, CSRF, IP차단)
#   │   ├── auth.py
#   │   ├── csrf.py
#   │   ├── ip_blocker.py
#   │   └── permissions.py
#   ├── features/      # 기능 (감사로그, 휴지통, 암호화 등)
#   │   ├── audit_log.py
#   │   ├── duplicates.py
#   │   ├── cloud_sync.py
#   │   ├── trash.py
#   │   ├── metadata.py
#   │   └── crypto.py      # NEW: AES-256
#   ├── routes/        # Flask Blueprint (13개)
#   │   ├── main_routes.py
#   │   ├── file_routes.py
#   │   ├── api_routes.py
#   │   ├── root_api_routes.py   # 프론트엔드 호환
#   │   ├── media_routes.py      # 스트리밍/썸네일
#   │   ├── share_routes.py      # 공유 링크
#   │   ├── trash_routes.py      # 휴지통
#   │   ├── metadata_routes.py   # 태그/즐겨찾기
#   │   ├── security_routes.py   # 암호화/복호화
#   │   ├── admin_routes.py      # 관리자
#   │   ├── upload_routes.py     # 청크 업로드
#   │   ├── duplicate_routes.py  # 중복 검사
#   │   ├── cloud_routes.py      # 클라우드 동기화
#   │   ├── cloud_routes.py      # 클라우드 동기화
#   │   └── ...
#   ├── templates/     # HTML 템플릿 (index.html 등)
#   └── gui/           # PyQt6 GUI
#   └── gui/           # PyQt6 GUI
#       └── pyqt_gui.py
#
# ============================================
# 문제 해결
# ============================================
# ModuleNotFoundError 발생 시:
#   hiddenimports에 해당 모듈 추가
#
# 'webshare.xxx' 모듈을 찾을 수 없는 경우:
#   datas에 ('webshare', 'webshare') 추가 확인
#
# 파일 크기가 큰 경우:
#   excludes에 미사용 패키지 추가
#
# ============================================

