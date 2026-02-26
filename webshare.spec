# -*- mode: python ; coding: utf-8 -*-
# ============================================
# WebShare Pro v7.2.x - PyInstaller Spec File
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
        # Flask 정적/템플릿 리소스 포함
        ('static', 'static'),
        ('templates', 'templates'),
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
        # WebShare 모듈 (v7.2.x 모듈형 구조)
        # =========================================
        'config',
        'i18n',
        'server',  # Flask 앱 팩토리, ServerThread
        # utils 패키지
        'utils',
        'utils.log_manager',
        'utils.file_utils',
        'utils.helpers',
        'utils.dashboard_service',
        'utils.listing',
        'utils.zip_utils',
        'utils.request_policy',
        # security 패키지
        'security',
        'security.auth',
        'security.csrf',
        'security.ip_blocker',
        'security.permissions',
        # features 패키지
        'features',
        'features.audit_log',
        'features.duplicates',
        'features.cloud_sync',
        'features.trash',
        'features.metadata',
        'features.crypto',  # NEW: AES-256 암호화
        'features.search_indexer',
        # routes 패키지 (14개 Blueprint)
        'routes',
        'routes.main_routes',
        'routes.file_routes',
        'routes.api_routes',
        'routes.root_api_routes',   # NEW: 프론트엔드 호환
        'routes.media_routes',      # NEW: 미디어 스트리밍
        'routes.share_routes',      # NEW: 공유 링크
        'routes.trash_routes',      # NEW: 휴지통
        'routes.metadata_routes',   # NEW: 태그/즐겨찾기
        'routes.security_routes',   # NEW: 암호화
        'routes.admin_routes',      # NEW: 관리자
        'routes.upload_routes',     # NEW: 청크 업로드
        'routes.duplicate_routes',  # NEW: 중복 검사
        'routes.cloud_routes',      # NEW: 클라우드
        'routes.pwa_routes',        # NEW: PWA (v7.2.3)
        'routes.templates',
        
        # features (v7.2.3)
        'features.network',         # NEW: UPnP
        'features.webdav_server',   # NEW: WebDAV
        'features.transcoder',      # NEW: Transcoder
        
        # External Libs (v7.2.3)
        'miniupnpc',
        'wsgidav',
        'cheroot',
        'ffmpeg', # ffmpeg-python
        # gui 패키지
        'gui',
        'gui.pyqt_gui',
        
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
    icon=None,  # 아이콘: 'ico'
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
#    icon='ico' 로 설정
#
# ============================================
# 의존성 패키지
# ============================================
# 필수: flask, werkzeug, Pillow, cryptography
# GUI: PyQt6 (권장) 또는 tkinter
# 선택: qrcode (QR 코드 기능)
#
# ============================================
# v7.2.x 모듈 구조 (14개 Blueprint)
# ============================================
# (repo root)/
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
#   ├── routes/        # Flask Blueprint (14개)
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
#   │   ├── pwa_routes.py        # PWA 엔드포인트
#   │   └── ...
#   ├── templates/     # HTML 템플릿 (index.html 등)
#   └── gui/           # PyQt6 GUI
#       └── pyqt_gui.py
#
# ============================================
# 문제 해결
# ============================================
# ModuleNotFoundError 발생 시:
#   hiddenimports에 해당 모듈 추가
#
# 특정 모듈을 찾을 수 없는 경우:
#   hiddenimports에 모듈명(config, routes.main_routes 등) 추가 확인
#
# 파일 크기가 큰 경우:
#   excludes에 미사용 패키지 추가
#
# ============================================

