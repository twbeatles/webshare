# WebShare Pro v7.2

<div align="center">

![WebShare Pro Logo](https://img.shields.io/badge/WebShare-Pro-6366f1?style=for-the-badge&logo=server&logoColor=white)

**웹 브라우저를 통해 로컬 파일을 공유하는 올인원 파일 서버**

[![Version](https://img.shields.io/badge/version-7.2.0-blue?style=flat-square)](https://github.com)
[![Python](https://img.shields.io/badge/python-3.8+-green?style=flat-square)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.0+-orange?style=flat-square)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## 📖 목차

- [주요 기능](#-주요-기능)
- [스크린샷](#-스크린샷)
- [설치 방법](#-설치-방법)
- [사용 방법](#-사용-방법)
- [GUI 사용법](#-gui-사용법)
- [웹 인터페이스 사용법](#-웹-인터페이스-사용법)
- [키보드 단축키](#-키보드-단축키)
- [설정](#-설정)
- [API 엔드포인트](#-api-엔드포인트)
- [프로젝트 구조](#-프로젝트-구조)
- [문제 해결](#-문제-해결)
- [라이선스](#-라이선스)

---

## ✨ 주요 기능

### 🗂️ 파일 관리
- **업로드/다운로드** - 드래그 앤 드롭 지원, 대용량 파일 청크 업로드 (10GB까지)
- **폴더 관리** - 생성, 이름 변경, 삭제, ZIP 다운로드
- **파일 검색** - 실시간 파일명 검색
- **일괄 작업** - 다중 선택 후 일괄 다운로드/삭제

### 🔒 보안
- **역할 기반 접근 제어** - 관리자/게스트 분리
- **PBKDF2-SHA256 암호화** - 안전한 비밀번호 저장
- **CSRF 토큰 보호** - 모든 POST 요청 검증
- **IP 차단** - 5회 로그인 실패 시 15분 차단
- **AES-256 파일 암호화** - 개별 파일 암호화/복호화

### 🔗 공유 기능
- **공유 링크 생성** - 비밀번호 보호, 만료 시간, 다운로드 횟수 제한
- **QR 코드** - 모바일 접속용 QR 코드 생성

### 📁 고급 기능
- **휴지통** - 삭제 파일 보관, 복원, 자동 비우기 (30일)
- **버전 관리** - 파일 수정 시 자동 백업 (최대 5개 버전)
- **태그/메모** - 파일에 태그 및 메모 추가
- **즐겨찾기** - 자주 가는 폴더 즐겨찾기

### 🆕 v7.2 신규 기능
- **🔍 파일 중복 검사** - SHA256 해시 기반 중복 파일 검출
- **🔐 폴더 권한 세분화** - 폴더별 읽기/쓰기/삭제 권한 설정
- **📋 감사 로그** - 모든 파일 작업 히스토리 기록
- **🖱️ 드래그 앤 드롭 이동** - 파일을 폴더로 드래그하여 이동
- **📄 PDF/Markdown 미리보기** - pdf.js, marked.js 연동
- **⌨️ 키보드 단축키** - 빠른 파일 탐색 및 작업
- **📑 다중 탭 지원** - 여러 폴더 동시 열기
- **☁️ 클라우드 동기화** - Google Drive/Dropbox 연동 준비

---

## 📸 스크린샷

| 메인 화면 | 파일 미리보기 |
|:---:|:---:|
| 모던 UI, 다크모드 지원 | 이미지/동영상/문서 미리보기 |

| GUI 컨트롤 패널 | 모바일 반응형 |
|:---:|:---:|
| PyQt6 기반 설정 관리 | 모바일 최적화 UI |

---

## 💾 설치 방법

### 필수 요구사항
- Python 3.8 이상
- pip (Python 패키지 관리자)

### 1. 저장소 클론
```bash
git clone https://github.com/your-repo/webshare.git
cd webshare
```

### 2. 의존성 설치
```bash
# 필수 패키지
pip install flask werkzeug pillow cryptography

# GUI (권장)
pip install pyqt6

# 선택 패키지 (추가 기능)
pip install qrcode              # QR 코드 생성
pip install python-docx         # Word 문서 미리보기
pip install openpyxl            # Excel 문서 미리보기
pip install python-pptx         # PowerPoint 미리보기
```

### 3. 실행
```bash
# 모듈형 (권장)
python main.py

# 레거시 (단일 파일)
python "웹서버 프로그램v4.py"
```

---

## 🚀 사용 방법

### 빠른 시작

1. **프로그램 실행**
   ```bash
   python "웹서버 프로그램v4.py"
   ```

2. **GUI에서 설정 확인**
   - 공유 폴더 경로 설정
   - 포트 번호 (기본: 5000)
   - 관리자/게스트 비밀번호 설정

3. **서버 시작**
   - GUI에서 "🚀 서버 시작" 버튼 클릭

4. **브라우저 접속**
   - `http://localhost:5000` 또는 표시된 IP 주소로 접속
   - 비밀번호 입력 후 로그인

### 기본 비밀번호
| 계정 | 비밀번호 | 권한 |
|------|----------|------|
| 관리자 | `1234` | 전체 권한 |
| 게스트 | `0000` | 읽기 전용 |

---

## 🖥️ GUI 사용법

### 메인 화면

```
┌─────────────────────────────────────────────────┐
│  WebShare Pro v7.2                    [_][□][X] │
├─────────────────────────────────────────────────┤
│  [🏠 홈]  [⚙️ 설정]  [📝 로그]                    │
├─────────────────────────────────────────────────┤
│                                                 │
│     ┌─────────────────────────────┐             │
│     │       ⏸️ 서버 중지됨         │             │
│     └─────────────────────────────┘             │
│                                                 │
│     접속 URL: http://192.168.0.10:5000          │
│                                                 │
│     [🚀 서버 시작]  [🌐 브라우저]  [📱 QR]       │
│                                                 │
└─────────────────────────────────────────────────┘
```

### 탭 설명

#### 🏠 홈 탭
- **서버 상태** - 서버 실행 상태 표시
- **접속 URL** - 현재 접속 가능한 URL
- **서버 시작/중지** - 서버 제어 버튼
- **브라우저 열기** - 기본 브라우저로 접속
- **QR 코드** - 모바일 접속용 QR 코드 표시

#### ⚙️ 설정 탭
| 설정 항목 | 설명 |
|-----------|------|
| 공유 폴더 | 공유할 폴더 경로 (찾아보기 버튼) |
| 네트워크 IP | 서버 바인딩 IP (0.0.0.0 = 모든 IP) |
| 포트 번호 | 웹 서버 포트 (기본: 5000) |
| 관리자 비밀번호 | 관리자 접속 비밀번호 |
| 게스트 비밀번호 | 게스트 접속 비밀번호 |
| 게스트 업로드 허용 | 게스트에게 업로드 권한 부여 |
| 세션 타임아웃 | 자동 로그아웃 시간 (분) |

#### 📝 로그 탭
- 서버 활동 로그 실시간 표시
- 로그 레벨 필터링 (전체/INFO/WARN/ERROR)
- 로그 내보내기 (TXT 파일)
- 로그 클리어

---

## 🌐 웹 인터페이스 사용법

### 로그인
1. 브라우저에서 서버 주소 접속
2. 비밀번호 입력 (관리자 또는 게스트)
3. "접속하기" 클릭

### 파일 탐색
- **폴더 열기** - 폴더 클릭
- **상위 폴더** - ".." 클릭 또는 브레드크럼 경로 클릭
- **정렬** - 이름순/크기순/날짜순 선택
- **검색** - 검색창에 파일명 입력

### 파일 업로드
1. **업로드 버튼 클릭** 또는
2. **파일 드래그 앤 드롭** (화면에 직접 드롭)

> 💡 **대용량 파일**: 100MB 이상 파일은 자동으로 청크 업로드 (진행률 표시)

### 파일 다운로드
- **개별 다운로드** - 파일 옆 ⬇️ 버튼 클릭
- **폴더 다운로드** - ZIP 버튼 클릭 (폴더 전체 압축)
- **일괄 다운로드** - 체크박스 선택 후 ZIP 버튼

### 파일 관리 (관리자 전용)
| 작업 | 방법 |
|------|------|
| 이름 변경 | 우클릭 → 이름 변경 |
| 삭제 | 우클릭 → 휴지통 or 영구 삭제 |
| 새 폴더 | 툴바에서 📁 버튼 |
| 복사/이동 | 우클릭 메뉴 |
| 암호화 | 우클릭 → 암호화 |

### 미리보기 지원
| 파일 형식 | 지원 기능 |
|-----------|-----------|
| 이미지 | 갤러리 모드, 확대/축소 |
| 동영상 | 스트리밍 재생 (HTTP Range) |
| 오디오 | 플레이리스트 재생 |
| 텍스트/코드 | 편집기 (저장 가능) |
| PDF | 페이지별 미리보기 |
| Markdown | 렌더링 미리보기 |
| Word/Excel/PPT | 텍스트 추출 미리보기 |

### 공유 링크 생성 (관리자 전용)
1. 파일/폴더 우클릭 → "공유 링크"
2. 옵션 설정:
   - 비밀번호 (선택)
   - 만료 시간 (기본: 24시간)
   - 다운로드 횟수 제한 (선택)
3. 링크 복사 후 공유

---

## ⌨️ 키보드 단축키

### 파일 탐색
| 단축키 | 기능 |
|--------|------|
| `↑` / `↓` | 파일 선택 이동 |
| `Enter` | 파일 열기 / 폴더 진입 |
| `Backspace` | 상위 폴더 이동 |
| `Ctrl + A` | 전체 선택 |
| `Esc` | 선택 해제 / 모달 닫기 |

### 파일 작업
| 단축키 | 기능 |
|--------|------|
| `Delete` | 선택 파일 삭제 |
| `F2` | 이름 변경 |
| `Ctrl + C` | 복사 |
| `Ctrl + X` | 잘라내기 |
| `Ctrl + V` | 붙여넣기 |

### 기타
| 단축키 | 기능 |
|--------|------|
| `Ctrl + N` | 새 폴더 |
| `Ctrl + U` | 파일 업로드 |
| `Ctrl + F` | 검색 |
| `Ctrl + T` | 새 탭 |
| `G` | 뷰 전환 (목록/그리드) |
| `D` | 다크모드 토글 |
| `?` | 단축키 도움말 |

---

## ⚙️ 설정

### webshare_config.json
```json
{
    "folder": "C:\\Users\\User\\shared_files",
    "port": 5000,
    "admin_pw": "1234",
    "guest_pw": "0000",
    "allow_guest_upload": false,
    "display_host": "0.0.0.0",
    "session_timeout": 60,
    "enable_versioning": true,
    "language": "ko",
    "ip_whitelist": [],
    "daily_download_limit": 0,
    "disk_warning_threshold": 90
}
```

### 설정 항목 설명
| 키 | 설명 | 기본값 |
|-----|------|--------|
| `folder` | 공유 폴더 경로 | `./shared_files` |
| `port` | 웹 서버 포트 | `5000` |
| `admin_pw` | 관리자 비밀번호 | `1234` |
| `guest_pw` | 게스트 비밀번호 | `0000` |
| `allow_guest_upload` | 게스트 업로드 허용 | `false` |
| `session_timeout` | 세션 타임아웃 (분) | `60` |
| `enable_versioning` | 버전 관리 활성화 | `true` |
| `language` | 언어 (`ko`/`en`) | `ko` |
| `ip_whitelist` | 허용 IP 목록 (비어있으면 모든 IP 허용) | `[]` |
| `daily_download_limit` | 일일 다운로드 제한 (건) | `0` (무제한) |

---

## 📡 API 엔드포인트

### 인증
| 메서드 | 경로 | 설명 |
|--------|------|------|
| `POST` | `/` | 로그인 |
| `GET` | `/logout` | 로그아웃 |

### 파일 관리
| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/browse/<path>` | 폴더 탐색 |
| `GET` | `/download/<path>` | 파일 다운로드 |
| `POST` | `/upload/<path>` | 파일 업로드 |
| `POST` | `/mkdir/<path>` | 폴더 생성 |
| `POST` | `/rename/<path>` | 이름 변경 |
| `POST` | `/delete/<path>` | 파일 삭제 |
| `POST` | `/copy` | 파일 복사 |
| `POST` | `/move` | 파일 이동 |
| `GET` | `/zip/<path>` | 폴더 ZIP 다운로드 |

### v7.2 API
| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/api/audit_log` | 감사 로그 조회 |
| `GET/POST` | `/api/permissions` | 폴더 권한 관리 |
| `GET` | `/api/duplicates` | 중복 파일 조회 |
| `POST` | `/api/duplicates/scan` | 중복 스캔 시작 |

---

## 📁 프로젝트 구조

### v7.2.2 모듈형 구조 (13개 Blueprint)
```
webshare/
├── main.py                    # 진입점
├── webshare/                  # 메인 패키지
│   ├── config.py              # 설정/상수
│   ├── i18n.py                # 다국어 지원
│   ├── server.py              # Flask 앱 팩토리, ServerThread
│   ├── utils/                 # 유틸리티
│   │   ├── log_manager.py
│   │   ├── file_utils.py
│   │   └── helpers.py
│   ├── security/              # 보안
│   │   ├── auth.py
│   │   ├── csrf.py
│   │   ├── ip_blocker.py
│   │   └── permissions.py
│   ├── features/              # 기능
│   │   ├── audit_log.py
│   │   ├── duplicates.py
│   │   ├── cloud_sync.py
│   │   ├── trash.py
│   │   ├── metadata.py
│   │   └── crypto.py          # AES-256 암호화
│   ├── routes/                # Flask Blueprint (13개)
│   │   ├── main_routes.py     # 로그인, 브라우징
│   │   ├── file_routes.py     # 파일 관리 (10+ operations)
│   │   ├── api_routes.py      # REST API (/api 접두어)
│   │   ├── root_api_routes.py # 루트 레벨 API
│   │   ├── media_routes.py    # 스트리밍/썸네일
│   │   ├── share_routes.py    # 공유 링크
│   │   ├── trash_routes.py    # 휴지통
│   │   ├── metadata_routes.py # 태그/즐겨찾기
│   │   ├── security_routes.py # 암호화/복호화
│   │   ├── admin_routes.py    # 관리자
│   │   ├── upload_routes.py   # 청크 업로드
│   │   ├── duplicate_routes.py# 중복 검사
│   │   ├── cloud_routes.py    # 클라우드
│   │   └── templates.py       # HTML 템플릿
│   └── gui/                   # PyQt6 GUI
│       └── pyqt_gui.py        # WebShareGUI 클래스
├── backup/                    # 백업 파일
├── 웹서버 프로그램v4.py       # 레거시 (단일 파일)
└── shared_files/              # 공유 폴더
```

---

## ❓ 문제 해결

### 서버가 시작되지 않음
```
오류: Address already in use
```
**해결**: 다른 프로그램이 포트를 사용 중. 설정에서 포트 번호 변경

### PyQt6 오류
```
ModuleNotFoundError: No module named 'PyQt6'
```
**해결**: `pip install pyqt6`

### 한글 파일명 깨짐
- WebShare는 한글 파일명을 완벽 지원합니다
- `safe_filename()` 함수가 한글을 보존합니다

### 대용량 파일 업로드 실패
- 100MB 이상 파일은 자동 청크 업로드
- 네트워크 불안정 시 재시도 지원
- 최대 10GB까지 지원

### 외부에서 접속 불가
1. 방화벽에서 포트 열기
2. 공유기 포트포워딩 설정
3. `display_host`를 `0.0.0.0`으로 설정

---

## 📄 라이선스

MIT License

Copyright (c) 2026 WebShare Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files.
