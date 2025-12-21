# 🚀 WebShare Pro v4.2

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_Server-green?logo=flask)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-orange?logo=qt)
![License](https://img.shields.io/badge/License-MIT-yellow)

**강력하고 안전한 파일 공유를 위한 올인원 웹서버 솔루션**

단일 Python 파일로 동작하며, 직관적인 데스크톱 GUI와 현대적인 웹 인터페이스를 제공합니다.

---

## 📸 스크린샷

> 프로그램 실행 후 로그인 페이지와 파일 탐색기를 확인하세요.

---

## ✨ 주요 기능

### 1. 🔒 강력한 보안
| 기능 | 설명 |
|------|------|
| 비밀번호 해싱 | SHA256 암호화로 안전하게 저장 |
| 세션 타임아웃 | 설정 가능한 자동 로그아웃 |
| 접속 로깅 | 로그인/파일 접근/관리자 작업 기록 |
| Brute-force 방어 | 5회 실패 시 10분 차단 |
| 경로 탐색 공격 차단 | 디렉토리 탐색 시도 방지 |

### 2. 📁 향상된 파일 관리
- **파일/폴더 작업**: 웹 UI에서 복사, 이동, 삭제
- **전체 검색**: `/search` API로 서버 내 파일 빠르게 검색
- **이미지 썸네일**: 자동 생성 및 캐싱
- **버전 관리**: 파일 수정 시 자동 백업 (최대 5개 버전)
- **대용량 지원**: 10GB+ 파일 업로드/다운로드

### 3. 🖥️ 데스크톱 GUI
- **시스템 트레이**: 백그라운드에서 서버 실행
- **실시간 통계**: 접속자 수, 요청량, 트래픽 모니터링
- **QR 코드**: 모바일 기기 빠른 접속
- **시스템 알림**: Windows 10/11 토스트 알림

### 4. 🎨 v4.2 개선사항 (New!)
- ✅ 모바일 반응형 UI 강화
- ✅ 그리드 뷰 접근성 개선 (호버 시 액션 버튼 표시)
- ✅ 빈 폴더 상태 UI 개선
- ✅ 로딩 상태 애니메이션 추가
- ✅ 실시간 통계 패널 (요청/접속/트래픽)
- ✅ 고급 설정 UI 추가 (버전관리, 알림, 세션 타임아웃)
- ✅ **HiDPI 디스플레이 지원** (4K/고해상도 모니터)
- ✅ 휴지통 복원 버그 수정 (파일명에 _ 포함 시)

---

## 📥 설치 및 실행

### 요구 사항
- **Python 3.8+**
- 권장: `PyQt6` (GUI), `Pillow` (썸네일)

### 설치
```bash
# 필수 패키지
pip install flask werkzeug

# 권장 패키지
pip install pyqt6 pillow

# HTTPS 사용 시 (선택)
pip install cryptography
```

### 실행
```bash
python "웹서버 프로그램v4.py"
```

### 빌드 (EXE 생성)
```bash
# PyInstaller 설치
pip install pyinstaller

# EXE 빌드
pyinstaller webshare.spec

# 결과물: dist/WebSharePro.exe
```

---

## 🎮 사용 방법

1. **서버 시작**: 공유 폴더 선택 → `서버 시작` 클릭
2. **접속**: 표시된 URL(`http://x.x.x.x:5000`)로 브라우저 접속
3. **로그인**:
   - 👑 **관리자**: 모든 권한 (기본 비밀번호: `1234`)
   - 👤 **게스트**: 보기/다운로드만 (기본 비밀번호: `0000`)

---

## ⌨️ 키보드 단축키

| 단축키 | 기능 |
|:------:|------|
| `Ctrl+U` | 파일 업로드 |
| `Ctrl+N` | 새 폴더 생성 |
| `Ctrl+A` | 전체 선택 |
| `Delete` | 선택 항목 삭제 |
| `F2` | 이름 변경 |
| `Escape` | 모달 닫기 |

---

## ⚙️ 설정

`webshare_config.json` (자동 생성)

```json
{
    "folder": "shared_files",
    "port": 5000,
    "admin_pw": "1234",
    "guest_pw": "0000",
    "allow_guest_upload": false,
    "session_timeout": 30,
    "minimize_to_tray": true,
    "enable_versioning": true,
    "enable_notifications": true
}
```

| 설정 | 설명 | 기본값 |
|------|------|--------|
| `folder` | 공유 폴더 경로 | `shared_files` |
| `port` | 서버 포트 | `5000` |
| `admin_pw` | 관리자 비밀번호 | `1234` |
| `guest_pw` | 게스트 비밀번호 | `0000` |
| `session_timeout` | 세션 만료 시간(분) | `30` |
| `minimize_to_tray` | 트레이로 최소화 | `true` |
| `enable_versioning` | 파일 버전 관리 | `true` |

---

## 🔧 API 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/` | 파일 탐색 |
| POST | `/upload/<path>` | 파일 업로드 |
| GET | `/download/<path>` | 파일 다운로드 |
| GET | `/search?q=<query>` | 파일 검색 |
| GET | `/metrics` | 서버 통계 |
| GET | `/thumbnail/<path>` | 이미지 썸네일 |
| POST | `/share/create` | 공유 링크 생성 |

---

## 📝 변경 이력

### v4.2 (2025-12)
- 📱 모바일 반응형 UI 대폭 강화
- ♿ 그리드 뷰 접근성 개선 (호버 시 액션 표시)
- 🎨 빈 폴더 상태 UI 개선
- ⏳ 로딩 상태 애니메이션 추가
- 📊 실시간 통계 패널 추가
- ⚙️ 고급 설정 UI (버전관리, 알림, 세션 타임아웃)
- 🐛 휴지통 복원 버그 수정
- 🧹 코드 정리 (import 통합, 중복 함수 제거)

### v4.1 (2025-12)
- 🎨 로그인 페이지 UI/UX 개선
- ⌨️ 키보드 단축키 가이드 추가
- 🐛 예외 처리 강화 (15개 수정)
- 🌙 다크 모드 스크롤바 개선

### v4.0
- 🔐 비밀번호 해싱 (SHA256)
- 📁 파일 버전 관리
- 🗑️ 휴지통 기능
- 🔗 임시 공유 링크

---

## 📄 라이선스

MIT License

Copyright (c) 2024

---

Made with ❤️ in Python
