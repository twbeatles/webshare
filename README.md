# 🚀 WebShare Pro v5.1

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_Server-green?logo=flask)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-orange?logo=qt)
![License](https://img.shields.io/badge/License-MIT-yellow)

**강력하고 안전한 파일 공유를 위한 올인원 웹서버 솔루션**

단일 Python 파일로 동작하며, 직관적인 데스크톱 GUI와 현대적인 웹 인터페이스를 제공합니다.

---

## ✨ 주요 기능

### 🔒 보안
| 기능 | 설명 |
|------|------|
| 비밀번호 해싱 | SHA256 암호화 |
| IP 화이트리스트 | 허용 IP만 접속 *(v5.1)* |
| 다운로드 제한 | 일일 횟수/용량 제한 *(v5.1)* |
| 세션 타임아웃 | 자동 로그아웃 |
| Brute-force 방어 | 5회 실패 시 10분 차단 |
| XSS 방어 | 동적 콘텐츠 이스케이프 |

### 📁 파일 관리
| 기능 | 설명 |
|------|------|
| 드래그&드롭 이동 | 파일→폴더 드래그 *(v5.1)* |
| 폴더 크기 계산 | 비동기 API *(v5.1)* |
| 최근 파일 | 빠른 접근 20개 *(v5.1)* |
| 버전 관리 | 최대 5개 자동 백업 |
| 휴지통 | 삭제 파일 복구 |
| 압축 다운로드 | 여러 파일 ZIP |

### 🌐 사용자 경험
| 기능 | 설명 |
|------|------|
| 다국어 (한/영) | 실시간 전환 *(v5.1)* |
| 접속자 모니터링 | 실시간 세션 *(v5.1)* |
| 디스크 경고 | 90% 초과 알림 *(v5.1)* |
| Breadcrumb | 폴더 경로 탐색 |
| 키보드 탐색 | 방향키 + Enter |

### 🖥️ 데스크톱 GUI
- 시스템 트레이 지원
- 실시간 통계 표시
- 로그 필터링/내보내기
- QR 코드 생성

---

## 📥 설치 및 실행

### 요구 사항
- **Python 3.8+**
- Windows / macOS / Linux

### 설치
```bash
# 필수
pip install flask werkzeug pillow

# GUI (권장)
pip install pyqt6

# QR 코드 (선택)
pip install qrcode
```

### 실행
```bash
python "웹서버 프로그램v4.py"
```

---

## 🛠️ PyInstaller 빌드

```bash
pip install pyinstaller
pyinstaller webshare.spec

# 결과: dist/WebSharePro.exe
```

---

## ⌨️ 키보드 단축키

| 단축키 | 기능 |
|:------:|------|
| `↑ / ↓` | 파일 목록 탐색 |
| `Enter` | 선택 항목 열기 |
| `Ctrl+U` | 파일 업로드 |
| `Ctrl+N` | 새 폴더 생성 |
| `Ctrl+A` | 전체 선택 |
| `Delete` | 선택 항목 삭제 |
| `F2` | 이름 변경 |
| `Escape` | 모달 닫기 |

---

## ⚙️ 설정 옵션

`webshare_config.json` (자동 생성)

| 설정 | 설명 | 기본값 |
|------|------|--------|
| `folder` | 공유 폴더 경로 | `shared_files` |
| `port` | 서버 포트 | `5000` |
| `admin_pw` | 관리자 비밀번호 | `1234` |
| `guest_pw` | 게스트 비밀번호 | `0000` |
| `session_timeout` | 세션 만료(분) | `30` |
| `language` | 언어 (ko/en) | `ko` |
| `ip_whitelist` | 허용 IP 목록 | `[]` (전체) |
| `daily_download_limit` | 일일 다운로드 횟수 | `0` (무제한) |
| `daily_bandwidth_limit_mb` | 일일 대역폭(MB) | `0` (무제한) |
| `disk_warning_threshold` | 디스크 경고(%) | `90` |

---

## 🔧 API 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/` | 파일 탐색기 |
| POST | `/upload/<path>` | 파일 업로드 |
| GET | `/search?q=<query>` | 파일 검색 |
| GET | `/metrics` | 서버 통계 |
| GET | `/recent_files` | 최근 파일 *(v5.1)* |
| GET | `/folder_size/<path>` | 폴더 크기 *(v5.1)* |
| GET | `/active_sessions` | 접속자 목록 *(v5.1)* |
| POST | `/move` | 파일 이동 *(v5.1)* |
| GET | `/disk_status` | 디스크 상태 *(v5.1)* |
| GET | `/set_language/<lang>` | 언어 변경 *(v5.1)* |

---

## 📝 변경 이력

### v5.1 (2024-12-28)
**신규 기능 8개 추가**
- 🌐 다국어 지원 (한/영 전환)
- ⏱️ 최근 파일 빠른 접근
- 🔐 IP 화이트리스트
- 📊 폴더 크기 계산 (비동기)
- 👥 접속자 실시간 모니터링
- 🖱️ 드래그&드롭 파일 이동
- ⬇️ 다운로드 제한 (횟수/용량)
- 💾 디스크 용량 경고

### v5.0 (2024-12-27)
- 🧭 Breadcrumb 폴더 네비게이션
- ⌨️ 키보드 방향키 파일 탐색
- 📝 로그 레벨 필터링/내보내기
- 📂 공유 폴더 열기 버튼
- 🔒 XSS 취약점 수정

### v4.2 (2024-12)
- 📱 모바일 반응형 UI
- ♿ 접근성 개선
- 📊 실시간 통계 패널

---

## 📄 라이선스

MIT License

Copyright (c) 2024-2025

---

Made with ❤️ in Python
