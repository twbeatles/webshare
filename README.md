# 🚀 WebShare Pro v5.1

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_Server-green?logo=flask)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-orange?logo=qt)
![License](https://img.shields.io/badge/License-MIT-yellow)

**강력하고 안전한 파일 공유를 위한 올인원 웹서버 솔루션**

단일 Python 파일로 동작하며, 직관적인 데스크톱 GUI와 현대적인 웹 인터페이스를 제공합니다.

---

## ✨ 주요 기능

### 🖥️ 시스템 편의성 *(v5.1 New)*
- **윈도우 자동 실행**: PC 시작 시 서버 자동 시작
- **트레이 최소화**: 닫기 버튼 클릭 시 트레이로 이동 (백그라운드 실행)
- **UI 개선**: 고해상도 모니터에서도 잘 보이는 입력창

### 🔒 보안
| 기능 | 설명 |
|------|------|
| 비밀번호 해싱 | SHA256 암호화 |
| IP 화이트리스트 | 허용 IP만 접속 |
| 다운로드 제한 | 일일 횟수/용량 제한 |
| 세션 타임아웃 | 자동 로그아웃 |
| XSS 방어 | 동적 콘텐츠 이스케이프 |

### 📁 파일 관리
| 기능 | 설명 |
|------|------|
| 드래그&드롭 이동 | 파일→폴더 드래그 |
| 폴더 크기 계산 | 비동기 API |
| 최근 파일 | 빠른 접근 20개 |
| 버전 관리 | 최대 5개 자동 백업 |
| 휴지통 | 삭제 파일 복구 |

### 🌐 사용자 경험
| 기능 | 설명 |
|------|------|
| 다국어 (한/영) | 실시간 전환 |
| 접속자 모니터링 | 실시간 세션 |
| 디스크 경고 | 90% 초과 알림 |
| Breadcrumb | 폴더 경로 탐색 |

---

## 📥 설치 및 실행

### 요구 사항
- **Python 3.8+**
- Windows (자동 실행 기능 지원)

### 설치
```bash
# 필수 패키지
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

## 🛠️ PyInstaller 빌드 (배포)

```bash
pip install pyinstaller
pyinstaller webshare.spec --clean

# 결과물: dist/WebSharePro.exe
```

---

## ⚙️ v5.1 추가 설정

설정 탭 > 고급 설정에서 변경 가능

| 설정 | 설명 | 기본값 |
|------|------|--------|
| `close_to_tray` | 닫기(X) 시 트레이로 이동 | `True` |
| `autostart` | 윈도우 시작 시 자동 실행 | `False` |
| `minimize_to_tray` | 최소화 시 트레이로 이동 | `True` |

---

## 📝 변경 이력

### v5.1 Update (2024-12)
- 🖥️ **윈도우 시작 시 자동 실행** 추가
- 🔽 **프로그램 종료 시 트레이 최소화** 옵션 추가
- 🎨 **설정 UI 개선** (입력창 가독성 향상)
- 🐛 빌드 시 `http.server` 모듈 누락 수정

### v5.1 (2024-12)
- 🌐 다국어, 최근 파일, IP 화이트리스트, 폴더 크기
- 🖱️ 드래그&드롭, 다운로드 제한, 디스크 경고

---

## 📄 라이선스

MIT License © 2024-2025
