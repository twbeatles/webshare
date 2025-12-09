# 🚀 WebShare Pro v3.3

> 파일 공유 및 관리를 위한 올인원 웹 서버 솔루션

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![PyQt6](https://img.shields.io/badge/PyQt6-Optional-purple.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## ✨ 주요 기능

### 🔐 보안
- 관리자/게스트 이중 비밀번호 시스템
- 경로 탐색(Path Traversal) 공격 방어
- HTTPS 지원 (자체 서명 인증서)
- 로그인 시도 제한

### 📁 파일 관리
- 파일/폴더 업로드, 다운로드, 삭제
- 드래그 앤 드롭 업로드
- ZIP 압축/해제
- 텍스트 파일 편집 (Markdown 미리보기)
- 이미지/동영상/오디오 미리보기
- 휴지통 기능 (복원 가능)

### 🔗 공유 기능
- 임시 공유 링크 생성 (1시간 ~ 7일)
- QR 코드 생성
- 공유 클립보드
- 북마크

### 🎨 UI/UX
- **데스크톱**: PyQt6 모던 다크 테마 (Tkinter 자동 폴백)
- **웹**: 반응형 디자인, 다크/라이트 테마 전환
- 키보드 단축키 지원
- 향상된 토스트 알림 (success/error/warning/info)
- 업로드 진행률 (속도, 예상시간 표시)

---

## 📦 설치

```bash
# 필수 의존성
pip install flask pillow

# 권장 (더 나은 GUI)
pip install PyQt6 qrcode

# HTTPS 사용 시
pip install cryptography
```

---

## 🚀 실행

```bash
python "웹서버 프로그램v3.py"
```

1. 📁 공유 폴더 선택
2. 🔐 비밀번호 설정
3. ▶️ **서버 시작** 클릭
4. 🌐 브라우저에서 접속 또는 📱 QR 코드 스캔

---

## ⌨️ 키보드 단축키 (웹)

| 단축키 | 동작 |
|--------|------|
| `Ctrl+U` | 파일 업로드 |
| `Ctrl+N` | 새 폴더 생성 |
| `Delete` | 선택 파일 삭제 |
| `Ctrl+A` | 전체 선택 |
| `F2` | 이름 변경 |
| `Escape` | 모달 닫기 |

---

## 🖼️ 스크린샷

### 데스크톱 GUI (PyQt6 다크 테마)
- 홈 탭: 서버 시작/중지, 접속 정보
- 설정 탭: 폴더, 네트워크, 비밀번호
- 로그 탭: 실시간 서버 로그

### 웹 UI
- 리스트/그리드 뷰 전환
- 파일 미리보기 (이미지, 동영상, 오디오, 텍스트)
- 컨텍스트 메뉴 (우클릭)

---

## 📋 기술 스택

| 분류 | 기술 |
|------|------|
| Backend | Flask, Werkzeug |
| Frontend | Vanilla JS, CSS Variables |
| Desktop GUI | PyQt6 / Tkinter |
| Icons | Font Awesome 6 |
| Markdown | marked.js, highlight.js |

---

## 📁 파일 구조

```
webshare/
├── 웹서버 프로그램v3.py   # 메인 애플리케이션 (단일 파일)
├── webshare_config.json     # 설정 파일 (자동 생성)
└── README.md
```

---

## 🔧 설정 파일

`webshare_config.json`
```json
{
  "folder": "C:/Users/username/Share",
  "display_host": "192.168.0.10",
  "port": 5000,
  "admin_pw": "admin123",
  "guest_pw": "guest",
  "allow_guest_upload": false,
  "use_https": false
}
```

---

## 📄 라이선스

MIT License

---

## 🤝 기여

Issues 탭에서 버그 리포트 및 기능 제안을 환영합니다!
