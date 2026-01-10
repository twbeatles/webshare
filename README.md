# WebShare Pro v7.1

> 🌐 **웹 기반 파일 공유 서버 with PyQt6 GUI**

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-Server-green)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-purple)

**WebShare Pro**는 파이썬으로 제작된 올인원 파일 공유 서버입니다.

---

## ✨ v7.1 신규 업데이트 (보안)

### 🛡️ 보안 강화 (Security)
- **비밀번호 보안**: PBKDF2 + SHA256 (Salted) 암호화 적용 (기존 비밀번호 호환 지원)
- **CSRF 보호**: 모든 폼 및 AJAX 요청에 CSRF 토큰 검증 적용
- **경로 탐색 방지**: 대용량 업로드(청크) 및 파일 관리 시 상위 경로 접근 원천 차단
- **IP 차단**: 5회 로그인 실패 시 15분 자동 차단

### 🔒 핵심 기능
- **파일 암호화**: AES-256 암호화/복호화 (랜덤 Salt)
- **접속 대시보드**: 활동 통계, 차단 IP 관리

### 📂 파일 관리
- **문서 미리보기**: Word, Excel, PowerPoint, CSV, JSON
- **파일 태그/메모**: 색상별 태그, 파일 메모 기능
- **즐겨찾기**: 폴더 빠른 접근

### 🔗 공유 확장
- **비밀번호 보호**: 공유 링크에 비밀번호 설정
- **다운로드 제한**: 최대 다운로드 횟수 설정

### 🎨 UI/UX
- **현대적 디자인**: Glassmorphism 스타일 적용
- **헤더 그룹화**: 빠른 접근을 위한 드롭다운 메뉴
- **파일 아이콘**: 파일 타입별 고유 색상

---

## 🚀 설치

### 필수 라이브러리
```bash
pip install flask pyqt6 pillow cryptography
```

### 선택 라이브러리 (미리보기 기능)
```bash
pip install python-docx    # Word 미리보기
pip install openpyxl       # Excel 미리보기
pip install python-pptx    # PowerPoint 미리보기
```

### 실행
```bash
python "웹서버 프로그램v4.py"
```

---

## 🏗️ EXE 빌드

```bash
pip install pyinstaller
pyinstaller WebSharePro.spec
```

빌드 결과: `dist/WebSharePro.exe`

---

## ⌨️ 단축키

| 단축키 | 동작 |
|--------|------|
| `Ctrl+U` | 업로드 |
| `Ctrl+N` | 새 폴더 |
| `Ctrl+A` | 전체 선택 |
| `Delete` | 삭제 |
| `F2` | 이름 변경 |

---

## 📁 프로젝트 구조

```
webshare/
├── 웹서버 프로그램v4.py     # 메인 소스
├── webshare_config.json    # 설정
├── webshare_users.json     # 사용자 DB
├── .webshare_meta.json     # 태그/메모
├── WebSharePro.spec        # PyInstaller 스펙
└── README.md
```

---

## 📜 라이선스

MIT License
