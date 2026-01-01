# WebShare Pro v6.0

> 🌐 **웹 기반 파일 공유 서버 with PyQt6 GUI**

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-Server-green)
![PyQt6](https://img.shields.io/badge/PyQt6-GUI-purple)

**WebShare Pro**는 파이썬으로 제작된 올인원 파일 공유 서버입니다. 직관적인 웹 인터페이스와 편리한 트레이 아이콘 GUI를 제공합니다.

## ✨ 주요 기능

### 📂 파일 관리
- **웹 탐색기**: 파일 업로드, 다운로드, 삭제, 이름 변경, 폴더 생성
- **대용량 전송**: **청크 업로드(Chunk Upload)** 지원으로 5MB 단위 분할 전송 (대용량 파일 안정적 업로드)
- **압축**: 폴더 및 다중 파일을 ZIP으로 즉시 압축 다운로드/해제
- **휴지통**: 실수로 삭제한 파일 복원

### 🎬 미디어 스트리밍 (v6.0)
- **비디오**: 구간 이동(Seek)이 가능한 HTTP Range 스트리밍
- **오디오**: 폴더 내 음악 자동 감지 및 플레이리스트 생성
- **갤러리**: 이미지 라이트박스 뷰어 및 키보드 탐색

### 👥 다중 사용자 & 보안 (v6.0)
- **사용자 관리**: 관리자(Admin)가 사용자 계정 생성/관리 (헤더의 👥 아이콘)
- **권한 제어**: 사용자별 개인 폴더 자동 생성 (`_user_아이디`), 용량 제한(Quota) 설정
- **보안**: IP 화이트리스트, 관리자/게스트 비밀번호 분리, 5회 로그인 실패 시 차단

### 🛠️ GUI & 시스템
- **트레이 모드**: 닫기 버튼 시 트레이로 최소화 (백그라운드 실행)
- **DPI 대응**: 고해상도 모니터 완벽 지원
- **실시간 로그**: 접속 및 전송 현황 실시간 모니터링

---

## 🚀 설치 및 실행

### 1. 필수 라이브러리 설치
```bash
pip install flask pyqt6 pillow
```

### 2. 소스 코드 실행
```bash
python "웹서버 프로그램v4.py"
```

### 3. EXE 파일 빌드 (선택 사항)
`PyInstaller`를 사용하여 단일 실행 파일로 만들 수 있습니다.
```bash
pip install pyinstaller
pyinstaller WebSharePro.spec
```
빌드가 완료되면 `dist/WebSharePro.exe` 파일이 생성됩니다.

---

## 📁 프로젝트 구조

```
webshare2/
├── 웹서버 프로그램v4.py   # 메인 애플리케이션 소스
├── webshare_config.json  # 서버 설정 (자동 생성)
├── webshare_users.json   # 사용자 DB (자동 생성)
├── .webshare_uploads/    # 청크 업로드 임시 폴더
├── WebSharePro.spec      # PyInstaller 빌드 스펙
└── README.md             # 설명서
```

---

## ⌨️ 웹 단축키

| 단축키 | 동작 |
|--------|------|
| `Ctrl + U` | 파일 업로드 |
| `Ctrl + N` | 새 폴더 생성 |
| `Ctrl + A` | 전체 선택 |
| `Delete` | 선택 항목 삭제 |
| `F2` | 이름 변경 |
| `Wait...` | (갤러리) `←` `→` 키로 이미지 탐색 |

---

## 📝 사용 팁

1. **설정**: GUI의 [설정] 탭에서 포트, 공유 폴더, 비밀번호를 변경할 수 있습니다. (기본: `5000` 포트, `admin`/`guest` 암호)
2. **트레이**: 창을 닫아도 트레이 아이콘으로 계속 실행됩니다. 우클릭하여 '완전 종료' 할 수 있습니다.
3. **사용자 추가**: 관리자로 로그인 후 우측 상단의 [사용자 관리] 아이콘을 클릭하세요.

---

## 📜 라이선스

MIT License
