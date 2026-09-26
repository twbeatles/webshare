# 🚀 WebShare Pro v7.3.0 Release Notes

> **Release Date:** 2026-09-26  
> **Tag:** `v7.3.0`  
> **Key Highlight:** **Go 네이티브 코어 엔진 탑재 (Milestone J 완료)** 및 **하이브리드 자동 장애 복구(Auto Fallback)** 아키텍처 적용

---

## 🌟 개요 (Overview)

WebShare Pro v7.3.0은 성능과 신뢰성 모두에서 획기적인 도약을 이뤄낸 메이저 업데이트입니다.  
기존 Python/Flask 기반 서버 코어를 **Go 언어로 완전 재작성한 고성능 네이티브 코어(`go-core`)**로 전환(Milestone J)하여, 기가바이트(GB) 단위 대용량 파일 전송 속도와 동시 접속 처리량을 대폭 향상시켰습니다.

동시에, 만약의 환경 문제로 Go 엔진 구동에 문제가 생길 경우 사용자 개입 없이 **1초 이내에 Python 백엔드로 무중단 자동 전환(Auto Fallback)**되는 이중 안전망을 갖추었습니다.

---

## ⚡ 주요 변경 사항 (What's New)

### 1. ⚡ 고성능 Go 네이티브 서버 코어 기본 탑재 (Default Backend: Go)
- **Goroutine 기반 고동시성 I/O**:
  - Python WSGI 단일 스레드/프로세스 구조 대비 수백 개의 동시 스트리밍 및 파일 다운로드 요청을 극도로 낮은 메모리 점유율로 처리합니다.
- **RFC 7233 멀티파트 바이트 레인지 (206 Partial Content) 완벽 지원**:
  - 다중 스레드 다운로드 가속기 및 대용량 비디오/오디오 시크(Seek) 탐색 시 버퍼링 없이 즉각 응답합니다.
- **NFC 유니코드 파일명 정규화 (`golang.org/x/text`)**:
  - macOS(NFD)와 Windows/Linux(NFC) 간 한글 및 특수문자 파일명 자모 분리 현상을 원천 방지합니다.
- **Twin-Server Contract Parity 달성**:
  - 모든 사용자 인증, CSRF, 세션, 공유 링크, 다운로드 쿼터, 감사 로그(`.webshare_*.json`)가 Python 레퍼런스 구현체와 100% 동일한 스키마로 상호 호환됩니다.

### 2. 🛡️ 무중단 자동 장애 복구 (Resilient Auto Fallback)
- **1초 내 자동 전환**:
  - Go 엔진 실행 파일 누락, 환경 권한 문제, 비정상 크래시 발생 시 프로세스 수퍼바이저([`GoServerProcess`](file:///c:/twbeatles-repos/webshare/webshare_app/server/go_process.py))가 즉시 내장 Python 백엔드로 1초 만에 자동 전환합니다.
- **런타임 백엔드 강제 제어 옵션**:
  - `WEBSHARE_SERVER_BACKEND=go` (기본값)
  - `WEBSHARE_SERVER_BACKEND=python` (기존 Python 레거시 엔진 유지 시)
  - `WEBSHARE_CORE_BIN=/path/to/binary` (별도 빌드된 바이너리 지정 가능)

### 3. 📦 파일 관리 및 미디어 스트리밍 고도화
- **최대 10GB 청크 분할 업로드**: 업로드 도중 네트워크가 끊겨도 마지막 완료 청크부터 즉시 재개
- **디스크 공간 사전 예약(Preflight Reserve)**: 업로드 전 서버 잔여 용량을 확인하여 디스크 고갈 사고 원천 차단
- **동영상 HLS 실시간 스트리밍 & 문서 뷰어**: MKV/AVI/MP4 HLS 트랜스코딩, 오디오 연속 재생, PDF/Word/Excel 인라인 뷰, 30+ 프로그래밍 언어 코드 편집기 내장
- **휴지통 및 버전 롤백**: 삭제 파일 원클릭 복원, 수정 시 최대 5개 이전 버전 자동 보관

### 4. 🔒 보안 및 관리자 기능 강화
- **보안 공유 링크 (Share Link)**: 유효 기간(1시간~무제한), 접근 비밀번호, 다운로드 횟수 제한(예: 3회 후 자동 파기)
- **세분화된 RBAC 권한 제어**: 폴더별 게스트 사용자 대상 `Read`, `Write`, `Delete` 권한 분리 적용
- **SHA-256 중복 파일 검사기**: 중복된 대용량 파일 탐색 및 원클릭 일괄 정리로 디스크 용량 확보
- **Google Drive 클라우드 양방향 동기화**: 안전한 OAuth 인증 및 충돌 방지 정책(덮어쓰기/건너뛰기/이름변경)
- **실시간 감사 로그 (Audit Log) & UPnP 자동 포트포워딩** 지원

---

## 📦 다운로드 및 아티팩트 (Artifacts)

| 플랫폼 / 형식 | 파일명 | 설명 |
|---|---|---|
| **Windows 포터블** | `WebSharePro-v7.3.0.exe` | Go 코어 엔진이 번들된 무설치 단일 실행 파일 |
| **소스코드 (ZIP)** | `Source code (zip)` | Go & Python 전체 소스코드 |
| **소스코드 (TAR)** | `Source code (tar.gz)` | 리눅스 / macOS 환경용 아카이브 |

### SHA-256 체크섬
```text
WebSharePro-v7.3.0.exe: 995d30dcad0f0843597e250495eec4a442158e97ef1bdc5905bf152650f1b4ab
```

---

## 🔄 업그레이드 및 설치 가이드 (Upgrade Guide)

### 기존 v7.2.x 사용자
1. 기존 실행 중인 WebShare Pro를 정상 종료합니다.
2. 새 `WebSharePro-v7.3.0.exe`를 실행합니다.
3. 기존 공유 폴더의 설정 및 파일, 공유 링크, 휴지통, 메타데이터(`.webshare_*.json`)는 **데이터 변환 작업 없이 100% 그대로 유지**됩니다.
4. (또는 데스크톱 GUI 상단의 **[🔄 업데이트 확인]** 버튼을 눌러 원클릭 무중단 자동 업데이트를 진행할 수 있습니다.)

### 소스코드 빌드 사용자
```bash
git pull origin main
# Go 코어 바이너리 빌드
cd go-core
go test ./...
go build -o webshare-core.exe ./cmd/webshare-core
cd ..
# 실행
python main.py
```

### Docker 사용자
```bash
docker compose pull
docker compose up -d
```

---

## 🧪 검증 및 테스트 결과 (Verification)

- **Go 코어 단위 테스트**: `go test ./...` 전 패키지 통과 (Pass)
- **Python 회귀 테스트**: `pytest` 161 passed, 1 skipped
- **Twin Contract Parity 테스트**: Python ↔ Go API 명세 일치 검증 100% 통과
- **보안 검증**: PBKDF2 해시, CSRF 토큰, IP 무차별 대입 차단, Path Traversal 방지 검증 통과
- **패키징 스모크 테스트**: `WebSharePro-v7.3.0.exe --smoke` 정상 통과 (`SMOKE_OK WebShare Pro`)

---

<div align="center">
  <sub>WebShare Pro is an open-source project licensed under the MIT License.</sub>
</div>
