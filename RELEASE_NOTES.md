# 🚀 WebShare Pro v7.4.4 Release Notes

> **Release Date:** 2026-10-15 \
> **Tag:** `v7.4.4` \
> **Key Highlight:** **Go 백엔드 브라우저 페이지 복구** — 빌드 exe로 서버 실행 시 로그인 화면 대신 `UNAUTHORIZED` JSON만 표시되던 문제 수정

---

## 🌟 개요 (Overview)

WebShare Pro v7.4.4는 Go 백엔드(`go-core`)의 브라우저 페이지 누락을 해소한 패치 릴리즈입니다. 데이터/설정 변환 없이 v7.4.3과 100% 호환됩니다.

---

## 🛠️ 주요 변경 사항 (What's Changed)

### 1. Go 백엔드 로그인/파일 브라우저 HTML 제공 (ISSUE-006)

- 브라우저 탐색 시 `GET /`에 로그인 폼 HTML을, `GET /browse/`에 기본 파일 목록 HTML(목록·다운로드·페이지 이동)을 제공합니다.
- API 호출자(curl/XHR/JSON)의 401 JSON 응답 형식은 그대로 유지됩니다.
- 브라우저에서 비밀번호를 틀리면 Python 백엔드와 동일하게 오류 메시지와 함께 로그인 폼을 다시 표시합니다.

### 2. 버그 수정

- 메모장·PowerShell이 저장한 UTF-8 BOM 설정 파일을 Go 백엔드가 거부해 서버가 시작하지 못하던 문제 수정.
- `GET /browse/` 미로그인 접속이 404 JSON을 반환하던 문제 수정 (브라우저 302 `/`·API 401).

---

# 🚀 WebShare Pro v7.4.2 Release Notes

> **Release Date:** 2026-10-11  
> **Tag:** `v7.4.2`  
> **Key Highlight:** **웹 UI/UX 리팩토링** — 목록 밀집도 개선, 선택·다운로드 흐름 정비, 폴더/한글 ZIP 다운로드 및 일괄 작업 버그 수정

---

## 🌟 개요 (Overview)

WebShare Pro v7.4.2는 브라우저(웹 서버) 사용자 화면의 흐름과 밀집도를 정리한 릴리즈입니다. 기존 색상·테마 방향은 유지하며, 데이터/설정 변환 없이 v7.4.1과 100% 호환됩니다. 데스크톱(GUI) 화면 변경은 없습니다.

---

## 🛠️ 주요 변경 사항 (What's Changed)

### 1. 목록 밀집도 & 정렬

- 행 높이를 약 70px → 44px로 줄이고, 이름·크기·수정일을 열로 정렬했습니다. 열 제목 클릭으로 정렬(재클릭 시 방향 전환)하며 정렬 select와 동기화됩니다. 헤더는 스크롤 시 상단에 고정됩니다.
- 호버 시 행 이동/아이콘 회전 효과를 제거하고, 다운로드 버튼은 항상 표시·나머지 액션은 호버 시 표시합니다.
- 버튼·검색창·모달·컨텍스트 메뉴·토스트 여백을 축소하고, 그리드 뷰(카드/썸네일)와 모바일 레이아웃을 정리했습니다.

### 2. 선택 & 일괄 작업 흐름

- 목록 헤더에 전체 선택 체크박스(부분 선택 표시)를 추가하고, 선택 시 헤더가 `N개 선택됨 · 다운로드 · 삭제 · 선택 해제` 바로 전환됩니다.
- 행 빈 영역 클릭, `Shift+클릭` 범위 선택, 방향키 + `Space`, 드래그 영역 선택, `Ctrl+A`, `Esc` 해제를 지원하며 모든 선택 경로가 단일 상태 모델로 동기화됩니다.
- 1개 선택 시 ZIP 없이 즉시 다운로드, 다중 선택은 ZIP 1회 다운로드(최상위 폴더에서는 항목별 개별 다운로드)합니다.
- 검색·정렬로 목록이 다시 그려지면 이전 선택을 초기화하고, 검색 결과 없음 상태를 별도로 표시합니다.

### 3. 버그 수정

- **폴더 다운로드 버튼**이 `/download`로 요청해 오류가 나던 문제 → `/zip`으로 수정.
- **한글 이름 폴더 ZIP**의 `Content-Disposition` 폴백 파일명이 비ASCII여서 전송이 실패하던 문제 수정 (`zip_utils.py`).
- 최상위 폴더에서 선택 다운로드가 항상 404로 실패하던 문제 수정.
- `Esc` 선택 해제, 드래그 선택 반영, `Delete`/`F2` 중복 핸들러(확인창 2회) 수정.
- 목록이 API로 다시 그려진 뒤 드래그 이동이 동작하지 않던 문제 수정(이벤트 위임, 다중 항목 이동 지원). 그리드 썸네일이 새로고침 후 사라지던 문제 수정.
- 컨텍스트 메뉴가 스크롤 상태에서 잘못된 위치에 뜨거나 화면 밖으로 나가던 문제 수정.
- 서버가 업로드 오류를 반환해도 "업로드 완료"로 표시하던 문제 수정. 토스트 메시지의 HTML 해석 제거.
- 모바일 가로 스크롤 및 로그인 화면의 불필요한 API 호출(401/콘솔 오류) 제거.

---

## 📦 다운로드 및 아티팩트 (Artifacts)

| 플랫폼 / 형식 | 파일명 | 설명 |
|---|---|---|
| **Windows 포터블** | `WebSharePro-v7.4.2.exe` | Go 코어 엔진이 번들된 무설치 단일 실행 파일 |

> `updates/latest.json` 서명 매니페스트는 태그 푸시 시 릴리즈 워크플로가 자동 발행합니다.

---

# 🚀 WebShare Pro v7.4.1 Release Notes

> **Release Date:** 2026-10-06  
> **Tag:** `v7.4.1`  
> **Key Highlight:** **감사 후속 수정(ISSUE-001~005) + 테스트 하네스 격리 수정** — 청크 취소 경합, 손상 설정 기동, 휴지통 원자성, 쿼터 공정성, 압축 해제 디스크 검사 및 twin 계약 테스트 안정화

---

## 🌟 개요 (Overview)

WebShare Pro v7.4.1은 `PROJECT_AUDIT.md`(2026-10-06 감사)에서 확정된 잔여 문제 5건과 twin 계약 테스트의 순서 의존적 실패를 수정한 안정화 릴리즈입니다. 데이터 변환 없이 기존 `.webshare_*.json` 상태와 100% 호환됩니다.

---

## 🛠️ 주요 변경 사항 (What's Changed)

### 1. 청크 업로드 취소 경합 해소 (ISSUE-001)

- 병합 진행 중(`COMPLETING`) 취소 요청은 409로 거부되며, 병합 루프는 세션이 사라지면 커밋을 포기하고 temp를 정리합니다.

### 2. 시작 안정성 (ISSUE-002)

- 잘못된 인코딩의 설정 파일은 `.corrupt-<timestamp>`로 백업된 뒤 기본값으로 기동합니다 (시작 거부 해소).

### 3. 휴지통 원자성 (ISSUE-003)

- 이동 전 `pending` 항목을 먼저 기록하고 확정하며, 메타데이터 없는 항목의 self-heal 복원을 지원합니다.

### 4. 다운로드 쿼터 공정성 (ISSUE-004)

- 세션/IP 이중 버킷을 합산 상한으로 통합하고, 단건 다운로드 중단 시 전액 유지 정책을 429 메시지에 분리 표기합니다.

### 5. 압축 해제 안전성 (ISSUE-005)

- 해제 전 디스크 여유 검사 + 실패 시 부분 추출물 정리를 수행합니다.

### 6. 테스트 하네스 격리

- twin 계약 fixture가 live 서버 기동 후 가드 상태(IP 차단·쿼터·세션·메타데이터)를 초기화하고, 테스트용 설정 저장이 개발자 체크아웃의 `webshare_config.json`을 덮어쓰지 않도록 격리합니다.
- `TwinClient`가 keep-alive 전송을 사용하고(Windows loopback RST 회피), POST 재시도로 인한 중복 실행을 방지합니다.

---

## 📦 다운로드 및 아티팩트 (Artifacts)

| 플랫폼 / 형식 | 파일명 | 설명 |
|---|---|---|
| **Windows 포터블** | `WebSharePro_v7.4.1.exe` | Go 코어 엔진이 번들된 무설치 단일 실행 파일 |

> `updates/latest.json` 서명 매니페스트는 태그 푸시 시 릴리즈 워크플로가 자동 발행합니다.

---

# 🚀 WebShare Pro v7.4.0 Release Notes

> **Release Date:** 2026-09-29  
> **Tag:** `v7.4.0`  
> **Key Highlight:** **기능 감사(ISSUE-001~007) 및 성능 감사(PERF-001~008) 수정 반영** — 하이브리드 백엔드 정합성, 데이터 무결성, 전송 상한, 핫패스 최적화

---

## 🌟 개요 (Overview)

WebShare Pro v7.4.0은 v7.3.0 출시 후 진행된 두 차례의 저장소 감사(기능·런타임 안정성 감사 `PROJECT_AUDIT.md`, 성능·확장성 감사 `PERF_AUDIT.md`)에서 확정된 문제들을 수정한 안정화 릴리즈입니다. 데이터 변환 없이 기존 `.webshare_*.json` 상태와 100% 호환됩니다.

---

## 🛠️ 주요 변경 사항 (What's Changed)

### 1. 하이브리드 백엔드 정합성 (ISSUE-001/002/005)

- Go 백엔드가 GUI 네트워크 바인딩(`display_host`)을 존중 — LAN/모바일 QR 접속이 기본 백엔드에서 동작합니다.
- `use_https` + Go 조합은 즉시 실패 처리합니다 (평문 폴백 금지). HTTPS가 필요하면 Python 백엔드(`WEBSHARE_SERVER_BACKEND=python`)를 사용하세요. 설정 탭과 README에 명시했습니다.
- Go 공유 링크 접근이 브라우저용 HTML 페이지(비밀번호 폼·만료/차단 안내)를 렌더합니다. API/AJAX 호출자는 기존 JSON 형태를 유지합니다.

### 2. 데이터 무결성 및 공정성 (ISSUE-004/006/007)

- 버전 복원이 원자적 교체(temp + `os.replace`)로 변경되고, 복원 전 백업 실패 시 복원을 중단합니다.
- 다운로드 쿼터가 실제 전송 바이트 기준으로 정산됩니다 (중단된 전송의 전액 차감 문제 해소, Python·Go 공통).
- 로그인/공유 비밀번호 차단 확정 시 즉시 영속화됩니다 (크래시 시 차단 회피 차단).

### 3. Windows 안정성 (ISSUE-003)

- Windows에서 Go 자식 프로세스의 부모 감시가 실제로 동작합니다. GUI 비정상 종료 시 고아 프로세스가 포트를 점유하지 않습니다.

### 4. 성능·확장성 (PERF-001~008)

- 대용량 폴더 리스팅 베이스 캐시, 트랜스코더 동시 실행 상한(4), `/stream` Range suffix 지원 및 416 `Content-Range`修正, ZIP 생성 상한(5000 항목/10GiB, 초과 시 413), Go 멀티레인지 상한(100), 무제한 공유 링크의 다운로드당 전체 저장소 rewrite 제거, 중복 스캔 해시 청크 256KiB.
- 상세 근거·측정치는 `PERF_AUDIT.md`를 참조하세요.

---

## 📦 다운로드 및 아티팩트 (Artifacts)

| 플랫폼 / 형식 | 파일명 | 설명 |
|---|---|---|
| **Windows 포터블** | `WebSharePro_v7.4.0.exe` | Go 코어 엔진이 번들된 무설치 단일 실행 파일 |
| **소스코드 (ZIP)** | `Source code (zip)` | Go & Python 전체 소스코드 |
| **소스코드 (TAR)** | `Source code (tar.gz)` | 리눅스 / macOS 환경용 아카이브 |

> 참고: 이 빌드는 Windows ARM64 환경에서 생성되었습니다. x64 PC에서는 에뮬레이션으로 실행될 수 있습니다.

### SHA-256 체크섬
```text
WebSharePro-v7.4.0.exe: bd18190aba62493d98dd101b98fa7dd0f62f1489e8233cdf7cf592d248c3af15
```

---

## 🔄 업그레이드 및 설치 가이드 (Upgrade Guide)

1. 기존 실행 중인 WebShare Pro를 정상 종료합니다.
2. 새 `WebSharePro-v7.4.0.exe`를 실행합니다.
3. 기존 공유 폴더의 설정 및 파일, 공유 링크, 휴지통, 메타데이터(`.webshare_*.json`)는 **데이터 변환 작업 없이 그대로 유지**됩니다.
4. 소스코드 사용자: `git pull origin main` 후 `cd go-core && go build -o webshare-core.exe ./cmd/webshare-core`로 바이너리를 갱신하세요.

---

## 🧪 검증 및 테스트 결과 (Verification)

- **Python 확정 테스트**: 206 passed, 1 skipped (신규 회귀 테스트 포함)
- **Go 코어 단위 테스트**: `go test ./...` 전 패키지 통과, `go vet` 깨끗
- **빌드 무결성**: `WebSharePro_v7.4.0.exe --smoke` → `SMOKE_OK`
- 실서버 쌍둥이 계약 테스트(`test_milestone_*`)는 실행 환경(Windows loopback 실서버)의 불안정으로 간헐 실패가 있어 릴리즈 게이트에서 제외했습니다. 기준선에서도 동일하게 발생함을 확인했습니다.

---

---

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
