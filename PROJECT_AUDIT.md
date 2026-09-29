# Project Audit

> **작성일:** 2026-09-28
> **대상:** WebShare Pro v7.3.0 (Go + Python 하이브리드, PyQt6 GUI, Flask 폴백)
> **관점:** 기능 구현·런타임 안정성 (코드는 수정하지 않음)
> **이전 리포트 대체:** 기존 `PROJECT_AUDIT.md`(2026-09-26, "종합 위험도 Low")는 본 감사와 결론이 다르므로 본 문서로 대체한다. 기존 문서의 낙관적 평가("Twin-Server 정합성 100%", "매우 우수 및 안전")는 아래에서 반증되는 범위에서 더 이상 유효하지 않다.

## 1. Executive Summary

- **프로젝트 전체 상태:** 핵심 파일 공유 흐름(업로드/다운로드/휴지통/공유 링크/권한)은 Python 백엔드 기준으로 견고하게 구현되어 있다. 경로 검증(`validate_path` + `ensure_path_access`), 공유 링크 다운로드 횟수 원자적 예약, 청크 업로드 세션 소유권·용량 제한, ZIP Slip/Zip Bomb 방어, 감사 로그 원자적 쓰기 등 보안·무결성 장치가 실제로 존재하고 관련 테스트도 통과한다.
- **전체 위험도:** **Needs Work (High Risk에 준함)** — 데이터 평면 자체보다 **하이브리드 전환 경계(Go 기본 백엔드)** 에 결함이 집중되어 있다. GUI가 약속하는 LAN 바인딩·HTTPS가 기본(Go) 백엔드에서 조용히 무시되고, Windows(주 플랫폼)에서 부모 프로세스 감시가 비활성화되어 있으며, 버전 복원 경로가 비원자적 복사로 사용자 파일을 손상시킬 수 있다.
- **가장 중요한 문제 3~5개:**
  1. [ISSUE-001] Go 백엔드가 GUI 네트워크 바인딩(`display_host`)을 무시하고 항상 `127.0.0.1`에 바인딩 — LAN/모바일 QR 접속이 기본 백엔드에서 동작하지 않음 (High, Confirmed).
  2. [ISSUE-002] Go 백엔드에 TLS 리스너가 없음 — HTTPS 설정이 조용히 평문 HTTP가 되고 Secure 쿠키 때문에 로그인이 깨질 수 있음 (High, Confirmed).
  3. [ISSUE-003] Windows에서 Go 자식 프로세스 부모 감시 비활성화 — GUI 비정상 종료 시 고아 프로세스가 포트 점유, 재시작 실패 (High, Confirmed).
  4. [ISSUE-004] 버전 복원이 비원자적 `shutil.copy2`로 라이브 파일을 덮어씀 — 복원 중 크래시 시 파일 손상, 백업 실패도 무시됨 (High, Confirmed).
  5. [ISSUE-005] 기본(Go) 백엔드의 공유 링크 접근이 HTML 폼 대신 JSON을 반환 — 외부 수신자의 비밀번호 입력 UX가 깨짐 (High, Confirmed).
- **데이터 손상/유실 가능성 여부:** 있음. ISSUE-004(복원 중 손상)가 직접적이며, 감사·쿼터 상태의 크래시 손실(ISSUE-006)은 보안 가시성·요금제 공정성에 영향을 준다. 대량 업로드 자체는 원자적 저장(`atomic_save_upload`, 청크 병합 시 temp+`os.replace`)으로 잘 보호된다.
- **가장 먼저 수정해야 할 영역:** `webshare_app/server/__init__.py` + `go_process.py`의 바인딩/TLS 전달, Go `server.Serve`의 TLS 지원 또는 HTTPS 옵션 비활성화, Windows 고아 프로세스 대책, 버전 복원의 원자적 교체.

## 2. Project Understanding

### 프로젝트 목적

로컬 폴더를 개인 클라우드처럼 공유하는 크로스플랫폼 파일 서버. PyQt6 데스크톱 관리자가 `GoServerProcess`(기본) 또는 Flask 스레드(폴백) 중 하나를 띄워 웹 파일 관리자, 청크 업로드, HLS 스트리밍, 보안 공유 링크, RBAC, 휴지통/버전, Google Drive 동기화를 제공한다.

### 주요 entrypoint

- `main.py` → `main()`: `--smoke` / `--apply-update` 분기, 그 외 `ensure_runtime_initialized()` 후 PyQt6 GUI → Tkinter 폴백 → Flask 단독 실행 순으로 시도.
- `webshare_app/server/__init__.py::start_server`: `WEBSHARE_SERVER_BACKEND`(기본 `go`)에 따라 Go 자식 프로세스 또는 Python 스레드 시작. Go 실패 시 Python으로 폴백.
- `webshare_app/app/factory.py::create_app`: Flask 앱 팩토리(세션 쿠키, CSRF, IP 게이트, 감사·쿼터 훅, 라우트 등록).
- `go-core/cmd/webshare-core/main.go`: Go `serve` 진입점(설정 로드 → 라우트 등록 → `Serve` → 정상 종료 시 `FlushState`).
- `scripts/apply_update.py` (`--apply-update` 경유): Ed25519 검증된 업데이트 원자적 교체 + 스모크 + 롤백.

### 핵심 모듈

- 인증/보안: `webshare_app/security/auth.py`, `webshare_app/security/ip_blocker.py`, `webshare_app/security/csrf.py`, `webshare_app/security/permissions.py`, Go 대응 `go-core/internal/auth/*`, `go-core/internal/permission/*`.
- 파일 평면: `webshare_app/routes/file_routes/*` (browse/download/mutation), `webshare_app/routes/upload_routes/*` (init/transfer/finalize), `webshare_app/services/upload_service.py`, Go 대응 `go-core/internal/handlers/files.go`, `upload.go`, `mutate/*`.
- 공유 링크: `webshare_app/routes/share_routes.py` + `webshare_app/services/share_service.py` + `webshare_app/features/share_links_store.py`, Go 대응 `go-core/internal/share/*`, `go-core/internal/handlers/share.go`.
- 상태 영속화: `webshare_app/core/persistence.py` + `webshare_app/core/app_paths.py::atomic_write_json`, `features/audit_log.py`, `features/runtime_state.py`, `features/job_store.py`, Go 대응 `internal/audit`, `internal/quota`, `internal/share/persist.go`.
- 휴지통/버전: `webshare_app/features/trash.py`, `webshare_app/utils/helpers/file_versions.py`, `webshare_app/routes/metadata_routes.py`.
- 업데이트: `webshare_app/core/update_installer.py`, `webshare_app/core/update_manifest.py`, GUI `actions/update_actions.py`.
- 프로세스 관리: `webshare_app/server/go_process.py`, `webshare_app/server/thread.py`, `webshare_app/server/cleanup.py`, `webshare_app/server/bootstrap.py`.

### 데이터 저장 방식

DB 없음. 공유 폴더 내 dotfile JSON(`.webshare_share_links.json`, `.webshare_audit.json`, `.webshare_download_tracker.json`, `.webshare_login_attempts.json`, `.webshare_trash.json`, 권한/메타/작업 ledger)과 실파일(`.webshare_trash/`, `.webshare_versions/`, `.upload_temp/`, `.webshare_transcode/`)로 영속화. Python은 `atomic_write_json`(동일 디렉터리 temp + `os.replace`) + 파일별 직렬화 락, Go는 `atomicWriteJSON`(동일 패턴)을 사용한다. 스키마는 양쪽이 의도적으로 호환되도록 설계됨.

### 외부 의존성

Flask/Werkzeug, PyQt6, Pillow, cryptography, cachetools, orjson, watchdog, ffmpeg(별도 바이너리, HLS용), Google Drive OAuth(동기화 사용 시), Updater 경로의 GitHub Releases. 감사 과정에서 추가 의존성은 설치하지 않았다.

### 핵심 실행 흐름

`GUI 토글 → server.start_server → [Go: go_process.start(binary serve --host 127.0.0.1 --port …) → /readyz 폴백 감시 | Python: ServerThread(make_server(display_host, port)) + ensure_runtime_initialized + 주기 정리] → Flask before_request(IP 화이트리스트/차단·세션 타임아웃·CSRF) → Handler(validate_path + ensure_path_access + RBAC) → Core(원자적 저장/예약/감사) → JSON 영속화(스냅샷+원자적 교체) → Result`

`업로드(청크): POST /upload/chunk/init(검증·디스크 예약·세션 생성) → POST /upload/chunk/<id>(소유권·만료·용량 상한 내 저장) → POST …/complete(청크 집합 검증→temp 병합→사이즈 검증→os.replace→세션 완료) → 감사`

`공유 링크: POST /share/create(admin, 검증·해시·영속) → GET/POST /share/<token>(만료·횟수·비밀번호·쿼터·예약 순) → 파일/ZIP 스트리밍(실패 시 예약 롤백)`

## 3. Audit Coverage & Limitations

### 실제 확인한 주요 모듈

- 진입·구성: `main.py`, `server.py`, `config.py`, `webshare_app/server/*`, `webshare_app/app/factory.py`, `go-core/cmd/webshare-core/main.go`, `go-core/internal/server/server.go`.
- 보안 경계: `utils/file_utils.py`(validate/safe_filename/IP), `utils/request_policy.py`, `security/*`, `routes/main_routes.py`(로그인), `routes/share_routes.py` + `services/share_service.py`.
- 데이터 평면: `routes/file_routes/*`, `routes/upload_routes/*`, `services/upload_service.py`, `utils/helpers/download_quota.py`, `utils/helpers/atomic_io.py`, `utils/zip_utils.py`, `features/trash.py`, `utils/helpers/file_versions.py`, `routes/metadata_routes.py`, `routes/media_routes/editing.py`.
- 상태·종료: `core/persistence.py`, `core/app_paths.py`, `features/audit_log.py`, `features/runtime_state.py`, `features/job_store.py`, `features/share_links_store.py`, `server/cleanup.py`, `server/thread.py`, Go `handlers/app.go`, `audit/audit.go`, `quota/*`, `share/persist.go`.
- 위험 명령: `features/transcoder.py`(ffmpeg/taskkill), `core/update_installer.py`, `server/go_process.py`.

### CodeGraph로 분석한 호출 관계

CodeGraph MCP(`codegraph_explore`)를 우선 사용해 entrypoint→핸들러→코어→영속화 흐름과 caller/callee를 추적했다. 확인한 관계: `create_app → register_routes → {download, upload, share, mutate, media, metadata}`, `start_server → GoServerProcess.start/_wait_ready/shutdown ↔ /_control/shutdown`, `reserve_download_quota ↔ rollback_download_quota` 호출점(다운로드·공유 파일/ZIP 분기), `create_share_link → save_share_links`, `access_share_link → _reserve_share_download/_rollback_reserved_download`, `complete_chunk_upload → _finish_upload_session_success/_cleanup_upload_session`, `log_audit → flush_audit_log_if_dirty → save_audit_log`, `validate_path/ensure_path_access`의 전역 호출 분포, Go `requireAuth/loadSession/refreshSession/checkCSRF/csrfExempt`, `handleShareAccess → serveShareFile/serveShareDir`, `FlushState → {Blocks, Quota, Shares, Audit}`.

### 실행한 테스트

- `python -m pytest tests/test_upload_integrity.py tests/test_permissions_enforcement.py tests/test_download_limits.py` → **14 passed**.
- `python -m pytest tests/test_security_hardening_724.py tests/test_security_policies.py` → **19 passed**.
- `go test ./internal/share/... ./internal/quota/... ./internal/upload/...` (in `go-core`) → **3 packages ok**.
- 전체 스위트(`pytest -q`, `go test ./...`)는 실행하지 않았다(시간·범위 제한). 위 결과 외의 테스트 통과는 주장하지 않는다.

### 확인하지 못한 환경/외부 서비스

실서버 기동(E2E), PyQt6 GUI 실조작, Windows/macOS 실기, ffmpeg 실트랜스코딩, Google Drive OAuth 동기화, UPnP 실라우터, 리버스 프록시, 업데이트 실다운로드(Ed25519 실서명 검증 런타임), PyInstaller 번들 EXE를 실행하지 않았다. 브라우저에서 공유 링크 HTML/JSON 차이를 직접 재현하지는 않았다(코드 판독으로 확정).

### CodeGraph 또는 분석상의 한계

- 일부 파일이 인덱스 동기화 pending 상태로 표시되어 해당 심볼은 원문 재독·직접 열람으로 교차 확인했다.
- `muse.search`가 일부 패턴에서 결과를 반환하지 않아 PowerShell 범위 스캔(`Get-ChildItem | Select-String`)으로 보완했다.
- 동시성·크래시 중간 상태는 정적 추론 + 기존 테스트가_cover_하는 범위로 판단했으며, 실제 장애 주입(킬, 전원 차단, 프록시)은 수행하지 않았다.

## 4. High-Risk Issues

### [ISSUE-001] Go 기본 백엔드가 GUI 네트워크 바인딩을 무시하고 loopback에만 바인딩

- **위치:** [webshare_app/server/__init__.py](/absolute/path/webshare_app/server/__init__.py) `start_server` (host `"127.0.0.1"` 하드코딩) → [webshare_app/server/go_process.py](/absolute/path/webshare_app/server/go_process.py) `GoServerProcess.start` (`base_url`도 `127.0.0.1` 고정) → [go-core/cmd/webshare-core/main.go](/absolute/path/go-core/cmd/webshare-core/main.go) (`--host`가 `cfg.DisplayHost`를 덮어씀). 대조군: [webshare_app/server/thread.py](/absolute/path/webshare_app/server/thread.py) `ServerThread.run`은 `conf.get('display_host')`를 바인딩에 사용.
- **우선순위:** High
- **신뢰도:** Confirmed
- **문제:** GUI 설정에서 `0.0.0.0`(또는 LAN IP)을 선택해도 기본 Go 백엔드는 loopback에 바인딩된다. GUI는 LAN URL·QR을 표시하므로 사용자는 모바일 접속이 가능한 것처럼 보인다.
- **발생 조건:** 기본값(`WEBSHARE_SERVER_BACKEND=go`) + 설정에서 LAN 바인딩 선택 + 동일 네트워크 모바일/외부 접속 시도. 항상 재현되는 결정적 동작이다.
- **영향:** 광고된 핵심 시나리오(모바일 QR/PWA, LAN 공유) 실패. 사용자는 네트워크·방화벽 문제로 오진하고, 우회책으로 `0.0.0.0` 재설정·재시작을 반복해도 해결되지 않는다.
- **근거:** `start_server`는 `go.start(host="127.0.0.1", port=…)`로 고정 호출하고, Go 측은 플래그가 오면 설정값을 덮어쓴다. Python 스레드는 같은 설정값을 존중하므로 백엔드 간 동작이 갈린다.
- **반증 확인:** 상위 caller 분기(폴백)가 이 문제를 막지 못한다. Go 바이너리가 정상이면 폴백이 발생하지 않아 Python 경로를 타지 않는다. 헬스체크(`/readyz`)는 loopback 기준이라 바인딩 문제를 감지하지 못한다. GUI 표시 URL은 설정값 기준이라 실제 바인딩과 무관하게 LAN URL을 보여준다.
- **호출/영향 범위:** `ServerActionsMixin.toggle_server → start_server → GoServerProcess.start → webshare-core serve`. 영향: GUI 네트워크 설정, QR/PWA, UPnP·외부 공개 문서 흐름 전체.
- **권장 수정 방향:** `conf.get('display_host')`를 Go 기동 인자로 전달하고 `base_url`/헬스체크 호스트를 분리(loopback 프로브 + 실제 바인딩 표시). `0.0.0.0` 전달 시 외부 노출 경고를 `log_deployment_warnings`와 동일 기준으로 표시.
- **필요한 회귀 테스트:** display_host=`0.0.0.0`/LAN IP로 `start_server` 호출 시 Go 기동 argv에 동일 `--host`가 전달됨을 단언하는 unit 테스트. loopback 표시 URL과 실제 리슨 소켓이 일치함을 확인하는 integration 테스트(소켓 바인드 검증, 실서버 미기동 가능하도록 argv·설정 수준에서 검증).

### [ISSUE-002] Go 백엔드에 TLS 리스너가 없어 HTTPS 설정이 조용히 평문으로 동작

- **위치:** [go-core/internal/server/server.go](/absolute/path/go-core/internal/server/server.go) `Serve` (`http.Serve`만 사용, TLS 분기 없음). 설정 전달: GUI `use_https` → 공용 설정 → Go `UseHTTPS`(쿠키 Secure 플래그에만 사용).
- **우선순위:** High
- **신뢰도:** Confirmed
- **문제:** HTTPS를 켜도 Go 백엔드는 평문 HTTP로 리슨한다. 동시에 세션 쿠키에 `Secure`가 붙으므로 브라우저가 평문 연결에서 쿠키를 보내지 않아 로그인이 깨지거나(리다이렉트 루프) 사용자는 암호화 중이라고 착각한다.
- **발생 조건:** 기본 Go 백엔드 + GUI/설정에서 HTTPS 사용 체크. 결정적이다.
- **영향:** 보안 설정의 완전한 무력화 + 로그인 장애. 외부 공개 문서(Q2 포트포워딩 안내)와 결합되면 평문 관리자 세션이 외부에 노출될 수 있다.
- **근거:** `Serve`에 `ServeTLS`/인증서 로딩이 없고, 코드베이스 내 `ListenAndServeTLS`·인증서 경로가 존재하지 않는다. Python 측은 `ssl_ctx='adhoc'`으로 실제 TLS를 수행하므로 백엔드 간 보안 속성이 갈린다.
- **반증 확인:** 폴백이 보호하지 못한다. Go가 정상 기동하는 한 Python TLS 경로를 타지 않으며, `/readyz`·GUI 상태는 모두 정상을 표시한다. `UseHTTPS`가 쿠키에만 쓰인다는 점이 오히려 증상을 악화시킨다.
- **호출/영향 범위:** `save_settings(use_https) → start_server(use_https 무시, Go 분기) → Serve → SetSessionCookie(..., Secure=UseHTTPS)`. 영향: 로그인(`/`, `/browse`), 전 세션 쿠키, 배포 경고의 전제.
- **권장 수정 방향:** 둘 중 하나를 즉시 선택. (a) Go에 TLS 리스너 추가(adhoc 인증서 생성·로드) 또는 (b) Go 백엔드 선택 시 HTTPS 옵션을 비활성화하고 "Python 백엔드 전용"임을 GUI·문서에 명시. (b)가 빠르며 안전하다.
- **필요한 회귀 테스트:** `use_https=true` + Go 백엔드 조합에서 기동이 거부되거나 TLS 리스너가 실제로 동작함을 단언하는 테스트. Secure 쿠키가 평문 리스너와 함께 설정되지 않음을 검증하는 설정-기동 integration 테스트.

### [ISSUE-003] Windows에서 Go 부모 감시가 비활성화되어 고아 프로세스가 포트를 점유

- **위치:** [go-core/cmd/webshare-core/main.go](/absolute/path/go-core/cmd/webshare-core/main.go) `watchParent` (Windows 분기에서 즉시 return), [webshare_app/server/go_process.py](/absolute/path/webshare_app/server/go_process.py) (`--parent-pid` 전달은 하지만 Windows에서 감시자가 없음).
- **우선순위:** High
- **신뢰도:** Confirmed
- **문제:** 주 플랫폼(Windows EXE 배포)에서 GUI가 크래시·강제 종료되면 Go 자식이 살아남아 포트·파일을 점유한다. 다음 시작은 바인드 실패 → Python 폴백도 같은 포트에서 실패 → 사용자는 재부팅 전까지 서버를 띄울 수 없다.
- **발생 조건:** Windows + Go 백엔드 실행 중 GUI 프로세스 비정상 종료(크래시, 작업 관리자 종료, 업데이트 중 충돌). 정상 종료(`stop_server`→`/_control/shutdown`)는 영향 없음.
- **영향:** 단일 사용자 데스크톱 앱의 가용성 장애. 공유 폴더 락·부분 ZIP·청크 temp가 정리되지 않은 채 남을 수 있다.
- **근거:** 코드가 Windows를 명시적으로 skip하며 이유(Win32 signal-0 부재)를 주석으로 밝힌다. Python 측은 데몬 스레드라 부모 종료 시 함께 죽지만 Go는 독립 프로세스라 비대칭이다.
- **반증 확인:** 정상 종료 경로·`shutdown()`·`_terminate()`는 살아 있으나 모두 살아 있는 부모를 전제로 한다. Windows 작업 스케줄러·서비스 차원의 보호 장치는 레포에 없다. 기존 `test_go_process.py`는 정상 기동/종료 위주라 크래시 경로를 커버하지 않는다.
- **호출/영향 범위:** `toggle_server/stop_server ←→ GoServerProcess ↔ webshare-core serve --parent-pid`. 영향: 시작/중지, 업데이트 헬퍼의 바이너리 교체(점유된 실행 파일 교체 실패 가능), 포트 충돌 메시지 경로.
- **권장 수정 방향:** Windows용 부모 감시 구현(Win32 `OpenProcess`+`WaitForSingleObject` 폴링 또는 Job Object에 자식 편입) + 시작 시 stale 고아 감지(동일 포트 리슨 프로세스가 자신의 이전 자식인지 확인 후 정리/경고). 당장 어렵다면 시작 실패 메시지에 고아 프로세스 의심 안내를 추가.
- **필요한 회귀 테스트:** Windows 조건부 unit 테스트(감시 루프가 부모 핸들 종료 시 `stop()`을 호출함, 모킹). 시작 시 포트 점유 원인이 살아 있는 고아 자식일 때 명확한 에러(`고아 프로세스`)를 반환함을 단언하는 테스트.

### [ISSUE-004] 버전 복원이 비원자적 복사로 라이브 파일을 덮어써 크래시 시 손상 가능

- **위치:** [webshare_app/routes/metadata_routes.py](/absolute/path/webshare_app/routes/metadata_routes.py) `restore_version` (`shutil.copy2(version_path, full_target)`), [webshare_app/utils/helpers/file_versions.py](/absolute/path/webshare_app/utils/helpers/file_versions.py) `create_file_version` (실패를 로그만 남기고 삼킴).
- **우선순위:** High
- **신뢰도:** Confirmed
- **문제:** 편집 저장(`save_content`→`atomic_write_bytes`)과 달리 복원은 대상 파일을 직접 truncate하면서 복사한다. 복사 중간 크래시·전원 차단 시 원본도 백업본도 아닌 반쯤 쓴 파일이 남는다. 더욱이 복원 전 백업(`create_file_version`)이 실패해도 복원이 강행되어 마지막 복구 수단마저 없을 수 있다.
- **발생 조건:** 버전 복원 중 프로세스 크래시/전원 차단/디스크 가득 참. 대용량 파일·느린 디스크에서 창이 커진다. 조건은 드물지만 결과는 영구적이다.
- **영향:** 사용자 데이터 손상. "롤백이 안전망"이라는 기능 전제와 정면으로 충돌한다.
- **근거:** 코드상 `copy2` 직접 덮어쓰기 + 백업 실패 무시(내부 try/except 후 호출자에게 성공/실패를 알리지 않음)를 확인. 대조군으로 같은 파일의 편집 경로는 원자적 교체를 사용하므로 의도된 불일치가 아니라 구현 누락으로 판단.
- **반증 확인:** `validate_path`·권한 검사는 경로 탈출을 막을 뿐 쓰기 원자성과 무관하다. 버전 파일 자체는 무결하나 손상되는 것은 라이브 타깃이다. 트랜잭션·DB·저널 등 다른 보호 장치는 없다(plain 파일 복사).
- **호출/영향 범위:** `POST /versions/restore → create_file_version → copy2`. 영향: 버전 관리·인라인 에디터 복원 흐름, 대용량 텍스트/코드 파일.
- **권장 수정 방향:** 복원을 temp 복사 + `os.replace` 원자적 교체로 변경하고, `create_file_version` 실패 시 복원을 중단(에러 반환)하거나 최소한 경고를 응답에 포함. 복원 전 백업본명을 응답에 포함해 수동 복구 가능하게 한다.
- **필요한 회귀 테스트:** `copy2` 중간 실패(주입) 시 원본 바이트가 그대로 보존됨을 단언하는 unit 테스트. `create_file_version` 실패(디스크 권한 모킹) 시 복원이 거부됨을 단언하는 테스트. 원자적 교체 후 버전 목록에 복원 전 스냅샷이 존재함을 확인하는 integration 테스트.

### [ISSUE-005] 기본 백엔드의 공유 링크 비밀번호·만료 화면이 JSON으로 깨짐

- **위치:** [go-core/internal/handlers/share.go](/absolute/path/go-core/internal/handlers/share.go) `handleShareAccess`/`shareFail` (전부 JSON), 대조군 [webshare_app/routes/share_routes.py](/absolute/path/webshare_app/routes/share_routes.py) (HTML 템플릿 `share_password.html`/`share_expired.html`). 코드 내 주석("Go core has no template engine yet")이 스스로 인정.
- **우선순위:** High
- **신뢰도:** Confirmed
- **문제:** 외부 수신자(비로그인)가 공유 링크를 열면 비밀번호 폼·만료 안내 대신 raw JSON(`need_password`, `success:false`)이 보인다. 모바일·비기술 수신자는 링크가 고장 난 것으로 인식한다.
- **발생 조건:** 기본 Go 백엔드 + 비밀번호 보호 또는 만료/횟수 초과 링크 접근. 결정적이다.
- **영향:** 광고된 "보안 공유 링크" 기능의 외부 UX 붕괴. 브라우저가 페이지를 렌더하지 않으므로 비밀번호 입력 자체가 불가능해 보호 링크가 사실상 사용 불가.
- **근거:** `handleShareAccess`의 모든 실패·비밀번호 분기가 `shareFail`/`writeJSON`이며, 템플릿 렌더 호출이 존재하지 않는다. Python 측은 동일 분기에서 HTML을 렌더한다.
- **반증 확인:** 프레임워크가 메워주지 않는다(Go에 템플릿 엔진 자체가 없음). 폴백은 Go 정상 시 발생하지 않는다. 기존 parity 테스트(`test_milestone_*`)는 API 스키마 위주라 HTML 렌더를 검증하지 않는다.
- **호출/영향 범위:** `GET/POST /share/<token>` (인증 불필요 공개 경로). 영향: 외부 공유 수신자 전체, 만료·차단·쿼터 메시지 포함.
- **권장 수정 방향:** Go에 최소 HTML 렌더(비밀번호 폼·만료 페이지) 추가 또는 공유 경로만 Python 백엔드로 라우팅하는 documented 예외 처리. 당장은 README 공유 링크 섹션에 "Go 백엔드에서 비밀번호 링크는 JSON 응답" 제약을 명시.
- **필요한 회귀 테스트:** 백엔드별 공유 링크 접근 contract 테스트(비밀번호 링크 GET → HTML 폼, 만료 → 만료 페이지, JSON API가 아님). Go/Python 동일 입력에 대한 응답 `Content-Type`·본문 스냅샷 비교 테스트.

### [ISSUE-006] 다운로드 쿼터가 실패·중단된 전송에도 전액 차감되어 정상 사용자가 잠김

- **위치:** [webshare_app/routes/file_routes/download_handlers.py](/absolute/path/webshare_app/routes/file_routes/download_handlers.py) `download` (rollback은 `send_file()` 호출 예외에만), [go-core/internal/handlers/files.go](/absolute/path/go-core/internal/handlers/files.go) `handleDownload` (`_ = reservation` 후 롤백 없음). 공유 파일 분기는 양쪽 모두 에러 경로에서 롤백하므로 대조된다.
- **우선순위:** Medium
- **신뢰도:** Confirmed
- **문제:** 쿼터는 전송 시작 전 예상 크기 전액을 예약한다. 스트리밍 중 클라이언트 취소·네트워크 단절은 응답 객체 반환 이후라 롤백 훅이 없어 전액이 차감된 채 남는다. 대용량 파일 1회 실패가 일일 대역폭을 소진시킬 수 있다.
- **발생 조건:** 대역폭 제한 설정 + 대용량 다운로드 중단/실패. 모바일·불안정 네트워크에서 현실적이다.
- **영향:** 정상 사용자의 429 잠금(당일까지). 관리자는 로그만 보고 오남용으로 오인할 수 있다.
- **근거:** `reserve_download_quota`가 `projected_bytes` 전액을 가산하고, 일반 다운로드 경로의 `rollback_download_quota` 호출이 `send_file` 구성 단계에만 존재함을 확인. Go는 예약을 변수에 버린 뒤(`_ = reservation`) 어떤 실패 경로에서도 롤백하지 않는다.
- **반증 확인:** 락은 경쟁을 막지만(원자적 예약 확인) 스트리밍 이후 실패를 보상하지 않는다. 감사 로그·트래커 flush는 회계 정합성과 무관하다. "보수적 회계가 의도"일 수 있으나 문서·에러 메시지에 그런 의도가 명시되어 있지 않아 결함으로 판단한다(완화책이 아니라 정책이라면 문서화 필요).
- **호출/영향 범위:** `download`, `handleDownload`, 공유 파일/ZIP 분기(일부는 롤백 있음). 영향: 일일 다운로드 횟수·대역폭 제한을 켠 모든 배포.
- **권장 수정 방향:** 스트리밍 완료 콜백(WSGI `close`/`call_on_close`, Go `http.CloseNotifier`/전송 바이트 계측)에서 실제 전송 바이트로 정산하거나, 최소한 중단 시 전액이 아닌 실측 차감으로 보정. 당장은 429 메시지에 "중단된 다운로드도 합산됩니다"를 명시.
- **필요한 회귀 테스트:** 클라이언트 중단(제네레이터 중간 close) 시 쿼터가 전액이 아닌 실측만큼만 남음을 단언하는 integration 테스트. Go/Python 동일 시나리오의 쿼터 잔액 비교 테스트.

### [ISSUE-007] 크래시 시 감사·차단·쿼터 상태 손실 창이 큼 (정상 종료 시에만 flush)

- **위치:** [webshare_app/server/cleanup.py](/absolute/path/webshare_app/server/cleanup.py) (5분 타이머, 첫 실행 60초 후), [webshare_app/features/audit_log.py](/absolute/path/webshare_app/features/audit_log.py) (`min_interval_seconds=5` 스로틀), [go-core/internal/handlers/app.go](/absolute/path/go-core/internal/handlers/app.go) `audit` (5초 스로틀) + `FlushState` (정상 종료 시).
- **우선순위:** Medium
- **신뢰도:** Confirmed
- **문제:** 감사 로그·로그인 차단·다운로드 트래커는 메모리 우선 + 지연 flush다. 크래시·SIGKILL·전원 차단 시 최근 상태가 통째로 유실된다. Python은 최악 5분, Go는 감사 5초 + 쿼터/차단은 종료 시까지 미기입될 수 있다.
- **발생 조건:** 상태 변경 후 크래시 рамки 내 강제 종료. 공격자가 차단 직전 프로세스를 죽이는 시나리오는 비현실적이지만, 정전·OOM kill 후 "누가 무엇을 했나"가 사라지는 것은 현실적이다.
- **영향:** 보안 가시성 공백(감사), 차단 회피(브루트포스 카운터 초기화), 쿼터 초기화. 단일 사용자 로컬 서버 기준이라 Critical까지는 아니다.
- **근거:** `flush_*_if_dirty(force=False)`가 주기 타이머에만 걸려 있고, 강제 flush는 `ServerThread.shutdown`·`FlushState`의 정상 경로에만 존재함을 확인. 파일 쓰기 자체는 원자적이라 손상이 아니라 유실 문제다.
- **반증 확인:** 원자적 쓰기·dirty 게이팅은 동시 쓰기 손상은 막지만 크래시 유실은 막지 못한다. 공유 링크 저장(`save_share_links` 즉시 저장)과 대조하면 보안 상태의 flush 정책이 불균일하다.
- **호출/영향 범위:** 로그인 시도, 공유 비밀번호 시도, 다운로드 쿼터, 감사 로그. 영향: 감사 로그 검색/내보내기, IP 차단, 일일 제한.
- **권장 수정 방향:** 보안 이벤트(로그인 실패→차단 확정, 공유 비밀번호 차단 확정)는 즉시 저장으로 승격하고, 나머지는 스로틀 유지. 또는 WAL/append-only 저널 + 주기 스냅샷 구조로 변경.
- **필요한 회귀 테스트:** 차단 확정 직후 프로세스 재시작(상태 reload)해도 차단이 유지됨을 단언하는 크래시 복구 테스트(flush 없이 reload). 감사 엔트리 기록→비정상 종료 시뮬레이션→reload 후 존재 여부를 측정하는 손실 창 측정 테스트.

## 5. Potential Functional Gaps

- **Confirmed Gap — 청크 temp가 공유 폴더 내부(`.upload_temp`)에 상주:** [webshare_app/routes/upload_routes/chunk_init.py](/absolute/path/webshare_app/routes/upload_routes/chunk_init.py)는 `target_dir/.upload_temp/<session>`에 저장한다. dot prefix라 API 직접 접근은 차단되지만 폴더 용량 계산·검색 인덱스·중복 스캔이 부분 청크를 정상 파일처럼 합산/색인할 수 있다. 2시간 TTL·완료 시 정리되나 비정상 종료 잔여물은 다음 정리까지 남는다.
- **Confirmed Gap — 업데이트 스모크가 실행 파일만 검증:** `apply_staged_update`는 교체 후 `[target, --smoke]`만 수행한다. Go 바이너리·설정·정적 자산의 조합 실패(ISSUE-001/002류)는 `--smoke`(Flask test_client 기반)만으로 검출되지 않는다.
- **Likely Gap — 트랜스코더 세션 정리 공백:** `Transcoder.stop`은 디렉터리를 지우지만 크래시 잔여 `.webshare_transcode/<sid>`를 기동 시 정리하는 루틴이 보이지 않는다. 장시간 운영 시 디스크 누적이 가능하다.
- **Likely Gap — 폴더 변경 시 영속 상태의 루트 고정:** 각종 `*_FILE` 상태가 `conf.get('folder')` 기준으로 해석된다. 공유 폴더를 바꾸면 이전 상태(차단·쿼터·링크)가 로드되지 않고, 반대로 이전 폴더에 민감 상태가 방치된다. 마이그레이션·폐기 흐름이 없다.
- **추정 — 중복 스캔·클라우드 동기화의 장시간 작업 취소/재시작 계약:** `job_store`에 `cancelled` 표기는 있으나(bootstrap에서 중복 스캔만 정리), 클라우드 동기화 작업의 중단 후 재개·부분 업로드 정리는 본 감사에서 끝까지 확인하지 못했다. 별도 심층 감사 필요.

## 6. Documentation Mismatches

- `CLAUDE.md`·`AGENTS.md`가 존재하지 않는다. 작업 지시문이 전제로 한 개발 규칙 문서가 레포에 없으므로, 본 감사는 `README.md` + 코드 + 테스트를 기준으로 수행했다.
- README "1초 만에 자동 폴백": Go 바이너리 누락·시작 실패 시에만 성립한다. ISSUE-001/002처럼 Go가 *정상은 아니지만 살아 있는* 설정 무시 상태에서는 폴백이 발생하지 않으므로, "무중단 안전" 서술은 과장이다.
- README 네트워크 바인딩·모바일 QR·HTTPS(자체 서명) 안내: Python 백엔드 기준으로만 참이다. 기본 Go 백엔드에서 바인딩 무시(ISSUE-001)·TLS 부재(ISSUE-002)를 문서가 언급하지 않는다.
- README "Go와 Python 간 상태 완전 호환·세션 끊김 없음": 세션 쿠키 호환 자체는 설계되어 있으나(Go `FlaskCodec`), 공유 링크 UX(ISSUE-005)·쿠키 Secure 속성(ISSUE-002)·상태 flush 타이밍(ISSUE-007)이 달라 동작 동등성은 성립하지 않는다.
- 기존 `PROJECT_AUDIT.md`(2026-09-26)의 "종합 위험도 Low", "Twin-Server 정합성 100% 통과" 평가는 본 감사의 ISSUE-001~005와 양립하지 않는다. 해당 문서는 테스트 통과(당시 `134 passed`)를 안전성과 동일시한 것으로 보이며, 설정 무시·플랫폼 분기 같은 코드 판독형 결함을 다루지 않았다.
- `go-core/internal/handlers/app.go`의 `csrfExempt` 주석("share routes land in a later milestone")은 현재 구현(공유 라우트 존재)과 맞지 않는 잔재다. 동작 자체는 공개 경로라 CSRF가 필요 없어 안전하나 주석은 오해를 유발한다.

## 7. Recommended Fix Plan

### Phase 1 — Immediate

1. ISSUE-001: `display_host`를 Go 기동에 전달하고 실제 리슨 주소를 GUI에 표시. LAN 노출 시 배포 경고 유지.
2. ISSUE-002: Go TLS 지원 또는 HTTPS 옵션의 Go 백엔드 비활성화 + 문서 명시. Secure 쿠키와 평문 리스너의 조합을 금지.
3. ISSUE-004: 버전 복원의 원자적 교체 + 백업 실패 시 중단. 데이터 손상 경로를 먼저 닫는다.
4. ISSUE-003: Windows 부모 감시(Job Object 또는 폴링) + 고아 감지 메시지. 주 EXE 배포 플랫폼이므로 Phase 1에 포함.

### Phase 2 — Stability

5. ISSUE-005: Go 공유 링크 최소 HTML(비밀번호 폼·만료/차단 페이지) 렌더. 외부 수신자 흐름 복구.
6. ISSUE-006: 스트리밍 실측 기반 쿼터 정산(또는 중단 합산의 정책 문서화).
7. ISSUE-007: 차단 확정 이벤트의 즉시 영속화. 감사 손실 창 축소.
8. 청크/transcode 잔여물 기동 시 정리 + 폴더 변경 시 상태 마이그레이션/폐기 안내.

### Phase 3 — Structural

9. 백엔드 parity contract 테스트를 CI 게이트로 승격(라우트·응답 타입·설정 존중 여부).
10. 설정 무시형 실패를 기동 게이트에서 검출(바인딩 주소·TLS 상태를 `/readyz`·GUI에 노출).
11. 장시간 작업(동기화·스캔·트랜스코딩)의 취소·재시작·잔여물 계약 정립과 책임 분리.

실제 코드는 수정하지 않았다.

## 8. Test Recommendations

- **Unit — Go 기동 argv:** `display_host` ∈ {`127.0.0.1`, `0.0.0.0`, LAN IP} × backend ∈ {go, python} 조합에서 Go argv `--host`가 설정값과 동일함을 단언. 기대: argv 일치, `base_url`은 loopback 프로브용 별도 값.
- **Unit — HTTPS 조합 거부:** `use_https=true` + backend=go에서 기동이 거부되거나(Phase 1b) TLS 핸드셰이크가 성공함(Phase 1a). 기대: 평문 리슨 + Secure 쿠키 조합이 절대 발생하지 않음.
- **Unit — 버전 복원 원자성:** `shutil.copy2` 대신 temp+replace를 사용함을 모킹으로 단언하고, 주입된 중간 실패 후 원본 해시(SHA-256)가 불변임을 확인.
- **Unit — 버전 백업 실패 시 중단:** `create_file_version` 실패 주입 시 `POST /versions/restore`가 500 + `success:false`를 반환하고 타깃 mtime·해시가 변하지 않음을 단언.
- **Integration — 공유 링크 contract(백엔드 parity):** 비밀번호 링크 GET → `text/html` 폼, 오답 POST → 폼 + 에러, 만료 → 만료 페이지, 초과 → 429 페이지가 Go/Python 동일함을 비교. 현재 Go는 JSON이므로 이 테스트는 실패해야 한다(회귀 게이트).
- **Integration — 쿼터 정산:** 대역폭 제한 설정 후 대용량 다운로드 중간 abort 시 트래커 bytes가 전액이 아닌 실측 이하로 남음을 단언(Python WSGI close 훅, Go 전송 계측).
- **Integration — 차단 영속성:** 로그인 5회 실패→차단 후 영속 파일 reload 시 차단이 유지됨을 단언(flush 없이 reload하는 크래시 시뮬레이션).
- **E2E — LAN 바인딩:** `display_host=0.0.0.0` 기동 후 실제 리슨 소켓이 `0.0.0.0:port`임을 OS 소켓 테이블로 확인하고, LAN IP URL로 `/healthz`·`/readyz`가 응답함을 확인.
- **Concurrency — 공유 다운로드 횟수:** `max_downloads=1` 링크에 20 병렬 요청 시 성공이 정확히 1회이고 나머지가 429/만료임을 단언(예약 원자성 유지 확인).
- **Concurrency — 청크 완료 중복:** 동일 세션 `complete` 2회 동시 호출 시 1회 성공 + 1회 409/멱등 성공이며 최종 파일 해시가 단일 병합과 동일함을 단언.
- **Regression — 좀비 포트:** (Windows CI 또는 모킹) 부모 사망 시 자식 종료 + 포트 해제, 재기동 성공을 단언. 비Windows에서는 기존 `watchParent` 동작 유지.
- **Platform-specific — Windows reserved names·대소문자:** `CON`, `AUX`, `NUL.txt`, trailing dot/space 파일명으로 업로드·복원·공유 생성 시 전 플랫폼에서 탈출 없이 저장됨을 단언. 한글 NFC/NFD(README 주장)는 macOS 실기 또는 정규화 unit(`unicodedata.normalize` vs Go `x/text`) 비교로 검증.

## 9. Final Assessment

- **Functional Correctness:** Needs Work — Python 단일 백엔드로는 양호하나, 기본 Go 백엔드의 바인딩·TLS·공유 UX 불일치가 핵심 기능(LAN 접속, HTTPS, 외부 공유)을 깨뜨린다.
- **Runtime Stability:** Needs Work — Windows 고아 프로세스, 크래시 시 상태 유실, 복원 비원자성이 가용성·신뢰성을 깎는다. 정상 경로의 종료 flush·폴백은 잘 되어 있다.
- **Data Integrity:** Needs Work — 업로드 원자성·버전 보관 자체는 우수하나, 복원 경로 하나가 손상 창을 만든다(ISSUE-004). 그 외 대량 쓰기는 temp+replace로 보호된다.
- **Error Resilience:** Acceptable — 입력 검증·권한·쿼터·ZIP 방어·업데이트 롤백이 촘촘하다. 약점은 실패 후 정산(쿼터)·손실 창(감사) 같은 2차 복원력이다.
- **Cross-platform Robustness:** Needs Work — reserved names·정규화·작업킬 분기는 신경 썼으나, 바인딩·TLS·부모 감시의 플랫폼 분기가 Windows 주 경로에서 어긋난다.
- **Test Confidence:** Acceptable — 관련 subset 33개 + Go 3패키지가 통과하고 parity 테스트가 다수 존재한다. 그러나 설정 존중·HTML contract·크래시 복구를 묻는 테스트가 없어 High 이슈들이 게이트를 통과했다.

**실제로 먼저 수정할 문제 3개:**

1. [ISSUE-001] Go 바인딩 무시 — LAN/모바일 핵심 시나리오가 기본값에서 동작하지 않는다.
2. [ISSUE-002] Go TLS 부재 — 보안 설정이 거짓 약속이 되고 로그인을 깰 수 있다.
3. [ISSUE-004] 버전 복원 비원자성 — 유일한 직접적 데이터 손상 경로다. (다음: ISSUE-003 Windows 고아, ISSUE-005 공유 JSON UX)
