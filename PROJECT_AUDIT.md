# Project Audit

> **작성일:** 2026-10-06
> **대상:** WebShare Pro v7.4.0 (Go + Python 하이브리드, PyQt6 GUI, Flask 백엔드)
> **관점:** 기능 구현·런타임 안정성 (코드 수정 없음, 감사 리포트만 작성)
> **이전 리포트와의 관계:** 기존 `PROJECT_AUDIT.md`(2026-09-28)의 ISSUE-001~005(Go 바인딩·HTTPS 거부·고아 프로세스 힌트·버전 복원 원자성·Go 공유 HTML)는 현 코드에서 **수정된 것으로 확인**되어 본 감사에서는 재지적하지 않는다. 본 문서는 잔여 위험만을 다룬다.

## 1. Executive Summary

- **프로젝트 전체 상태:** 핵심 파일 공유 흐름(업로드/다운로드/휴지통/공유 링크/권한)은 Python 백엔드 기준으로 견고하게 구현되어 있다. 경로 검증(`validate_path` + `ensure_path_access`), 공유 링크 다운로드 횟수 예약(`_reserve_share_download`), 청크 업로드 세션 소유권·용량 제한, ZIP Slip/Zip Bomb 방어, 감사 로그 지연 쓰기 등 보안·무결성 장치가 실제로 존재하고 관련 테스트도 통과한다.
- **전체 위험도:** **Acceptable (조치 필요 잔여 항목 있음)**. Critical 이슈는 없다. 잔여 위험은 모두 Medium 이하이며, 좁은 타이밍 윈도우·손상된 로컬 파일·대용량 ZIP 등 특정 조건에서만 발동한다.
- **가장 중요한 문제 3~5개:**
  1. [ISSUE-001] 병합 중 취소가 파일을 막지 못함 (청크 업로드 cancel이 COMPLETING 상태를 검사하지 않음, Medium/Likely).
  2. [ISSUE-002] 손상된 설정 파일(잘못된 UTF-8)이 시작 시점에 uncaught 예외로 서버를 죽임 (Medium/Confirmed).
  3. [ISSUE-003] 휴지통 이동/복원과 메타데이터 저장 사이의 비원자적 윈도우 (Medium/Likely).
  4. [ISSUE-004] 다운로드 쿼터 이중 버킷 + 중단 시 전액 차감과 429 메시지의 상충 (Medium/Confirmed).
  5. [ISSUE-005] 압축 해제에 디스크 여유 검사가 없고 실패 시 부분 추출물이 남음 (Medium/Likely).
- **데이터 손상/유실 가능성 여부:** 직접적인 데이터 파괴 경로는 확인되지 않았다. 청크 병합·버전 복원·설정/스냅샷 저장은 temp + `os.replace` 원자 쓰기를 사용한다. 다만 ISSUE-003의 윈도우에서는 휴지통 파일이 메타데이터 없이 남아 **원본 경로로의 복원이 부정확**해질 수 있다(유실이 아닌 복원 품질 저하).
- **가장 먼저 수정해야 할 영역:** `webshare_app/routes/upload_routes/chunk_finalize.py`(취소 경합), `webshare_app/core/config/manager.py`(설정 로드 예외 범위), `webshare_app/features/trash.py`(이동·메타데이터 순서 보장).

## 2. Project Understanding

### 프로젝트 목적

로컬 폴더를 개인 클라우드처럼 공유하는 크로스플랫폼 파일 서버. PyQt6 데스크톱 관리자가 서버를 제어하고, 브라우저용 웹 파일 관리자·보안 공유 링크·폴더별 RBAC·휴지통/버전·HLS 트랜스코딩·Google Drive 동기화·WebDAV를 제공한다.

### 주요 entrypoint

- `main.py::main()` → `--smoke` / `--apply-update` 분기, 이후 `ensure_runtime_initialized()` → PyQt6 GUI 또는 Flask 단독 실행.
- `webshare_app/server/__init__.py::start_server` → `WEBSHARE_SERVER_BACKEND`(기본 `go`)에 따라 Go 자식 프로세스 또는 Python 스레드 시작. Go 실패 시 Python으로 폴백. Go + HTTPS 조합은 `GO_HTTPS_BLOCKED`로 명시 거부한다(이전 감사 ISSUE-002 수정 반영됨).
- `webshare_app/app/factory.py::create_app` → Flask 팩토리(세션 쿠키, CSRF, IP 게이트, 전역 에러 정규화, 라우트 등록).
- `docker_entrypoint.py::main` → werkzeug `make_server`로 **Python 백엔드를 직접 서빙** (Go를 거치지 않음, §6 참조).
- `go-core/cmd/webshare-core/main.go` → Go `serve` 진입점.

### 핵심 모듈

- 인증/보안: `webshare_app/security/auth.py`, `ip_blocker.py`, `csrf.py`, `permissions.py` (Go 대응: `go-core/internal/auth/*`, `permission/*`).
- 파일 I/O: `webshare_app/routes/file_routes/*`, `webshare_app/routes/upload_routes/*`, `webshare_app/services/upload_service.py`, `file_service.py` (Go 대응: `go-core/internal/handlers/*`, `mutate/*`).
- 공유 링크: `webshare_app/routes/share_routes.py` + `webshare_app/services/share_service.py` + `webshare_app/features/share_links_store.py`.
- 상태 영속화: `webshare_app/core/persistence.py` + `core/app_paths.py::atomic_write_json`, `features/audit_log.py`, `features/runtime_state.py`, `features/job_store.py`.
- 휴지통/버전: `webshare_app/features/trash.py`, `webshare_app/utils/helpers/file_versions.py`.
- 업데이트: `webshare_app/core/update_installer.py`, `update_manifest.py`, `scripts/apply_update.py`.
- 프로세스 관리: `webshare_app/server/go_process.py`, `thread.py`, `cleanup.py`, `bootstrap.py`.

### 데이터 저장 방식

DB 없음. 공유 폴더 내 dotfile JSON(`.webshare_share_links.json`, `.webshare_audit.json`, `.webshare_download_tracker.json`, `.webshare_login_attempts.json`, `.webshare_trash.json`, 권한/메타데이터/작업 ledger)과 `.webshare_trash/`, `.webshare_versions/`, `.upload_temp/`, `.webshare_transcode/` 디렉터리. Python은 `atomic_write_json`(동일 디렉터리 temp + `os.replace`) + 파일별 직렬화 락(`persist_json_snapshot`)을 사용한다.

### 외부 의존성

Flask/Werkzeug, PyQt6, Pillow, cryptography, cachetools, orjson, watchdog, ffmpeg(별도 바이너리, HLS용), Google Drive OAuth(사용자 설정 시), GitHub Releases(업dater 경로). 감사 과정에서 추가 의존성을 설치하지 않았다.

### 핵심 실행 흐름

`GUI 시작 → server.start_server → [Go: go_process.start(binary serve --host display_host --port) → /readyz 폴백 감시 | Python: ServerThread(make_server(display_host, port)) + ensure_runtime_initialized + 주기 정리] → Flask before_request(IP 화이트리스트/차단·세션 타임아웃·CSRF) → Handler(validate_path + ensure_path_access + RBAC) → Core(원자적 저장·예약/감사) → JSON 스냅샷(원자적 교체) → Result`

`청크 업로드: POST /upload/chunk/init(검증·디스크 예약·세션 생성) → POST /upload/chunk/<id>(소유권·만료·용량 제한 후 청크 저장) → POST …/complete(청크 집합 검증 → temp 병합·사이즈 검증 → os.replace 커밋) → 감사`

`공유 링크: POST /share/create(admin, 검증·해시·유효기간) → GET/POST /share/<token>(만료·횟수·비밀번호·쿼터·예약 → 파일/ZIP 스트리밍, 실패 시 예약 롤백)`

## 3. Audit Coverage & Limitations

### 실제 확인한 주요 모듈

- 진입점/서버: `main.py`, `webshare_app/app/factory.py`, `webshare_app/server/__init__.py`, `go_process.py`, `thread.py`, `bootstrap.py`, `cleanup.py`, `docker_entrypoint.py`.
- 업로드: `routes/upload_routes/chunk_init.py`(CodeGraph 경유), `chunk_transfer.py`, `chunk_finalize.py`, `services/upload_service.py`, `services/file_service.py`.
- 파일/다운로드: `routes/file_routes/path_utils.py`, `mutation_handlers.py`(upload/unzip), `download_handlers.py`, `utils/file_utils.py`(validate_path/safe_filename), `utils/zip_utils.py`.
- 공유: `routes/share_routes.py` 전체, `services/share_service.py`, `features/share_links_store.py`.
- 상태/영속: `core/config/manager.py`, `core/persistence.py`, `core/app_paths.py`, `features/trash.py`, `features/audit_log.py`, `features/runtime_state.py`, `utils/helpers/download_quota.py`, `utils/helpers/atomic_io.py`, `utils/helpers/file_versions.py`, `utils/helpers/expiry_cleanup.py`, `utils/request_policy.py`.
- 보안: `security/auth.py`, `csrf.py`, `ip_blocker.py`, `permissions.py`, `features/webdav_server.py`.
- 외부연동: `services/google_drive_client/http.py`, `sync.py`, `features/transcoder.py`, `features/search_indexer/watcher.py`, `core/update_installer.py`.
- 테스트 기반: `tests/conftest.py`.

### CodeGraph로 분석한 호출 관계

CodeGraph MCP 도구가 본 환경에 없어 동등한 CLI(`codegraph explore`, `.codegraph/codegraph.db` 사용)로 아래를 구조적으로 확인했다.

- `main entrypoint create_app start_server factory bootstrap` — `start_server` 호출자 8곳(GUI 액션·트레이·main), `create_app` 호출자 7곳.
- `chunked upload finalize upload_service chunk_init chunk_finalize` — `init_chunk_upload` → `test_upload_integrity.py` 연결 확인.
- `trash delete restore file mutation path traversal safe_join` — Python `trash.py`와 Go `mutate/trash.go`의 동일 레이아웃(타임스탬프_uuid_파일명, 메타데이터 파일) 확인.
- `persistence atomic write share_links_store metadata trash audit_log secret_key` — `atomic_write_bytes` 호출자 6곳, 영속화 락 구조 확인.
- `auth login_required permissions ensure_path_access CSRF share link download limit` — 인증 데코레이터·권한·공유 흐름 확인.
- `update_installer apply_update Ed25519 manifest rollback go_process supervisor` — 스테이징 검증·롤백 경로 확인.
- `go-core handlers files upload mutate share parity Python fallback` — Go 공유 실패/비밀번호 페이지가 Python `share_expired.html`/`share_password.html` 분기와 상태 코드를 맞춘 것(이전 감사 ISSUE-005 수정 반영) 확인.

### 실행한 테스트

- `tests/test_upload_integrity.py` + `tests/test_permissions_enforcement.py`: **13 passed**.
- `tests/test_security_hardening_724.py` + `tests/test_share_html_and_orphan.py` + `tests/test_download_limits.py` + `tests/test_go_bind_and_https.py` + `tests/test_backend_parity_contract.py`: **35 passed**.
- 전체 스위트(`tests/`, `test_perf_transfer.py` 제외, `-x`): 102 passed 후 `tests/test_milestone_c_contract.py::test_batch_download`에서 `ConnectionResetError: [WinError 10054]`로 중단. 동일 테스트 단독 재실행 시 **1 passed** — 외부 요인(로컬 소켓 리셋)으로 판단되는 간헐 실패이며 코드 회귀 근거는 없다. 전체 스위트 1회 완주는 하지 못했다.
- Go 테스트(`go-core/...`)는 실행하지 않았다(Go 툴체인 검증 생략).

### 확인하지 못한 환경/외부 서비스

- 실제 Google Drive OAuth·동기화, ffmpeg HLS 트랜스코딩, UPnP 포트포워딩, PyQt6 GUI 동작, Linux/macOS 및 Docker 컨테이너 실행, 다중 사용자 동시 접속 부하는 검증하지 않았다. 감사는 Windows 소스코드 정독 + Python 테스트로 한정된다.

### CodeGraph 또는 분석상의 한계

- CodeGraph 결과는 호출자 수·파일 단위이며, 조건부 도달 가능성(예: 특정 권한 조합)은 직접 코드를 열어 반증했다.
- `legacy/` 디렉터리는 현 실행 경로가 아니므로(v4 단일 파일 유산) dead-code로 취급하고 production risk에서 제외했다.
- 동시성 이슈는 런타임 재현 없이 코드 근거로 판단한 것은 `Likely`로만 분류했다.

## 4. High-Risk Issues

### [ISSUE-001] 청크 병합 진행 중 취소가 파일을 막지 못함

- **위치:** `webshare_app/routes/upload_routes/chunk_finalize.py` / `complete_chunk_upload`(:25), `cancel_chunk_upload`(:184)
- **우선순위:** Medium
- **신뢰도:** Likely
- **문제:** `complete`는 락 안에서 세션 상태를 `COMPLETING`으로 바꾸고 락을 놓은 뒤 수 초~수십 초 걸리는 병합(temp 파일 조립 + `os.replace`)을 수행한다. `cancel`은 소유권만 검사하고 상태 검사를 하지 않으며(`cancel_chunk_upload` :184~201에 상태 분기 없음) 세션을 삭제하고 temp 디렉터리를 지운다. 병합 루프가 이미 열린 청크 파일 핸들을 들고 있으면 취소 후에도 `os.replace`가 실행되어 파일이 그대로 커밋된다. 사용자에게는 "취소 성공"이 반환되지만 파일은 나타난다.
- **발생 조건:** 대용량 업로드의 `complete` 호출 직후(병합 진행 중) 동일 세션 소유자가 `cancel`을 호출. 병합 시간이 길수록(GB 단위) 윈도우가 넓어진다.
- **영향:** 취소 의미 위반 + 디스크 예약 해제 후 커밋되므로 디스크 압력 회계 우회. 목표 파일 자체는 완전한 내용이라 데이터 손상은 아니다.
- **근거:** `chunk_finalize.py` :45~48(두 번째 complete는 409로 차단하지만 cancel 경로는 차단하지 않음), :106~126(락 밖 병합), :184~201(상태 무검사 삭제). `_cleanup_upload_session`(`upload_service.py` :129)은 세션 pop + temp 삭제만 하고 진행 중 병합을 중단시키지 않는다.
- **반증 확인:** 상위 caller의 검증 — `cancel`도 `_is_upload_session_owner`를 검사하므로 타인의 세션을 지울 수는 없다(소유권 문제는 반증됨). 디스크 예약 double-free — `_finish_upload_session_success`는 세션이 없으면 조용히 반환(`upload_service.py` :112~114)하므로 크래시는 나지 않는다(크래시 가능성은 반증됨). 그러나 "취소 후 커밋 방지" 장치는 어디에도 없다.
- **호출/영향 범위:** caller는 웹 UI 청크 업로더 1계열. callee는 `_cleanup_upload_session`, `release_upload_disk_space`. 영향 모듈은 업로드 세션 상태·디스크 예약 회계에 한정되며 다운로드·공유 경로에는 닿지 않는다.
- **권장 수정 방향:** `cancel` 진입 시 락 안에서 상태를 확인하고 `COMPLETING`이면 409 + 취소 거부를 반환하거나, 병합 루프가 주기적으로 세션 생존을 확인하고 사라졌으면 temp를 버리고 커밋을 포기하게 한다.
- **필요한 회귀 테스트:** 병합을 지연시킨 상태에서(예: `shutil.copyfileobj`를 느리게 monkeypatch) `complete` 스레드 실행 중 `cancel`을 호출하고, 응답은 409이며 목표 파일이 생성되지 않음을 assert하는 concurrency 테스트.

### [ISSUE-002] 잘못된 인코딩의 설정 파일이 시작 시점에 uncaught 예외로 서버를 죽임

- **위치:** `webshare_app/core/config/manager.py` / `ConfigManager.load`(:56~81)
- **우선순위:** Medium
- **신뢰도:** Confirmed
- **문제:** `load()`의 except 절은 `(json.JSONDecodeError, IOError)`만 잡는다(:78). 설정 파일이 유효한 UTF-8이 아닌 바이트를 포함하면 `open(..., encoding='utf-8')` 읽기 시점에 `UnicodeDecodeError`가 발생하는데, 이는 `ValueError` 계열이며 `JSONDecodeError`의 서브클래스가 아니다. 따라서 예외가 `__init__` → `conf` 싱글턴 생성 → import 시점으로 전파되어 서버가 시작하지 못한다.
- **발생 조건:** 설정 파일이 잘못된 인코딩으로 손상된 경우(수동 편집, 디스크 오류, 타 프로그램 간섭). 원자적 저장(`save()`의 temp + `os.replace`) 덕분에 정상 경로의 torn-write 가능성은 낮아 발생 빈도는 낮다.
- **영향:** 로컬 시작 거부(DoS). 데이터 손상 자체는 없으나 복구하려면 사용자가 파일을 직접 고쳐야 한다.
- **근거:** :60~63(`open` + `json.load`), :78(except 범위). Python 예외 계층 probe 실행으로 확인했다(`issubclass(UnicodeDecodeError, json.JSONDecodeError)` → `False`, `issubclass(UnicodeDecodeError, ValueError)` → `True`). 반대로 `save()`는 `IOError`(≒`OSError`)만 잡고 `json.dump`의 `TypeError`는 호출자로 전파되므로, 저장 경로의 예외 계약도 비대칭이다.
- **반증 확인:** 상위 보호 장치 — `main.py`·`docker_entrypoint.py` 어디에도 `conf` 생성 실패를 받아치는 try/except가 없다(모듈 import 시점에 싱글턴이 생성됨). framework 보장 — 없음. JSON 스키마 검증(`set()`의 키별 검증)은 파일이 파싱된 이후 단계라 도달하지 못한다.
- **호출/영향 범위:** `conf`는 전역 싱글턴이므로 모든 라우트·서비스·GUI에 영향. 단일 수정점(`except`에 `UnicodeDecodeError`/`ValueError` 추가 + 손상 시 백업 후 기본값 기동)이 전체를 복구한다.
- **권장 수정 방향:** `except (json.JSONDecodeError, UnicodeDecodeError, ValueError, OSError)`로 확장하고, 손상된 파일은 `.corrupt-<timestamp>`로 백업한 뒤 기본값으로 기동 + ERROR 로그를 남긴다.
- **필요한 회귀 테스트:** Unit — 잘못된 UTF-8 바이트가 든 설정 파일을 주고 `ConfigManager.load()`가 예외 없이 끝나고 백업 파일이 생기며 기본 포트로 동작함을 assert. Integration — 손상된 설정 상태에서 `create_app()` + `/healthz` 200을 assert.

### [ISSUE-003] 휴지통 이동/복원과 메타데이터 저장 사이의 비원자적 윈도우

- **위치:** `webshare_app/features/trash.py` / `move_to_trash`(:148~187), `restore_from_trash`(:190~247)
- **우선순위:** Medium
- **신뢰도:** Likely
- **문제:** (a) `move_to_trash`는 `shutil.move`(:173) 성공 후 메타데이터를 load→수정→save(:174~182)한다. 그 사이 크래시/전원 단절이 나면 파일은 휴지통에 있지만 메타데이터 항목이 없어 `original_rel_path`를 잃는다. 이때 복원은 `extract_original_name_from_trash` 폴백에 의존하는데, 현 명명 규칙(`{timestamp}_{uuid}_{filename}`)에서 정규식 `^\d{8}_\d{6}_(.+)$`는 `uuid_filename`을 돌려주므로 **복원 파일명에 uuid 접두사가 붙는다**. (b) `restore_from_trash`는 `shutil.move`(:240) 후 메타데이터에서 항목을 제거·저장(:241~242)한다. 사이 크래시 시 파일은 복원됐는데 항목이 남아 고아 메타데이터가 영구 누적된다(정리 루틴은 trash 디렉터리 목록 기준으로만 항목을 제거하므로 복원된 파일의 항목은 절대 지워지지 않음, `auto_cleanup_trash` :113~144 참조).
- **발생 조건:** 이동/복원 직후 수십 ms 이내의 프로세스 크래시·전원 단절. 정상 종료 경로에서는 발생하지 않는다.
- **영향:** 데이터 유실은 아니다(파일 자체는 온전). 복원 정확도 저하(a) 및 메타데이터 누적(b). 휴지통 자동 비우기는 타임스탬프 접두사(`item[:15]`) 기준이라 uuid 명명 파일도 정상 만료 삭제되므로 고아 파일 방치는 생기지 않는다.
- **근거:** :173~182(move 후 save), :240~242(move 후 pop+save), :20~29(정규식이 uuid를 분리하지 못함), :119~135(자동 정리는 파일명 파싱 기준이라 메타데이터 없이도 동작). Go 대응(`go-core/internal/mutate/trash.go`, CodeGraph 확인)도 동일 레이아웃·동일 순서이므로 양 백엔드에 공통된 설계이다.
- **반증 확인:** 상위 caller 검증 — `routes/trash_routes.py`의 삭제/복원 핸들러는 `validate_path`·권한 검사를 하지만 크래시 윈도우를 좁히지 못한다. DB 트랜잭션 — 없음(JSON 스냅샷 방식). 프레임워크 보장 — `os.replace`는 메타데이터 파일 자체의 torn-write만 막을 뿐 move↔save 순서의 원자성은 보장하지 않는다.
- **호출/영향 범위:** caller는 휴지통 삭제/복원/비우기 라우트 1계열. callee는 `_load/_save_trash_metadata`, `auto_cleanup_trash`. 공유·업로드 경로와는 독립적이다.
- **권장 수정 방향:** (a) 이동 전 메타데이터에 `pending` 항목을 먼저 기록하고 move 성공 후 확정하거나, 파일명에 `original_rel_path` 복원 힌트를 유지한다. (b) 복원 시 메타데이터 pop+save를 먼저 하고 move 실패 시 롤백한다. 또는 trash 디렉터리 스캔 시 메타데이터에 없는 파일을 재등록하는 self-heal을 추가한다.
- **필요한 회귀 테스트:** Integration — `_save_trash_metadata`를 실패하도록 monkeypatch한 상태에서 `move_to_trash` 호출 후 파일이 원위치에 남아 있음( halfway 커밋 금지 )을 assert. Unit — 메타데이터 없는 `timestamp_uuid_name` 파일의 복원 결과가 `uuid_name`이 아닌 원본명으로 복원되거나 명시적 경고를 냄을 assert.

### [ISSUE-004] 다운로드 쿼터의 이중 버킷과 중단 시 전액 차감 — 429 메시지와 실제 동작의 상충

- **위치:** `webshare_app/utils/helpers/download_quota.py` / `build_download_tracker_key`(:27), `reserve_download_quota`(:67), `settle_download_quota`(:192); `webshare_app/routes/file_routes/download_handlers.py` / `_settle_served_file_quota`(:19~44)
- **우선순위:** Medium
- **신뢰도:** Confirmed
- **문제:** 두 가지가 얽혀 있다. (1) 인증 다운로드는 `session:<id>` 키(`download_handlers.py` :75, :137)로, 공유 링크 다운로드는 `ip:<addr>` 키(`share_routes.py` :202, `prefer_session=False`)로 집계된다. 동일인이 두 경로를 섞어 쓰면 일일 제한을 사실상 두 배로 쓸 수 있다. (2) `send_file` 단건 다운로드는 `direct_passthrough`라 스트림 종료 훅이 없어 전송 길이를 즉시 확정한다(:19~29 주석 자인). 중도 abort 시 서버는 실제 전송량을 관측할 수 없어 **보수적으로 전액 예약금을 유지**한다. 그런데 429 메시지에 덧붙는 `QUOTA_POLICY_NOTE`(:14~17)는 "중단된 다운로드는 실제 전송 바이트로 정산되며 전송된 바이트만 쿼터에 집계된다"고 안내한다. 즉 메시지의 약속이 단건 다운로드 abort 케이스에서는 지켜지지 않는다.
- **발생 조건:** (1) 로그인 사용자가 인증 다운로드와 공유 링크 다운로드를 병행. (2) 대용량 단건 다운로드가 중도에 끊긴 뒤 재시도 → 쿼터가 실제보다 빨리 소진되어 429.
- **영향:** (1) 일일 제한 우회(공정성). (2) 끊긴 사용자에게 부정확한 429 + 오해 소지가 있는 안내. 데이터 손상은 없다.
- **근거:** 키 생성 분기(`download_quota.py` :27~32 + 양 호출부의 인자), abort 시 전액 유지임을 명시한 `download_handlers.py` :19~29 주석, 과장된 안내문(`QUOTA_POLICY_NOTE` :14~17). ZIP/공유 스트리밍 경로는 `make_settled_zip_stream_response`로 실제 정산되므로 이중 동작이 코드에 공존한다.
- **반증 확인:** 상위 보호 — `reserve_download_quota` 자체는 락 안에서 원자적으로 검사·증가하므로 동시 초과는 막힌다(race는 반증됨, `test_download_limits.py` 통과). 문제는 정확성(버킷 분리)과 메시지 정합성이며, 이를 막는 장치는 없다.
- **호출/영향 범위:** caller는 단건/ZIP/공유 다운로드 3계열. callee는 `DOWNLOAD_TRACKER`, `mark_download_tracker_dirty`(주기 flush). 감사 로그·공유 횟수에는 영향 없음.
- **권장 수정 방향:** (a) 로그인 사용자의 공유 다운로드도 `session:` 버킷에 합산하거나, 합산 상한(세션+IP 중 큰 쪽이 아닌 합계 기준)을 둔다. (b) 단건 다운로드 abort 케이스에 대한 429 문구를 분리("전송 완료 여부와 관계없이 예약량이 차감될 수 있음")하거나, `send_file` 대신 settled 스트리밍 응답으로 통일한다.
- **필요한 회귀 테스트:** Integration — 동일 세션으로 인증 다운로드 N회 + 공유 다운로드 M회 후 두 버킷 합계가 제한을 초과할 수 없음을 assert. Unit — abort를 시뮬레이션(예약 후 settle 없이 연결 종료)한 뒤 잔여 쿼터가 전액 차감 상태임을 문서화하는 테스트 + 429 메시지 분기 테스트.

### [ISSUE-005] 압축 해제에 디스크 여유 검사가 없고 실패 시 부분 추출물이 남음

- **위치:** `webshare_app/routes/file_routes/mutation_handlers.py` / `unzip_file`(:554~622)
- **우선순위:** Medium
- **신뢰도:** Likely
- **문제:** Zip Slip 검사(:592~598)와 Zip Bomb 상한(50GB 합산, 압축률 100x, :587~610)은 있으나, (a) 추출 전 디스크 여유 검사가 없다. 청크 업로드(`reserve_upload_disk_space`)와 달리 `unzip`은 잔여 공간을 확인하지 않으므로 작은 디스크에서 50GB 상한 이전에 볼륨이 가득 찬다. (b) `zf.extractall`(:612)은 비원자적 직접 쓰기이며, 실패 시(`BadZipFile` 포함) 부분 추출된 디렉터리를 정리하지 않는다. `_next_available_directory_path`로 만든 미완성 디렉터리가 목록에 그대로 노출된다.
- **발생 조건:** (a) 여유 공간보다 큰 ZIP을 쓰기 권한 있는 인증 사용자가 해제. (b) 손상된 ZIP 또는 해제 중 디스크 고갈.
- **영향:** 볼륨 고갈 시 동시 진행 중인 업로드·버전 백업·메타데이터 저장까지 연쇄 실패(서비스 전체 500). 부분 디렉터리는 사용자 혼란 + 수동 정리 부담. 기존 파일 덮어쓰기는 아니다(항상 새 디렉터리로 추출).
- **근거:** 함수 전체(:554~622)에 `reserve_upload_disk_space`·여유 검사가 없음(부재 확인). 실패 경로(:618~621)에 정리 코드 없음(부재 확인). Zip Slip 방어는 `abspath.startswith(extract_to_abs + os.sep)`로 유효함을 확인했으므로 traversal은 반증된다.
- **반증 확인:** 상위 caller — `ensure_mutation_allowed`·`ensure_path_access`는 권한만 보고 용량을 보지 않는다. 프레임워크 — `zipfile.extractall`은 원자성을 보장하지 않는다. 50GB 상한은 초대형 폭탄만 막을 뿐 디스크 크기와 무관한 고정값이라 소형 디스크 보호가 안 된다.
- **호출/영향 범위:** caller는 웹 UI 압축해제 1계열. callee는 `indexer.update_event`. 디스크 고갈 시 blast radius는 전역(모든 쓰기 경로).
- **권장 수정 방향:** 추출 전 `total_uncompressed_size`(헤더 합산, 이미 계산 중)와 `shutil.disk_usage` 비교 + 100MB 버퍼의 여유 검사를 추가하고, temp 디렉터리에 추출 후 `os.replace`급 원자적 승격(또는 실패 시 `shutil.rmtree` 정리)을 한다.
- **필요한 회귀 테스트:** Integration — 여유 공간을 작게 mock한 상태에서 대용량 ZIP 해제 요청이 507/413으로 거부되고 파일이 하나도 생기지 않음을 assert. Unit — 손상된 ZIP 입력 후 추출 디렉터리가 남아 있지 않음을 assert.

## 5. Potential Functional Gaps

- **Likely Gap — Google Drive 재시도 분류의 문자열 매칭:** `google_drive_client/http.py` :89의 `if attempt >= RETRY or " 4" in str(exc)`는 HTTP 429(재시도해야 할 rate-limit)를 재시도 대상에서 제외하고, 반대로 메시지에 " 4"가 들어간 무관한 에러를 재시도하지 않는다. 대형 동기화 중 일시적 429가 즉시 실패로 끝난다. 상태 코드 기반 분기(`exc.status in {429, 500, 502, 503, 504}` + `Retry-After` 존중)로 교체가 필요하다. 추정 아님 — 코드로 확인된 분류 오류이나 실서비스 재현은 못 했으므로 Gap으로 둔다.
- **Likely Gap — Python HTTPS adhoc 실패 시 조용한 HTTP 강등:** `server/thread.py` :58~66은 adhoc 인증서 실패 시 로그만 남기고 `http`로 계속 구동한다. 이때 `SESSION_COOKIE_SECURE=True`(`conf.use_https` 기준, `factory.py` :81)는 유지되므로 Secure 쿠키가 평문 HTTP에서 전달되지 않아 로그인이 깨진다(이전 감사 Go ISSUE-002와 동형). adhoc 실패율이 낮아 현실성은 낮다. 실패 시 시작 거부 + 명시 에러가 안전하다.
- **추정 — WebDAV 인증 시도 메모리의 만료 없음:** `features/webdav_server.py` :78~103의 `_webdav_auth_attempts`는 차단 해제된 항목만 삭제되고, 차단 한도(8회) 미만의 실패 기록은 만료되지 않는다. 키가 IP 기준이라 바운드는 되지만 장기 운영 시 증가한다. 주기 정리 대상(`cleanup.py`)에 포함되지 않았다. 단, 로그인 시도(`LOGIN_ATTEMPTS`) 쪽은 만료 정리가 있어 심각도는 낮다.
- **추정 — 청크 병합의 2배수 디스크 수요:** `chunk_finalize.py` :106~126은 청크 총량과 동일한 크기의 병합 temp를 한 번 더 쓰므로 순간 필요량은 선언 크기의 약 2배이다. `reserve_upload_disk_space`는 선언 크기 1회분 + 100MB만 확보하므로 거의 찬 디스크에서는 init 통과 후 merge에서 ENOSPC 500이 날 수 있다(세션 정리됨, 목표 파일 손상 없음). 대용량 업로드 지원(10GB)을 표방하므로 예약량에 병합 버퍼를 반영할 필요가 있다.
- **Confirmed Gap — Go/Python 공유 JSON 분기는 있으나 E2E parity 테스트는 Python 중심:** `test_backend_parity_contract.py`는 통과(35개 묶음 중 포함)하나, 감사에서 실행한 Go 테스트는 없다. Go 핸들러의 상태 코드·HTML/JSON 분기는 코드 대조로만 확인했다.

## 6. Documentation Mismatches

1. **Docker 배포는 사실상 Python 백엔드이다 (Confirmed).** README 아키텍처는 "Go 네이티브 코어 [기본 백엔드]" + "Go 이상 시 1초 만에 Python 폴백"을 설명하지만, `Dockerfile`에는 Go 툴체인·빌드 단계가 없고(`python:3.11-slim` + `pip install` + `COPY .`), `docker_entrypoint.py` :85~87은 werkzeug `make_server`로 Python WSGI를 직접 서빙한다(`go_process`·`start_server` 미사용). 즉 NAS/Docker 권장 경로에서는 Go의 성능상 이점이 적용되지 않는다. README의 성능 주장과 배포 현실이 어긋난다.
2. **`main.py` 독스트링 버전 표기가 구버전이다 (Confirmed).** `main.py` :3은 `v7.3.0`이라 적혀 있고, `README.md`·`APP_TITLE`(`core/config/defaults.py` :10, `APP_VERSION = "7.4.0"`)은 v7.4.0이다. 기능 영향은 없으나 릴리스 정합성 문제이다.
3. **`CLAUDE.md`가 없고 `AGENTS.md`는 gitignore 상태이다.** 작업 지시는 `README.md`·`CLAUDE.md`·`AGENTS.md` 확인을 요구하는데, 루트에 `CLAUDE.md` 파일이 없으며(확인 명령 결과 `MISSING`), `AGENTS.md`는 존재하지만 `.gitignore`에 등록되어 추적되지 않는다(`git status --ignored`에서 `!! AGENTS.md`). 에이전트 협업 문서의 추적·단일 진실 공급원이 불명확하다.
4. **429 메시지의 공정성 안내가 단건 다운로드 abort에는 해당하지 않는다 (Confirmed, ISSUE-004와 동일 근거).** `QUOTA_POLICY_NOTE`는 "전송된 바이트만 집계"를 약속하지만 `send_file` abort는 전액 유지이므로, 사용자 안내와 실제 정산이 다르다.
5. 불일치 없음으로 확인한 것: README의 "HTTPS는 Python 백엔드 전용" 다이어그램 주석은 `GO_HTTPS_BLOCKED` 거부 로직과 일치한다. Go 공유 링크의 HTML/JSON 이중 응답(이전 감사 ISSUE-005)은 `go-core/internal/handlers/share.go`의 `shareFail`·`sharePasswordPage`에서 Python 분기와 맞춰 구현되어 있다.

## 7. Recommended Fix Plan

### Phase 1 — Immediate

- ISSUE-002: 설정 로드 except 확장 + 손상 파일 백업 후 기본값 기동 (시작 거부 제거, 수정점 1곳).
- ISSUE-001: 청크 `cancel`의 COMPLETING 검사 또는 병합 루프의 세션 생존 확인 (취소 의미 복원).
- ISSUE-005: 압축 해제 전 디스크 여유 검사 + 실패 시 부분 추출물 정리 (볼륨 고갈의 전역 파급 차단).

### Phase 2 — Stability

- ISSUE-003: 휴지통 pending-확정 2단계 기록 또는 self-heal 스캔 (복원 정확도).
- ISSUE-004: 쿼터 버킷 통합(또는 합산 상한) + abort 케이스 429 문구 분리 (공정성·안내 정합).
- GDrive 재시도 분류를 상태 코드 기반으로 교체 + `Retry-After` 존중.
- Python adhoc HTTPS 실패 시 강등이 아닌 시작 거부로 변경.
- 청크 병합의 2배수 수요를 디스크 예약에 반영.

### Phase 3 — Structural

- WebDAV 인증 시도 기록에 TTL/주기 정리 편입.
- Docker 이미지의 Go 코어 포함 여부 결정(포함시키거나 README 성능 주장에 "Docker 제외" 명시).
- `CLAUDE.md`/`AGENTS.md` 추적 정책 정리 + 릴리스 버전 표기 단일화(APP_VERSION을 단일 진실 공급원으로).
- 전역 가변 상태(`UPLOAD_SESSIONS`, `SHARE_LINKS`, `TRANSCODE_SESSIONS`)의 책임 분리·테스트 가능성 개선(현행도 락 규율은 양호하므로 구조 개선 수준).

실제 코드는 수정하지 않았다.

## 8. Test Recommendations

- **Unit (ISSUE-002):** 입력 — 잘못된 UTF-8 바이트가 포함된 설정 파일. 기대 — `load()`가 예외 없이 완료되고, 손상 파일이 백업되며, 기본값으로 기동된다.
- **Integration (ISSUE-002):** 입력 — 손상된 설정 + `create_app()` + `GET /healthz`. 기대 — 200.
- **Concurrency (ISSUE-001):** 입력 — 병합 I/O를 지연시킨 상태에서 `complete` 스레드 + `cancel`. 기대 — 409(또는 명세된 거부 코드)이며 목표 파일 미생성.
- **Integration (ISSUE-003a):** 입력 — `_save_trash_metadata` 실패 주입 + `move_to_trash`. 기대 — 원본 파일이 원위치에 그대로 있고 halfway 커밋이 없다.
- **Unit (ISSUE-003b):** 입력 — 메타데이터 없는 `20250101_120000_<uuid>_report.pdf`. 기대 — 복원 결과가 `uuid_` 접두사 없는 원본명이거나 명시적 경고 반환.
- **Integration (ISSUE-004):** 입력 — 동일 세션에서 인증 다운로드와 공유 다운로드를 제한 합계 초과로 시도. 기대 — 합계 기준으로 429가 발생한다.
- **Unit (ISSUE-004 메시지):** 입력 — abort 시뮬레이션 후 429 응답 본문. 기대 — 단건 abort 케이스에서는 "실제 전송 바이트만 집계" 문구가 나가지 않는다.
- **Integration (ISSUE-005):** 입력 — `disk_usage.free`를 작게 mock + 대용량 ZIP 해제. 기대 — 507/413 거부이며 추출 파일 0개.
- **Unit (unzip 정리):** 입력 — 손상된 ZIP. 기대 — 추출 디렉터리 잔존 없음.
- **End-to-End (공유 흐름):** 입력 — 만료 1시간·최대 1회·비밀번호 포함 링크 생성 → 비밀번호 1회 실패(브루트포스 카운트) → 성공 다운로드 1회 → 2회째 시도. 기대 — `share_password.html` → 200(1회) → 429/만료 페이지, `download_count` 정확히 1.
- **End-to-End (청크 업로드):** 입력 — 3청크 중 1청크 누락 + 사이즈 불일치 + 중복 `complete`. 기대 — 400(size mismatch 계열), 두 번째 `complete`는 멱등 200(`idempotent: true`).
- **Platform-specific:** 입력 — Windows 예약어(`CON.txt`)·선행 점(`.hidden`)·200자 초과 파일명 업로드. 기대 — `safe_filename` 규칙通り 저장되고 목록에 노출된다. 입력 — NFC/NFD 한글 파일명. 기대 — 동일 파일로 취급된다.
- **Regression:** `test_backend_parity_contract.py`·`test_go_bind_and_https.py`를 수정마다 실행하고, Go 측 `shareFail`/`sharePasswordPage` 분기에 대한 `format=json` vs 브라우저 Accept 케이스를 쌍으로 유지한다.

## 9. Final Assessment

| 영역 | 평가 | 근거 |
|---|---|---|
| Functional Correctness | Acceptable | 핵심 흐름 정확. 잔여 결함은 취소 경합·중단 정산 등 좁은 조건에 한정 |
| Runtime Stability | Acceptable | 원자적 저장·락 규율·폴백이 갖춰짐. 시작 거부 1건(ISSUE-002)이 감점 요인 |
| Data Integrity | Acceptable | 병합/복원/스냅샷의 원자성 양호. 휴지통 메타 윈도우(ISSUE-003)는 복원 품질 문제로 한정 |
| Error Resilience | Needs Work | 손상 설정 크래시, unzip 무검사, GDrive 재시도 오분류, adhoc 강등이 집중 |
| Cross-platform Robustness | Acceptable | `validate_path`의 드라이브 불일치 처리, 예약어/정규화 확인. Linux/macOS 실기 검증은 미실시 |
| Test Confidence | Good | 13 + 35 passed, parity·보안 커버리지 존재. `test_batch_download` 1회 간헐 실패는 재실행 통과 |

**실제로 먼저 수정할 문제 3개:**

1. **[ISSUE-002] 손상된 설정 파일의 시작 크래시** — 수정 1곳으로 전체 시작 안정성이 올라가는 가성비 최우선.
2. **[ISSUE-005] 압축 해제의 디스크 검사·부분 정리 부재** — 볼륨 고갈이 전역 쓰기를 마비시키는 유일한 잔여 전역 파급 경로.
3. **[ISSUE-001] 병합 중 취소 무력화** — 사용자 조작 의미(취소)가 깨지는 실제 기능 오류이며 수정 범위도 `cancel` 1개 함수에 국한된다.

## 10. Remediation Status (2026-10-06, Phase 1~3 조치 기록)

> 본 섹션은 감사 이후 적용된 코드·문서 수정을 기록한다. 수정은 최소 diff 원칙을 따르며, 아래 테스트로 검증했다.

### Phase 1 — Immediate (적용됨, 선행 작업 기반 + 32 passed로 검증)

- ISSUE-001: 청크 `cancel`의 COMPLETING 상태 검사 (`chunk_finalize.py`).
- ISSUE-002: 설정 로드 except 확장 + 손상 파일 백업 후 기본값 기동 (`core/config/manager.py`).
- ISSUE-005: 압축 해제 전 디스크 여유 검사 + 실패 시 부분 추출물 정리 (`mutation_handlers.py`).

### Phase 2 — Stability (적용됨, 선행 작업 기반 + 32 passed로 검증)

- ISSUE-003: 휴지통 pending-확정 2단계 + `self_heal_trash_metadata` + uuid 접두사 제거 (`trash.py`).
- ISSUE-004: 세션/IP 합산 상한 (`reserve_combined_download_quota`) + 단건 abort용 429 문구 분리 (`QUOTA_DIRECT_NOTE`).
- GDrive 재시도 분류를 상태 코드 기반으로 교체 + `Retry-After` 존중 (`google_drive_client/http.py`).
- Python adhoc HTTPS 실패 시 강등이 아닌 시작 거부 (`server/thread.py`).
- 청크 init 예약에 병합 버퍼 반영 (2배수 수요, `UPLOAD_MERGE_RESERVATION_FACTOR`).

### Phase 3 — Structural + §6 문서 불일치 (본 작업에서 적용, 6 passed로 검증)

- WebDAV 인증 시도 기록에 TTL/주기 정리 편입: 실패 시 `last_attempt` 기록 + `cleanup_expired_webdav_auth_attempts()` 신설 + 5분 주기 정리(`server/cleanup.py`)에 편입 (`features/webdav_server.py`, `tests/test_audit_remediation_phase3.py`).
- Docker 문서 정합성: `Dockerfile`에 Go 빌드 단계가 없고 `docker_entrypoint.py`가 Python 백엔드를 직접 서빙한다는 사실을 README.md(한국어)/README_EN.md(영어) Docker 섹션에 명시. 이미지 변경 대신 문서 정정(최소 정직 수정)을 선택했다.
- `main.py` 독스트링의 구버전 표기(`v7.3.0`) 제거 — 버전은 `webshare_app/core/config/defaults.py`의 `APP_VERSION`(현재 7.4.0)이 단일 진실 공급원이며, `APP_TITLE`·`WebSharePro.spec`·`webshare.spec`이 이미 이를 참조한다.
- `CLAUDE.md` 부재·`AGENTS.md` 미추적: 의도적 untracked 정책임을 `.gitignore` 주석에 명시. 추적되는 정식 문서는 README.md / README_EN.md / PROJECT_AUDIT.md이다.
- §6 항목 4(429 안내 문구)는 Phase 2의 `QUOTA_DIRECT_NOTE` 분리로 해소됨을 코드로 재확인했다.

### 검증 결과

- `python -m pytest tests/test_audit_remediation_phase3.py -q` → **6 passed** (신규).
- `python -m pytest tests/test_audit_remediation_001_002_005.py tests/test_audit_remediation_phase2.py tests/test_audit_remediations.py tests/test_audit_remediations_phase2.py -q` → **32 passed** (기존 회귀).
- 미패치 확인(읽기 전용): HEAD의 `webdav_server.py`에는 정리 함수가 없고, `main.py`에는 `7.3.0`이 남아 있으며, README에는 Python 백엔드 명시가 없어 신규 테스트가 미패치 코드에서 실패함(ImportError/assert 실패 사유)을 확인했다.

### 남길 일 (미완)

- Go/Python E2E parity: Go 툴체인 검증을 생략했으므로 `go test ./...` 미실행. Python 측 parity 계약 테스트는 통과하나 Go 측 실행 확인은 남는다.
- 전역 가변 상태(`UPLOAD_SESSIONS`, `SHARE_LINKS` 등) 책임 분리: 현행 락 규율이 양호하여 구조 개선 수준으로 판단, 본 조치에서는 제외.
- Docker 이미지의 Go 코어 포함 여부는 이미지 변경이 아닌 문서 명시로 일단락. 실제 포함 결정은 빌드·배포 정책 판단이 필요하여 남긴다.

### 후속 검증 및 하네스 수정 (2026-10-06, v7.4.1)

- `go test ./...` 전체 통과, Go 바이너리 현 소스에서 재빌드.
- twin 계약 테스트 순서 의존 실패의 근본 원인 3건을 확정·수정했다.
  1. 가드 상태 오염: live 서버 fixture가 `app` fixture를 거치지 않아 이전 테스트의 IP 차단·쿼터를 상속 → fixture 기동 후 `reset_live_guard_state()`로 초기화(`tests/conftest.py`, `tests/test_twin_guard_isolation.py` 회귀 테스트).
  2. 개발 설정 오염: 테스트 실행이 저장소 루트의 `webshare_config.json`을 tmp 경로·테스트 해시로 덮어씀 → `app`/twin fixture에서 `CONFIG_FILE`을 tmp로 격리, 개발 설정 복원(폴더 `shared_files`, 기본 비밀번호, 시크릿 회전).
  3. POST 재시도 중복 실행: Windows loopback RST에 대한 무분별한 재시도가 공유 생성/삭제를 중복 실행(유령 토큰 + 삭제 실패로 입증) → `TwinClient`는 keep-alive 전송 + POST는 연결 거부 시에만 재시도.
- 전체 스위트 265 passed, `pyright` 0 errors, 패키징 게이트 통과.
- 잔여 한계: 응답 64KB 이상이 이 Windows loopback 환경에서 간헐적으로 잘리는 현상(순수 WSGI + curl로도 재현되는 환경 문제, 제품 로직 아님)이 twin 실행 시간을 늘린다. LAN/컨테이너 실제 배포 경로에서는 해당하지 않는다.

