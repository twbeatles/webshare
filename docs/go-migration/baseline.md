# Go Migration Baseline (Phase 0)

> 작성일: 2026-09-25 · 대상: WebShare Pro v7.2.5 · 계획서: [00-migration-plan.md](00-migration-plan.md) Phase 0

## 1. Python 테스트 baseline

- `python -m pytest -q` → **144 passed, 1 skipped** (약 16초)
- 전체 출력: [python-test-baseline.txt](python-test-baseline.txt)
- 실패 없음. 이후 모든 Phase 종료 시 이 baseline과 비교한다.

## 2. Endpoint inventory

- Flask `url_map`에서 자동 추출 → [api-contract-baseline.json](api-contract-baseline.json)
- static 제외 **125 method+path 항목** (rule 기준 약 106개).
- 대표 route (URL 구조는 migration 중 변경 금지):
  - `/browse/`, `/browse/<path>` · `/download/<path>` · `/zip/<path>`
  - `/batch_download/<path>` · `/search` · `/file_info/<path>` · `/api/zip_preview/<path>`
  - 청크 업로드 3단계: `POST /upload/chunk/init` → `POST /upload/chunk/<session_id>` → `POST /upload/chunk/<session_id>/complete` (+ `/cancel`)
  - 상태: `GET /healthz`, `GET /readyz` (Python에도 이미 존재 — Go skeleton parity 대상)
  - 언어: `POST /set_language` (표준), `GET /set_language/<lang>` (legacy, `Deprecation: true` + `Sunset: 2026-08-31` 헤더 유지)
- auth/CSRF 매핑: endpoint별 인증·예외 의미는 Milestone B에서 확정한다. 전역 규칙(factory.py):
  - `POST/PUT/PATCH/DELETE` + 로그인 상태 → CSRF 검증 (예외 endpoint: `main.index`, `share.access_share_link`)
  - JSON 오류 스키마: `{"success": false, "error", "code", "message", "request_id"}` + `X-Request-ID` 헤더
  - IP 화이트리스트 → IP 차단 순으로 선검사, 세션 타임아웃 만료 시 AJAX/`/api/`는 401+`redirect:/`

## 3. Persistence 위치

| 데이터 | 위치/방식 | 비고 |
|---|---|---|
| 설정 JSON | `CONFIG_FILE` (`webshare_app/core/config/defaults.py` 참조, 루트 `webshare_config.json`) — 키 23개 | Go는 스키마를 새로 만들지 않고 그대로 읽기 |
| Flask secret | OS별 앱 config dir (`WebSharePro/secret_key`, `WEBSHARE_CONFIG_DIR` override 가능) | `ensure_config_secret_key`로 이관 |
| metadata / audit log / share links / permissions / cloud config / jobs / duplicates / download tracker / login attempts | 런타임 초기화는 `webshare_app/server/bootstrap.py::ensure_runtime_initialized` 참조 | 포맷 변경 시 old reader → migration → atomic write → 호환성/롤백 테스트 순서 준수 |
| 검색 인덱스 스냅샷 | `features/search_indexer` (`indexer.load_snapshot(folder)`) | Go 1차는 bounded fallback search, 인덱스는 분리 단계 |

설정 키 23개: `folder, port, admin_pw, guest_pw, allow_guest_upload, display_host, use_https,
session_timeout, enable_notifications, enable_versioning, minimize_to_tray, language,
ip_whitelist, daily_download_limit, daily_bandwidth_limit_mb, disk_warning_threshold,
trash_auto_delete_days, close_to_tray, autostart, trusted_proxies, trusted_hops,
webdav_allow_insecure, secret_key`

## 4. 보안 semantics 요약 (Milestone B 이관 대상)

- 비밀번호 3형식 모두 검증 유지: Werkzeug PBKDF2 / legacy SHA-256 / legacy 평문. Argon2·bcrypt 전환 금지.
- 세션: `logged_in, role(admin/guest), session_id, language, last_active` + `ACTIVE_SESSIONS` 추적.
- 쿠키: HttpOnly + SameSite=Lax (+ HTTPS 시 Secure).
- Path 보안 (`normalize_relative_path, validate_path, ensure_path_access, ...`)은 모든 파일 API보다 먼저 port.
- Control endpoint (`POST /_control/shutdown`)는 loopback + 실행 시 생성 random 256-bit 토큰, config·로그·API에 노출 금지.

## 5. 발견 사항 (이번 Phase 범위 외, 후속 판단 필요)

1. 루트 `webshare_config.json`의 `folder`가 pytest 임시 경로(`pytest-of-soulb/...`)를 가리킴 —
   테스트 실행이 실제 설정 파일을 덮어쓴 흔적으로 보임. 설정 격리(`WEBSHARE_CONFIG_DIR`)를 CI/로컬 실행에 적용할 것.
2. 루트 `routes/`, `security/`, `utils/` 등은 shim, 실제 구현은 `webshare_app/` 하위 — Go port 기준은 `webshare_app/`으로 고정.
3. **Go 툴체인 미설치 + Docker 데몬 미기동**으로 `go test ./...`, `go vet ./...`, `webshare-core.exe` 빌드 검증 불가.
   `go-core/` 스켈레톤 소스는 작성 완료했으나 빌드 검증 전까지 Milestone A acceptance 미충족 상태로 둔다.

## 6. 다음 단계

Milestone A 나머지: Go 툴체인 확보 후 `go test ./...` + `go vet ./...` + `serve` 기동/종료 확인 →
Milestone B (Auth / Session / CSRF / Permission foundation).
