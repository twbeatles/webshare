# WebShare Pro — Go Server Core 점진 전환 구현 계획

> 대상 저장소: `twbeatles/webshare`  
> 목적: 현재 PyQt6 데스크톱 GUI와 웹 프론트엔드는 유지하면서 Flask/Werkzeug 기반 서버 코어를 Go 네이티브 서버로 점진 전환한다.  
> 전략: **전면 재작성 금지 / Python 서버를 reference implementation으로 유지 / Go 서버와 contract parity 확보 후 단계적 cutover**  
> 우선순위: **파일 안전성 > 보안 > API 호환성 > 데이터 호환성 > 롤백 가능성 > 성능**

---

## 0. 문서 사용 방법

이 문서는 구현 에이전트에게 그대로 전달하는 실행 계획서다.

에이전트는 임의로 전체 아키텍처를 다시 설계하지 말고, 아래 Phase 순서를 지켜 작업한다.

각 Phase가 끝날 때마다 반드시:

1. 기존 Python 테스트 baseline과 비교
2. Go 단위 테스트
3. Python ↔ Go contract parity 테스트
4. 보안 회귀 테스트
5. 파일 integrity 테스트
6. 변경 문서화

를 수행한다.

**앞 단계의 acceptance condition이 충족되지 않은 상태에서 다음 Phase로 넘어가지 않는다.**

---

# 1. 구현 전 필수 확인

먼저 아래 파일과 디렉터리를 읽고 현재 구조를 확인한다.

```text
README.md
PROJECT_AUDIT.md

main.py
server.py
config.py

webshare_app/
├── app/
├── core/
├── server/
├── services/
├── routes/
├── security/
├── features/
├── utils/
└── gui/

templates/
static/
tests/
```

특히 다음 파일은 필수 확인 대상이다.

```text
webshare_app/app/factory.py

webshare_app/server/
├── controller.py
├── thread.py
├── bootstrap.py
└── cleanup.py

webshare_app/services/
├── file_service.py
├── upload_service.py
├── media_service.py
└── share_service.py

webshare_app/routes/file_routes/
├── __init__.py
├── browse_handlers.py
├── download_handlers.py
├── mutation_handlers.py
└── path_utils.py

webshare_app/routes/upload_routes/
├── __init__.py
├── chunk_init.py
├── chunk_transfer.py
└── chunk_finalize.py

webshare_app/security/
├── auth.py
├── csrf.py
├── permissions.py
├── ip_blocker.py
└── deployment_guard.py

webshare_app/utils/
├── api_errors.py
├── file_utils.py
├── listing.py
├── request_policy.py
└── zip_utils.py

webshare_app/features/
├── audit_log.py
├── crypto.py
├── duplicates.py
├── job_store.py
├── metadata.py
├── runtime_state.py
├── search_indexer/
├── share_links_store.py
├── transcoder.py
├── trash.py
└── webdav_server.py
```

---

# 2. 저장소 구조 해석 시 주의

현재 저장소에는 루트의 다음 패키지와:

```text
routes/
features/
security/
utils/
gui/
```

실제 구현 패키지인 다음 경로가 함께 존재한다.

```text
webshare_app/routes/
webshare_app/features/
webshare_app/security/
webshare_app/utils/
webshare_app/gui/
```

루트 패키지 상당수는 backward compatibility용 shim이다.

따라서:

- 파일 크기만 보고 구현 위치를 판단하지 않는다.
- import 경로만 보고 실제 코드 소유권을 판단하지 않는다.
- Go migration 분석 및 port 대상은 기본적으로 `webshare_app/` 실제 구현을 기준으로 한다.

---

# 3. 현재 기술 구조

현재 주요 서버 구조:

```text
PyQt6 Desktop GUI
        │
        │ start_server()
        ▼
Python ServerThread
        │
        ▼
Werkzeug threaded server
        │
        ▼
Flask Application
        │
        ├── Authentication / Session / CSRF
        ├── File browse
        ├── Download / ZIP
        ├── Upload / Chunk Upload
        ├── File mutation
        ├── Metadata
        ├── Trash / Versioning
        ├── Share links
        ├── Search
        ├── Duplicate finder
        ├── Media preview / streaming
        ├── WebDAV
        ├── Cloud sync
        ├── Audit log
        └── Admin APIs
```

현재 서버 lifecycle은 대략:

```text
PyQt
→ webshare_app.server.controller
→ ServerThread
→ Flask app
→ Werkzeug make_server
```

이다.

---

# 4. 목표 구조

최종 목표:

```text
PyQt6 Desktop GUI
        │
        │ subprocess
        ▼
webshare-core.exe
        │
        ▼
Go HTTP Server
        │
        ├── Auth / Session / CSRF
        ├── Permission / Path Security
        ├── File Browse
        ├── Download / Range / ZIP
        ├── Upload / Chunk Upload
        ├── Mutation
        ├── Metadata / Trash
        ├── Share
        ├── Search
        ├── Duplicate Scan
        ├── Media
        ├── Audit
        └── Admin
```

Headless 환경:

```text
webshare-core serve
```

로 독립 실행 가능해야 한다.

---

# 5. 이번 migration에서 유지할 것

이번 작업에서는 다음을 유지한다.

```text
PyQt6 Desktop GUI
templates/
static/
현재 웹 UI/UX
현재 URL route
현재 config 형식
현재 persistent data 형식
현재 permission semantics
현재 share-link semantics
현재 trash/version semantics
```

---

# 6. 이번 migration에서 하지 않을 것

다음은 이번 작업 범위가 아니다.

```text
PyQt6 → Tauri 전환
PyQt6 → C# 전환
프론트엔드 React/Vue 재작성
API v2 전면 재설계
DB schema 전면 재설계
인증 체계 전면 재설계
WebDAV 프로토콜 재설계
Google Drive sync 재설계
ffmpeg 대체 구현
```

또한 성능을 이유로 기존 보안 검사를 제거하지 않는다.

---

# 7. 절대 안전 규칙

## 7.1 파일 시스템

테스트 중 실제 사용자 파일을 절대 사용하지 않는다.

반드시 다음만 사용한다.

```text
pytest tmp_path
tempfile
Go t.TempDir()
synthetic fixtures
```

금지:

```text
실제 Documents
Desktop
Downloads
사용자 홈 전체
C:\
D:\
저장소 상위 디렉터리
```

다음 명령을 프로젝트 외부에 실행하지 않는다.

```text
rm -rf
rmdir /s
Remove-Item -Recurse -Force
```

---

## 7.2 destructive operation

다음 테스트는 반드시 임시 fixture에서만 수행한다.

```text
delete
rename
move
overwrite
trash
restore
unzip
batch delete
chunk finalize
```

---

## 7.3 데이터

다음 persistent data를 migration 과정에서 자동 삭제하거나 초기화하지 않는다.

```text
config
metadata
trash metadata
share link store
audit log
runtime state
job state
search index
cloud sync state
```

포맷 변경이 필요한 경우:

```text
old reader
→ migration
→ atomic write
→ compatibility test
→ rollback test
```

순서를 지킨다.

---

# 8. 권장 Go 프로젝트 구조

저장소 루트에 다음을 추가한다.

```text
go-core/
├── go.mod
├── go.sum
│
├── cmd/
│   └── webshare-core/
│       └── main.go
│
├── internal/
│   ├── app/
│   │   ├── app.go
│   │   └── lifecycle.go
│   │
│   ├── config/
│   │   ├── config.go
│   │   ├── loader.go
│   │   └── compatibility.go
│   │
│   ├── server/
│   │   ├── server.go
│   │   ├── router.go
│   │   ├── middleware.go
│   │   └── control.go
│   │
│   ├── auth/
│   │   ├── password.go
│   │   ├── session.go
│   │   └── csrf.go
│   │
│   ├── permission/
│   │   ├── permissions.go
│   │   └── path_policy.go
│   │
│   ├── files/
│   │   ├── path.go
│   │   ├── listing.go
│   │   ├── download.go
│   │   ├── mutation.go
│   │   └── zip.go
│   │
│   ├── upload/
│   │   ├── simple.go
│   │   ├── session.go
│   │   ├── chunk.go
│   │   └── finalize.go
│   │
│   ├── search/
│   ├── metadata/
│   ├── trash/
│   ├── share/
│   ├── audit/
│   ├── media/
│   ├── duplicate/
│   └── persistence/
│
├── pkg/
│   └── api/
│       ├── response.go
│       └── errors.go
│
└── tests/
    ├── contract/
    ├── integration/
    ├── security/
    └── benchmark/
```

초기부터 지나치게 복잡한 인터페이스/DI 프레임워크를 만들지 않는다.

---

# 9. 전체 단계 요약

```text
Phase 0   Python baseline 확보
Phase 1   Go skeleton + health/readiness
Phase 2   PyQt ↔ Go lifecycle
Phase 3   Config compatibility
Phase 4   Auth / Session / CSRF / Error Contract
Phase 5   Path security / Permission core
Phase 6   Read-only file API
Phase 7   Download / Range / ZIP
Phase 8   File mutation
Phase 9   Trash / Versioning
Phase 10  Chunk Upload
Phase 11  Search
Phase 12  Metadata / Share / Audit
Phase 13  Duplicate scanner
Phase 14  Media streaming
Phase 15  WebDAV / Cloud Sync
Phase 16  Packaging / Docker
Phase 17  Default backend cutover
Phase 18  Python backend deprecation
```

---

# 10. Phase 0 — Python baseline 확보

## 목표

Go 코드 작성 전에 현재 Python backend 동작을 고정한다.

## 수행

```powershell
python -m pytest -q
```

현재 실패가 있다면 별도로 기록한다.

특히 다음 테스트군 baseline을 저장한다.

```text
tests/test_api_compatibility.py
tests/test_download_limits.py
tests/test_permissions_enforcement.py
tests/test_security_hardening_724.py
tests/test_security_policies.py
tests/test_upload_integrity.py
tests/test_persistence_and_metrics.py
tests/test_implementation_regressions.py
tests/test_review_remediations.py
```

---

## API inventory

Flask route table을 추출해 다음 파일을 생성한다.

```text
docs/go-migration/api-contract-baseline.json
```

예:

```json
{
  "method": "GET",
  "path": "/download/<path>",
  "auth": "guest+",
  "csrf": false,
  "response": "file",
  "status_codes": [200, 400, 403, 404, 429]
}
```

가능하면 Flask `url_map`에서 자동 생성한다.

---

## 산출물

```text
docs/go-migration/
├── baseline.md
├── api-contract-baseline.json
└── python-test-baseline.txt
```

---

## Acceptance

- 기존 테스트 baseline 기록 완료
- endpoint inventory 완료
- 주요 persistence 위치 목록화 완료

---

# 11. Phase 1 — Go skeleton

## 목표

사용자 기능 없이 Go 서버 프로세스의 기본 실행 구조만 만든다.

필수 명령:

```text
webshare-core serve
webshare-core version
webshare-core check-config
```

필수 옵션:

```text
--config
--host
--port
--parent-pid
```

---

## Health endpoint

```text
GET /healthz
```

예:

```json
{
  "status": "ok",
  "backend": "go",
  "version": "0.1.0"
}
```

---

## Readiness endpoint

```text
GET /readyz
```

다음 조건이 충족된 경우만 200:

```text
config loaded
shared folder exists
shared folder accessible
runtime initialized
HTTP listener ready
```

---

## Acceptance

```text
go test ./...
go vet ./...
```

통과.

Windows에서:

```text
webshare-core.exe serve
```

기동 및 종료 가능.

---

# 12. Phase 2 — PyQt ↔ Go process lifecycle

## 목표

기존 GUI 인터페이스를 유지하면서 Go subprocess를 실행한다.

신규:

```text
webshare_app/server/go_process.py
```

책임:

```text
Go binary 경로 탐색
subprocess 시작
startup readiness 확인
stdout/stderr 수집
health polling
graceful shutdown
crash detection
startup error 반환
```

---

## 기존 interface 유지

다음 GUI-facing 함수 semantics를 유지한다.

```python
start_server()
stop_server()
is_server_running()
get_server_startup_error()
```

GUI 코드 각 위치에서 직접:

```python
if go:
```

분기를 반복하지 않는다.

server controller 한 곳에서 backend를 추상화한다.

---

## Backend 선택

개발 단계:

```text
WEBSHARE_SERVER_BACKEND=python
WEBSHARE_SERVER_BACKEND=go
```

기본값:

```text
go  (Milestone J 전환 완료 — 이전 기본값 python)
```

Go backend가 전체 gate를 통과하기 전 기본값을 바꾸지 않는다.
(Milestone J에서 gate 통과 후 전환함.)

---

# 13. Phase 2-1 — 안전한 control endpoint

Go shutdown용 public API를 만들지 않는다.

Python launcher가 매 실행 시 random token을 생성한다.

예:

```text
WEBSHARE_CONTROL_TOKEN=<random 256-bit>
```

Go:

```text
POST /_control/shutdown
```

조건:

```text
127.0.0.1 / ::1 only
AND
control token match
```

토큰은:

```text
config 저장 금지
로그 출력 금지
API 반환 금지
```

---

# 14. Phase 3 — Config compatibility

현재 Python ConfigManager의 schema를 그대로 읽는다.

주요 설정:

```text
folder
port
admin_pw
guest_pw
allow_guest_upload
display_host
use_https
session_timeout
enable_notifications
enable_versioning
minimize_to_tray
language
ip_whitelist
daily_download_limit
daily_bandwidth_limit_mb
disk_warning_threshold
trash_auto_delete_days
close_to_tray
autostart
trusted_proxies
trusted_hops
webdav_allow_insecure
secret_key
```

---

## 규칙

Go가 새 config schema를 만들지 않는다.

Python rollback 시 동일 config를 읽을 수 있어야 한다.

쓰기 시:

```text
temp file
→ fsync 가능 시 수행
→ atomic rename
```

형태를 사용한다.

---

# 15. Phase 4 — Authentication

현재 password compatibility:

```text
Werkzeug PBKDF2
legacy SHA-256
legacy plaintext
```

Go가 세 형식을 모두 검증해야 한다.

기존 Python에서 생성된 비밀번호 hash를 Go에서 로그인할 수 있어야 한다.

Go에서 저장한 hash를 Python rollback backend도 읽을 수 있어야 한다.

따라서 이번 migration에서:

```text
Argon2 전환
bcrypt 전환
```

은 하지 않는다.

---

# 16. Phase 4-1 — Session

기존 session 의미 유지:

```text
logged_in
role
session_id
language
last_active
```

역할:

```text
admin
guest
```

Cookie:

```text
HttpOnly
SameSite=Lax
Secure when HTTPS
```

session timeout도 기존과 동일하게 동작해야 한다.

---

# 17. Phase 4-2 — CSRF

기존 HTML/JavaScript contract를 유지한다.

현재:

```html
<meta name="csrf-token" ...>
```

기반 흐름과 header/form token 사용 방식을 보존한다.

다음 state-changing method는 CSRF 검사:

```text
POST
PUT
PATCH
DELETE
```

기존 예외 route의 의미도 그대로 유지한다.

---

# 18. Phase 4-3 — Request ID / Error Schema

현재 JSON 오류 contract를 유지한다.

최소:

```json
{
  "success": false,
  "error": "...",
  "code": "...",
  "message": "...",
  "request_id": "..."
}
```

Response:

```text
X-Request-ID
```

유지.

Python test의 `_assert_error_schema()`와 같은 semantics를 Go contract test에도 적용한다.

---

# 19. Phase 5 — Path Security Core

이 단계는 모든 파일 API보다 먼저 끝내야 한다.

Port 대상:

```text
normalize_relative_path
validate_path
ensure_path_access
is_protected_system_path
build_path_capabilities
```

---

## 차단 대상

반드시 테스트:

```text
../
..\

mixed slash
URL encoded traversal
double encoded traversal
absolute Windows path
drive path
UNC path
symlink escape
junction escape
case-insensitive Windows bypass
.webshare protected path
hidden protected path
```

단순:

```go
filepath.Join(root, input)
```

만으로 검증 완료로 간주하지 않는다.

canonicalized final path가 반드시 root 내부인지 확인한다.

---

# 20. Phase 5-1 — Permission parity

기존 role/permission semantics를 보존한다.

최소 action:

```text
read
write
delete
rename
move
copy
upload
mkdir
edit
trash
unzip
```

특히:

```text
allow_guest_upload
protected path
parent write permission
```

동작을 기존 Python과 동일하게 맞춘다.

---

# 21. Phase 6 — Read-only File API

첫 실제 사용자 기능은 destructive operation이 없는 읽기 경로부터 이관한다.

순서:

```text
1. directory listing
2. file info
3. search fallback
4. ZIP preview
5. single download
6. folder ZIP
7. batch ZIP
```

---

## 유지할 기존 route

대표:

```text
/browse/
/browse/<path>

/download/<path>

/zip/<path>

/batch_download/<path>

/search

/file_info/<path>

/api/zip_preview/<path>
```

migration 중 URL 구조를 변경하지 않는다.

---

# 22. Phase 6-1 — Directory listing parity

다음 항목 parity 확인:

```text
name
path
is_dir
size
modified
type
capabilities
pagination
sort
query
permission filtering
```

대량 폴더에서도 모든 항목을 불필요하게 메모리에 올리지 않도록 검토한다.

---

# 23. Phase 7 — Download

Go 구현 원칙:

```text
streaming
bounded memory
http.ServeContent 또는 동등한 Range 구현
io.Copy / io.CopyBuffer
```

대용량 파일 전체를 메모리에 읽지 않는다.

---

## 기존 동작 유지

```text
permission
path validation
download quota
bandwidth quota
audit log
recent files
Content-Type
Content-Length
Content-Disposition
HTTP Range
status code
```

---

# 24. Phase 7-1 — ZIP

가능하면 Go:

```text
archive/zip
io.Pipe
```

기반 streaming ZIP 사용.

다만 compatibility가 깨지면 초기에는 temp ZIP 방식을 사용해도 된다.

ZIP 내부 모든 파일에 대해 각각:

```text
path security
read permission
protected path
```

검사를 수행한다.

상위 폴더 permission만 보고 전체 subtree를 허용하지 않는다.

---

# 25. Phase 8 — File Mutation

Read-only API parity 이후 진행한다.

대상:

```text
mkdir
rename
copy
move
delete
batch delete
unzip
simple upload
```

---

## Conflict policy

기존:

```text
rename
fail
overwrite
```

의 의미를 유지한다.

---

## Atomicity

가능한 작업은:

```text
staging
→ validation
→ replace/rename
```

형태로 구현한다.

중간 실패 시:

```text
원본 유지
부분 파일 없음
```

을 보장한다.

---

# 26. Phase 9 — Trash / Versioning

기존:

```text
trash
restore
version backup
```

schema와 semantics를 유지한다.

필수 cross-backend 테스트:

```text
Python에서 trash
→ Go에서 restore

Go에서 trash
→ Python에서 restore
```

---

# 27. Phase 10 — Chunk Upload

현재의 3단계 흐름을 유지한다.

```text
init
→ chunk transfer
→ complete
```

대표 API:

```text
POST /upload/chunk/init
POST /upload/chunk/<session_id>
POST /upload/chunk/<session_id>/complete
POST /upload/chunk/<session_id>/cancel
```

---

# 28. Chunk Upload 유지 조건

다음 의미를 그대로 보존한다.

```text
DEFAULT_CHUNK_SIZE
MAX_CHUNK_SIZE

owner별 active session 제한
owner별 pending bytes 제한

free-space reservation
session ownership
session expiration
completed TTL

uploaded_bytes
total_size
total_chunks
chunk index completeness
idempotent complete
```

---

# 29. Chunk Upload commit 구조

최종 target에 직접 chunk를 append하지 않는다.

권장:

```text
temporary upload directory
        ↓
chunk files
        ↓
merge temp file
        ↓
validate actual size
        ↓
atomic rename
        ↓
target
```

complete 시 검사:

```text
ownership
permission
chunk count
chunk indexes
chunk size
total size
free space reservation
target conflict
```

실패 시 target에 부분 파일이 남지 않아야 한다.

---

# 30. Phase 11 — Search

첫 버전에서는 기존 Python search system을 한 번에 재설계하지 않는다.

## Step 1

Go bounded fallback search 구현:

```text
max_results
time_budget
permission filtering
protected path skip
hidden path skip
```

## Step 2

필요 시:

```text
fsnotify
+
persistent search index
```

도입.

후보:

```text
SQLite FTS5
```

search redesign은 file core migration과 분리한다.

---

# 31. Phase 12 — Metadata

Port 대상:

```text
tag
note
bookmark
file metadata
recent file
```

기존 저장 포맷을 유지한다.

Cross-backend 테스트:

```text
Python write → Go read
Go write → Python read
```

---

# 32. Phase 12-1 — Share Link

보존:

```text
share ID
target path
expiration
password
download count
download limit
access tracking
```

필수:

```text
Python-created link → Go access
Go-created link → Python access
```

---

# 33. Phase 12-2 — Audit / Runtime State

Port:

```text
audit log
active session
request stats
bytes sent
runtime state
```

로그 또는 상태 파일 포맷이 기존과 공유되는 경우 schema를 변경하지 않는다.

---

# 34. Phase 13 — Duplicate Finder

Go에 적합한 기능이지만 destructive operation과 분리한다.

Pipeline:

```text
filesystem walk
→ size grouping
→ candidate filtering
→ hash
→ duplicate group
```

초기 Go duplicate scanner는 read-only.

삭제는 반드시 일반 mutation layer를 사용한다.

duplicate module 안에서 직접:

```text
os.Remove
```

하지 않는다.

---

# 35. Phase 14 — Media

대상:

```text
video/audio streaming
Range
thumbnail
preview
HLS
transcoding
```

FFmpeg를 Go로 다시 구현하지 않는다.

기존 external ffmpeg 방식을 유지한다.

Go는:

```text
process lifecycle
stream serving
HLS serving
cleanup
cancellation
```

을 담당한다.

---

# 36. Phase 15 — WebDAV / Cloud Sync

마지막 단계.

핵심 파일 서버 migration과 동시에 옮기지 않는다.

전체 cutover 이전까지 Python backend가 기능을 계속 제공할 수 있게 한다.

필요하면 feature capability 정보를 expose한다.

예:

```json
{
  "webdav": false,
  "cloud_sync": false
}
```

단, 기존 사용자를 강제로 Go backend로 전환하여 기능을 잃게 만들지 않는다.

---

# 37. HTML Template 전략

현재:

```text
templates/
static/
```

을 최대한 재사용한다.

Go에서는 우선:

```text
html/template
```

사용을 검토한다.

Jinja-specific syntax만 최소 수정한다.

Template input 데이터 구조 유지:

```text
logged_in
items
current_path
breadcrumbs
pagination
role
can_modify
translations
current_lang
capabilities
csrf_token
```

웹 UI 디자인 재작성 금지.

---

# 38. 국제화

현재:

```text
ko
en
```

지원 유지.

표준 API:

```text
POST /set_language
```

Legacy:

```text
GET /set_language/<lang>
```

도 compatibility 기간 동안 유지.

기존 contract:

```text
Deprecation: true
Sunset: 2026-08-31
```

헤더도 보존한다.

---

# 39. Contract Test Harness

동일 fixture를:

```text
Python backend
Go backend
```

양쪽에 보내 결과를 비교한다.

비교:

```text
status code
JSON
headers
cookies
redirect
Content-Type
Content-Disposition
file bytes
filesystem side effect
persistent state
```

다음 동적 값은 normalize:

```text
request_id
csrf token
session_id
timestamp
temp path
```

---

# 40. Golden Fixture 구조

```text
tests/fixtures/go_migration/
├── config/
├── filesystem/
├── uploads/
├── permissions/
├── metadata/
├── trash/
├── share_links/
└── expected/
```

실제 사용자 파일이나 시크릿을 fixture로 넣지 않는다.

---

# 41. 필수 보안 회귀 테스트

최소:

```text
path traversal
symlink escape
junction escape

unauthenticated access
guest → admin access
guest mutation denied

CSRF missing
CSRF invalid

expired session

IP whitelist
IP blocking
trusted proxy spoofing

download limit
bandwidth limit

oversized upload
chunk cumulative overflow
chunk session hijacking

ZIP traversal
ZIP bomb

protected .webshare path

share password failure
share brute-force policy
```

Python/Go 결과가 동등해야 한다.

---

# 42. Benchmark Suite

추가:

```text
benchmarks/go_migration/
```

Synthetic dataset 사용.

---

## 42.1 Directory listing

```text
1,000 files
10,000 files
100,000 files
```

측정:

```text
cold latency
warm latency
p50
p95
peak RSS
CPU
```

---

## 42.2 Download

```text
100 MB
1 GB
10 GB optional/manual
```

측정:

```text
throughput
TTFB
CPU
RSS
```

---

## 42.3 Concurrent Download

```text
1
10
50
100
```

동시 요청.

---

## 42.4 Chunk Upload

```text
100 MB
1 GB
10 GB optional/manual
```

---

## 42.5 ZIP

```text
1,000 small files
10,000 small files
mixed large files
```

---

# 43. 성능 acceptance

정확한 숫자를 migration 전에 임의로 약속하지 않는다.

동일 장비에서 Python baseline과 비교한다.

최소:

```text
기능 parity PASS
보안 regression PASS
data compatibility PASS
file integrity PASS
```

가 먼저다.

그 후:

```text
download throughput
directory p95
concurrency
RSS
CPU
```

를 기록한다.

성능이 조금 개선되더라도 correctness가 깨지면 cutover 금지.

---

# 44. Packaging

Go 안정화 후:

```text
webshare-core.exe
```

를 PyInstaller 배포에 포함한다.

현재 `.spec`에 binary asset을 추가한다.

실행 환경:

```text
development
PyInstaller sys._MEIPASS
portable build
installer
```

모두에서 binary 탐색 테스트를 작성한다.

---

# 45. Headless 배포

최종 목표:

```bash
webshare-core serve --config /config/webshare.json
```

Linux/NAS/Docker에서 Python GUI 없이 실행 가능.

Go backend cutover 후 Docker image에서는 Python runtime 제거를 검토한다.

단, Python-only 기능이 남아 있는 동안 기존 Docker 이미지를 제거하지 않는다.

---

# 46. CI

GitHub Actions에 최소 추가:

```text
Go format
Go test
Go vet
Go build Windows
Go build Linux
Python test
Contract test
```

예:

```text
python-tests
go-tests
contract-tests
windows-build
linux-build
```

---

# 47. Milestone A — Skeleton

완료 조건:

```text
Go module 생성
webshare-core build
serve 실행
healthz
readyz
config read
graceful shutdown
Python GUI launcher
```

Go는 아직 실제 file route를 처리하지 않는다.

---

# 48. Milestone B — Security Foundation

완료 조건:

```text
password compatibility
session
CSRF
request ID
error schema
IP rules
permission engine
path security
```

파일 mutation은 아직 구현하지 않는다.

---

# 49. Milestone C — Read-only File Core

완료 조건:

```text
browse
file info
download
Range
ZIP preview
folder ZIP
batch ZIP
search fallback
```

Python parity test PASS.

---

# 50. Milestone D — Mutation Core

완료 조건:

```text
mkdir
rename
copy
move
delete
batch delete
unzip
simple upload
```

Atomicity 및 rollback test PASS.

---

# 51. Milestone E — Chunk Upload

완료 조건:

```text
init
transfer
complete
cancel
owner isolation
disk reservation
size integrity
idempotency
expiration cleanup
```

기존 `test_upload_integrity.py` 수준 이상의 회귀 테스트 PASS.

---

# 52. Milestone F — Persistent Features

완료 조건:

```text
metadata
trash
versioning
share links
audit
runtime state
```

Cross-backend compatibility PASS.

---

# 53. Milestone G — Advanced File Features

완료 조건:

```text
search index
duplicate scan
media streaming
HLS
transcoder orchestration
```

---

# 54. Milestone H — Optional Services

완료 조건:

```text
WebDAV
cloud sync
network utilities
```

또는 명확히 Python-only로 남길 기능을 문서화한다.

---

# 55. Milestone I — Packaging

완료 조건:

```text
Windows EXE bundle
installer
portable
Docker
headless
auto-update compatibility
```

---

# 56. Milestone J — Go Default Cutover

Go를 기본 backend로 바꾸기 위한 필수 gate:

```text
전체 Python regression baseline 통과
Go tests 통과
contract parity 통과
security tests 통과
Windows packaging smoke 통과
headless smoke 통과
파일 integrity 통과
기존 config/data compatibility 통과
rollback 가능
```

이후:

```text
default = go
fallback = python
```

으로 변경한다.

---

# 57. Python Backend 제거 금지

Go 기본 전환 후에도 한동안 Python backend를 제거하지 않는다.

최소 다음 release cycle 동안 유지한다.

```text
Go default
Python legacy fallback
```

실사용 안정성이 확인된 이후 별도 문서로 제거 여부를 결정한다.

---

# 58. Rollback 전략

항상:

```text
Go failure
→ stop Go
→ Python server start
```

가 가능해야 한다.

Rollback 시:

```text
config 변환 불필요
persistent data 변환 불필요
frontend 변경 불필요
```

이어야 한다.

이 요구사항 때문에 migration 중 기존 포맷을 함부로 바꾸면 안 된다.

---

# 59. Logging

Go 로그에는 다음을 기록한다.

```text
startup
shutdown
request_id
route
status
latency
security rejection
file operation
unexpected error
```

다음은 로그 금지:

```text
password
session cookie
csrf token
control token
share password plaintext
secret key
sensitive auth header
```

---

# 60. Error Handling

panic에 의해 서버 전체가 종료되지 않도록 HTTP recovery middleware를 둔다.

단, panic을 무시만 하지 말고 request ID와 함께 기록한다.

사용자에게 internal stack trace를 반환하지 않는다.

---

# 61. Concurrency

공유 mutable state에는 명시적인 동시성 정책을 둔다.

예:

```text
upload sessions
download quota
active sessions
audit buffer
runtime stats
job state
```

무조건 global mutex 하나로 묶기보다 구조별 lock scope를 정의한다.

Go race detector도 가능한 테스트 환경에서 사용한다.

```bash
go test -race ./...
```

---

# 62. 파일 처리 구현 원칙

대용량 파일 처리에서 금지:

```text
os.ReadFile(10GB)
전체 ZIP 메모리 생성
전체 upload body 메모리 로드
무제한 goroutine 생성
```

권장:

```text
streaming
bounded buffer
io.Copy
context cancellation
worker limit
```

---

# 63. HTTP Server 설정

반드시 설정:

```text
ReadHeaderTimeout
IdleTimeout
reasonable WriteTimeout 정책
MaxHeaderBytes
```

대용량 upload/download 때문에 단순한 짧은 global WriteTimeout을 설정하지 않는다.

endpoint 특성에 맞춰 설계한다.

---

# 64. Graceful Shutdown

종료 시 최소:

```text
새 요청 차단
active HTTP graceful wait
upload state flush
audit flush
runtime state flush
transcoder cleanup
watcher cleanup
listener close
```

순서를 정의한다.

무한 대기는 하지 않는다.

---

# 65. 구현 중 하지 말아야 할 리팩터링

Go migration PR에서 동시에 다음을 하지 않는다.

```text
CSS redesign
HTML redesign
route rename
config rename
language key rename
permission model redesign
trash schema redesign
share schema redesign
Cloud API redesign
update system redesign
```

migration diff의 원인을 좁게 유지한다.

---

# 66. PR 분할 권장

한 개의 거대한 PR로 만들지 않는다.

권장:

```text
PR 1  Go skeleton + build
PR 2  launcher + lifecycle
PR 3  config + security foundation
PR 4  path/permission
PR 5  browse/download
PR 6  ZIP
PR 7  mutation
PR 8  upload
PR 9  metadata/trash/share
PR 10 advanced features
PR 11 packaging
PR 12 default cutover
```

---

# 67. 각 PR 필수 내용

각 PR 설명에 작성:

```text
Scope
Out of scope
Python behavior being matched
Go implementation
Security impact
Persistence impact
Tests
Benchmark if applicable
Rollback method
Known gaps
```

---

# 68. 최종 목표 구조 예시

```text
webshare/
├── go-core/
│   └── ...
│
├── webshare_app/
│   ├── gui/
│   ├── core/
│   └── server/
│       ├── controller.py
│       ├── python_backend.py
│       └── go_process.py
│
├── templates/
├── static/
│
├── legacy-python-server/
│   └── (필요 시 추후 이동)
│
└── tests/
```

기존 Python backend를 초기에 `legacy-python-server/`로 옮기지는 않는다.

안정화 후 별도 정리 단계에서만 고려한다.

---

# 69. 최종 성공 기준

아래 조건을 모두 만족해야 migration 완료로 본다.

## 기능

```text
기존 주요 Web UI 기능 정상
대용량 다운로드 정상
Range 정상
ZIP 정상
simple upload 정상
chunk upload 정상
file mutation 정상
trash/version 정상
metadata 정상
share link 정상
search 정상
```

## 보안

```text
auth parity
session parity
CSRF parity
permission parity
path traversal 방어
upload limits
download limits
IP policy
protected path
share security
```

## 데이터

```text
기존 config 그대로 사용
기존 metadata 사용
기존 trash 복원
기존 share links 사용
Python/Go 교차 읽기 가능
```

## 배포

```text
Windows portable
Windows installer
PyInstaller GUI bundle
headless
Docker
```

## 운영

```text
Go crash 감지
graceful shutdown
Python fallback
health/readiness
로그/진단
```

## 성능

```text
Python baseline과 benchmark 비교 완료
대용량 transfer에서 regression 없음
동시 사용자 처리 개선 또는 동등
메모리 사용량 기록
```

---

# 70. 구현 시작 시 에이전트의 첫 작업

에이전트는 바로 기능 port부터 시작하지 말고 다음 순서로 진행한다.

```text
1. README / PROJECT_AUDIT 읽기
2. 실제 구현 경로 확인
3. pytest 전체 baseline
4. Flask route inventory 생성
5. persistence 파일/포맷 inventory 생성
6. security semantics 정리
7. docs/go-migration/baseline.md 작성
8. go-core skeleton 생성
9. health/readiness 구현
10. Python launcher 구현
```

여기까지를 첫 번째 milestone으로 한다.

---

# 71. 첫 번째 구현 완료 보고 형식

Milestone A가 끝나면 다음 형식으로 보고한다.

```markdown
## Milestone A 결과

### 변경 파일
...

### Python baseline
...

### Go tests
...

### 구현
...

### 아직 Go로 처리하지 않는 기능
...

### 보안 영향
...

### 데이터 영향
...

### 다음 단계
Milestone B — Auth / Session / CSRF / Permission foundation
```

---

# 72. 핵심 판단 원칙

이번 migration의 목적은 "Python을 없애는 것"이 아니다.

목표는:

```text
파일 서버에 적합한 Go 코어
+
기존 PyQt GUI의 생산성
+
기존 웹 UI 호환성
+
안전한 rollback
```

을 함께 확보하는 것이다.

따라서 특정 기능이 Python에서 더 안정적이고 Go port의 실익이 작다면 억지로 옮기지 않는다.

반대로 다음 영역은 Go 이관 우선순위가 높다.

```text
HTTP serving
large file transfer
Range
ZIP
filesystem traversal
chunk upload
concurrent requests
duplicate scanning
headless server
```

---

# 73. 최종 권장 전환 순서

```text
[Python baseline]
       ↓
[Go process skeleton]
       ↓
[Config compatibility]
       ↓
[Auth / Session / CSRF]
       ↓
[Path / Permission]
       ↓
[Browse]
       ↓
[Download / Range]
       ↓
[ZIP]
       ↓
[Mutation]
       ↓
[Chunk Upload]
       ↓
[Trash / Metadata / Share]
       ↓
[Search / Duplicate]
       ↓
[Media]
       ↓
[WebDAV / Cloud]
       ↓
[Packaging]
       ↓
[Go default]
       ↓
[Python fallback 유지]
```

**전면 재작성하지 않는다.  
기능별로 parity를 확보한 뒤 이동한다.  
파일 안전성과 기존 사용자 데이터 호환성을 성능보다 우선한다.**
