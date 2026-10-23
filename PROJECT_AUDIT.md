# Project Audit

> **작성일:** 2026-10-22
> **대상:** WebShare Pro v7.4.5 (`73c116b`, main) — Go 기본 백엔드 + Python(Flask) 폴백, PySide6 GUI
> **관점:** 기능 구현·런타임 안정성. 코드는 수정하지 않았고 이 리포트만 작성했다.
> **이전 리포트와의 관계:** 2026-10-06 리포트(v7.4.0 대상)의 ISSUE-001~005는 v7.4.1에서 **Python 백엔드에만** 수정되었다. 그 수정이 기본 백엔드인 Go에는 이식되지 않았다는 점이 이번 감사의 핵심 결과다. 이전 리포트 원문은 git 이력(`03cd201` 시점)에 남아 있다.

---

## 1. Executive Summary

### 프로젝트 전체 상태

Python 백엔드는 v7.4.1 감사 조치 이후 견고하다. 경로 검증, RBAC, 청크 업로드 상태 머신, 휴지통 2단계 커밋, 합산 쿼터가 갖춰져 있고 테스트도 잘 되어 있다.

하지만 **실제 사용자 대부분이 쓰는 경로는 Go 백엔드다.** 기본값이 `WEBSHARE_SERVER_BACKEND=go`이고 Windows exe에 `webshare-core.exe`가 번들된다. Go 쪽에는 Python에서 이미 고친 결함이 그대로 남아 있고, 권한 검사 누락도 하나 있다. Go 백엔드는 웹 UI도 최소 목록 페이지만 제공한다.

### 전체 위험도: **Needs Work (High 3건 포함)**

Critical로 분류한 항목은 없다. 다만 ISSUE-001(권한 우회 후 영구 삭제)과 ISSUE-002(동시 업로드 시 조용한 덮어쓰기)는 데이터 유실로 이어지는 High이며, Critical에 가깝다.

### 가장 중요한 문제

1. **[ISSUE-001] Go 백엔드에서 게스트가 휴지통 목록 조회·복원·영구 비우기를 할 수 있음** (High / Confirmed). Python은 `login_required('admin')`이지만 Go는 `/trash/` 라우트를 `adminOnly=false`로 등록했다.
2. **[ISSUE-002] 같은 이름의 청크 업로드가 동시에 완료되면 한쪽 파일이 조용히 덮어써짐** (High / Confirmed, Go·Python 양쪽). 두 클라이언트 모두 `200 success`를 받는데 실제 파일은 하나만 남는다.
3. **[ISSUE-003] 기본(Go) 백엔드는 브라우저에 읽기 전용 최소 목록만 제공** (High / Confirmed). 업로드·삭제·공유·미리보기·휴지통 UI가 없다. v7.4.5에서 복원한 웹 UI는 Python 폴백에서만 보인다.
4. **[ISSUE-004] Go 휴지통 메타데이터 lost-update** (Medium / Confirmed). 동시 삭제 20건 중 메타데이터가 2~5건만 남는다. 메타데이터를 잃은 항목은 원래 폴더가 아니라 루트에 `uuid_파일명`으로 복원된다.
5. **[ISSUE-005~009] v7.4.1 Python 수정이 Go에 미이식**: 청크 취소/완료 원자성, 합산 쿼터, 압축 해제 디스크 검사, 주기 정리, 설정 재적용.

### 데이터 손상/유실 가능성: **있음**

- ISSUE-002: 동시 같은 이름 업로드 시 한쪽 업로드가 유실된다. 사용자에게는 성공으로 표시된다.
- ISSUE-001: 게스트가 휴지통을 영구 삭제할 수 있다. 삭제를 되돌릴 수단이 사라진다.
- ISSUE-004: 파일 자체는 남지만 원래 경로 정보를 잃는다.
- 원자적 쓰기(temp + rename)와 JSON 스냅샷 직렬화는 양쪽 백엔드 모두 갖추고 있어, 프로세스 크래시로 인한 상태 파일 손상 경로는 확인되지 않았다.

### 가장 먼저 수정해야 할 영역

1. `go-core/internal/handlers/extras.go`: `/trash/` 하위 핸들러에 관리자 검사 추가.
2. 업로드 커밋 경로(`go-core/internal/handlers/upload.go`, `webshare_app/routes/upload_routes/chunk_finalize.py`): 최종 파일명을 원자적으로 확보.
3. `go-core/internal/mutate/trash.go`, `go-core/internal/handlers/upload.go`: v7.4.1 Python 수정분(휴지통 메타데이터 락, 청크 상태 원자 전이)을 Go에 이식.

---

## 2. Project Understanding

### 프로젝트 목적

로컬 폴더를 웹으로 공유하는 셀프 호스팅 파일 서버다. 제공 기능은 PySide6 데스크톱 관리자, 브라우저 파일 관리자, 공유 링크(비밀번호·만료·횟수 제한), 폴더별 RBAC, 휴지통·버전 관리, 청크 업로드, HLS·WebDAV·Google Drive·UPnP(Python 전용)다.

### 문서

- `README.md` / `README_EN.md` / `RELEASE_NOTES.md`를 확인했다.
- `CLAUDE.md`, `AGENTS.md`는 저장소에 없다. `.gitignore`에 의도적으로 추적하지 않는다고 명시되어 있다.

### 주요 entrypoint

| Entry | 역할 |
|---|---|
| `main.py::main()` | `--smoke` / `--apply-update` 분기 → `cleanup_temp_files()` → `ensure_runtime_initialized()` → PySide6 GUI(실패 시 Tkinter) |
| `webshare_app/server/__init__.py::start_server` | `go_process.backend_name()`이 `go`(기본)면 `GoServerProcess.start()`, 실패 시 `_start_python_thread()`로 폴백 |
| `webshare_app/server/go_process.py::GoServerProcess.start` | `webshare-core serve --host --port --parent-pid` 실행 후 `/readyz` 폴링 |
| `go-core/cmd/webshare-core/main.go::runServe` | 설정 1회 로드 → `handlers.New` → 라우트 등록 → `Serve` → 종료 시 `FlushState` |
| `webshare_app/app/factory.py::create_app` | Flask 앱(Python 백엔드, 스모크 테스트) |
| `docker_entrypoint.py` | Docker는 Python 백엔드를 직접 서빙한다(Go 미사용) |

### 핵심 모듈

- **Go:** `internal/handlers/*`(HTTP), `internal/auth`(세션·CSRF·차단), `internal/permission`(경로 검증·RBAC), `internal/upload`(세션·디스크 예약), `internal/mutate`(휴지통·버전·압축 해제), `internal/share`, `internal/quota`, `internal/audit`.
- **Python:** `webshare_app/routes/*`, `services/upload_service.py`·`file_service.py`·`share_service.py`, `features/trash.py`, `utils/helpers/download_quota.py`, `server/cleanup.py`(주기 정리), `core/config/manager.py`.
- **프론트엔드(Python 전용):** `templates/partials/*.html`(v7.4.5에서 v7.4.1 UI로 복원), `static/js/app-core.js`.

### 데이터 저장 방식

DB는 없다. 공유 폴더 안의 dotfile JSON(`.webshare_share_links.json`, `.webshare_audit.json`, `.webshare_download_tracker.json`, `.webshare_trash.json` 등)과 `.webshare_trash/`, `.webshare_versions/`, 업로드 임시 디렉터리를 쓴다. 설정 파일은 CWD 기준 `webshare_config.json`이며 Go와 Python이 같은 파일을 읽는다. Go와 Python은 동시에 실행되지 않고, 같은 파일 형식을 공유한다.

### 외부 의존성

Flask/Werkzeug, PySide6 6.12, cryptography, Pillow, orjson, `golang.org/x/text`. 선택 의존성은 ffmpeg, Google Drive OAuth, UPnP다.

### 핵심 실행 흐름

```
GUI [서버 시작] → server.start_server
  → (go) GoServerProcess.start → webshare-core serve → config.Load(1회) → handlers.App
        → mux: requireAuth(gate → loadSession → [admin] → CSRF) → handler
        → permission.ValidatePath + EnsurePathAccess → mutate/upload/share → atomicWrite JSON → JSON/stream
  → (실패 시 python) ServerThread → Flask before_request(IP·세션·CSRF) → route → service → atomic_write_json
```

```
브라우저 GET / → [Go] 최소 로그인 폼 → POST / → 302 /browse/ → 최소 목록 셸(fetch /api/list/, /download/)
             → [Python] templates/index.html 전체 UI(업로드·삭제·공유·미리보기·휴지통·관리자)
```

```
청크 업로드: POST /upload/chunk/init(검증·디스크 예약) → POST /upload/chunk/<id>(청크 저장)
  → POST /upload/chunk/<id>/complete(상태 COMPLETING → 대상 파일명 결정 → 병합 → rename 커밋)
```

---

## 3. Audit Coverage & Limitations

### 실제 확인한 주요 모듈

- **Go:** `handlers/{app,routes,pages,upload,mutate,extras,files,share}.go`, `upload/upload.go`, `mutate/{trash,ops,versions}.go`, `quota/quota.go`, `share/{share,persist}.go`, `config/config.go`, `server/server.go`, `cmd/webshare-core/main.go`.
- **Python:** `server/{__init__,go_process,cleanup,thread}.py`, `routes/upload_routes/chunk_finalize.py`, `routes/file_routes/{download_handlers,mutation_handlers}.py`, `routes/trash_routes.py`, `utils/helpers/download_quota.py`, `core/config/manager.py`, `gui/actions/server_actions.py`, `main.py`.
- **프론트엔드:** `templates/partials/{scripts,toolbar,file_list,header}.html`(v7.4.5 변경분 중심).
- **변경 이력:** `git diff 03cd201..HEAD`(v7.4.1 → v7.4.5)를 전수 확인했다.

### CodeGraph로 분석한 호출 관계

`codegraph_explore`로 다음을 추적했다.

- `handleRoot` / `handleLogin` / `handleBrowse` → `gate` / `loadSession` / `denyUnauthenticated` / `requireAuth` / `checkCSRF`
- `start_server` → `GoServerProcess.start` / `find_binary` / `_start_python_thread` (caller: GUI `server_actions`, `tray`, `main.py` Tkinter 폴백)
- `handleChunkSub` → `handleChunkTransfer` / `handleChunkComplete` / `handleChunkCancel` ↔ `upload.Store`, Python `complete_chunk_upload` / `cancel_chunk_upload`와 비교
- `runServe` → `Serve` / `handleControlShutdown` / `watchParent` / `FlushState`

라우트별 관리자 플래그는 grep으로 Python `login_required('admin')` 목록과 Go `requireAuth(..., true)` 목록을 대조했다.

### 실행한 테스트

| 명령 | 결과 |
|---|---|
| `cd go-core && go test ./...` | **전체 ok** (13 패키지, 테스트 파일 없는 패키지 3개) |
| `cd go-core && go vet ./...` | 경고 없음 |
| `python -m pytest -q -x` (Python 3.15.0, Windows 11 arm64) | 첫 실패에서 중단: `tests/quality/test_harness_smoke.py::test_live_harness_login_upload_download`가 `ConnectionResetError [WinError 10054]`. 이전 리포트에 기록된 Windows loopback 연결 끊김과 같은 증상으로, 제품 로직 실패로 보지 않는다. |
| `python -m pytest -q` (전체, `-x` 없음) | **304 passed, 23 failed, 2 skipped** (10분 21초). 실패 23건은 전부 실제 HTTP 루프백을 쓰는 테스트다(`tests/quality/*` 21건, `test_milestone_c_contract.py::test_login_admin_guest`, `test_milestone_def_contract.py::test_batch_and_unzip`). |
| 위 실패 테스트 재실행 (`tests/quality` + twin 2건, `--tb=line`) | **35 passed, 26 failed.** 실패 원인은 전부 네트워크 계층이다: `TimeoutError: timed out` 22건, `ConnectionResetError [WinError 10054]` 4건. **assertion 실패는 0건**이다. 실행마다 실패 수가 달라(23 → 26) 환경 의존적인 flaky로 판단했다. 다만 이 환경에서는 live 계약 테스트가 사실상 검증 역할을 하지 못한다(§9 Test Confidence). |

#### 감사용 프로브

저장소 밖 scratch 디렉터리에서 실행했고, 저장소 파일은 변경하지 않았다.

- `go-core` 사본에 `zz_audit_*_test.go`를 추가했다. 대상: 게스트 휴지통 접근, 완료 중 취소, 이중 완료, 동시 같은 이름 업로드, 동시 삭제 메타데이터, 동시 청크 전송.
- Python 프로브(`app` fixture 재사용): 동시 같은 이름 청크 완료.
- 프론트엔드가 호출하는 67개 경로를 Flask `url_map`과 대조했다. 누락 0건(`/manifest.json` 정규식 오탐 1건 제외).

### 확인하지 못한 환경/외부 서비스

- PySide6 GUI 실조작, PyInstaller frozen exe 빌드·실행, Docker 이미지.
- Linux/macOS 실행. 모든 실행은 Windows 11 arm64에서만 했다.
- Google Drive, UPnP, ffmpeg/HLS, WebDAV 클라이언트, 업데이트 서버(GitHub Releases).
- 실제 원격 다중 사용자 부하.

### 분석상의 한계

- `go test -race`는 **windows/arm64에서 지원되지 않아** 실행하지 못했다. 그래서 ISSUE-005의 맵 data race는 Likely로 남겼다(프로브 3회 실행에서 런타임 crash는 재현되지 않음).
- CodeGraph는 Go의 클로저(`a.Uploads.Update(id, func...)`) 내부 쓰기를 호출 그래프로 보여주지 않는다. 공유 상태 변경 지점은 소스를 직접 읽어 확인했다.
- 동시성 프로브는 `httptest`/Flask test client를 이용한 in-process 재현이다. 실제 네트워크 타이밍과 다를 수 있지만, 경쟁 창(window)이 존재한다는 것은 확인했다.

---

## 4. High-Risk Issues

### [ISSUE-001] Go 백엔드: 게스트가 휴지통 목록 조회·복원·영구 비우기 가능

- **위치:** `go-core/internal/handlers/extras.go`
  - 라우트 등록(26행): `mux.HandleFunc("/trash/", a.requireAuth(a.handleTrashSub, false))`
  - `handleTrashList`(112), `handleTrashRestore`(153), `handleTrashEmpty`(170)
- **우선순위:** High (Critical에 가까움)
- **신뢰도:** Confirmed
- **문제:** Python은 `/trash/list`, `/trash/restore`, `/trash/empty`를 `@login_required('admin')`로 보호한다(`webshare_app/routes/trash_routes.py:79-144`). Go는 `/trash/` 전체를 `adminOnly=false`로 등록했고, 세 핸들러 안에도 역할 검사가 없다(주석에만 "(admin)"이라고 적혀 있다).
- **발생 조건:** 게스트 비밀번호로 로그인한 사용자가 CSRF 토큰과 함께 `POST /trash/empty`를 보낸다. 게스트 비밀번호의 기본값은 `0000`이고, 여러 사람에게 공유되는 것이 일반적이다.
- **영향:**
  - 휴지통 전체가 영구 삭제되어 실수로 지운 파일을 복구할 수 없게 된다.
  - 게스트가 볼 권한이 없는 폴더의 삭제 파일 경로가 노출된다.
  - 쓰기 권한이 없는 폴더로 파일을 복원할 수 있다. `RestoreFromTrash`는 경로 검증만 하고 RBAC는 검사하지 않는다.
- **근거:** 프로브 `TestProbeGuestTrash`
  - 게스트 `GET /trash/list` → `200`, 관리자가 삭제한 `secret.txt`의 `original_path`가 노출됨
  - 게스트 `POST /trash/empty` → `200 {"success":true}`, `.webshare_trash/` 디렉터리 삭제 확인
- **반증 확인:**
  - `requireAuth`는 `adminOnly=true`일 때만 역할을 검사한다.
  - `server.withMiddleware`는 request-id, recover, logging만 한다.
  - `/api/trash/cleanup`만 `true`로 등록되어 있다.
  - `tests/quality/test_live_security_boundary.py::test_security_guest_cannot_elevate_via_admin_apis`가 `/trash/list` 게스트 403을 검사하지만, `live_server` fixture는 **Python WSGI 서버**라 Go를 검증하지 않는다.
  - Go 단위 테스트(`extras_test.go`)는 관리자 쿠키로만 호출한다.
- **호출/영향 범위:** `RegisterRoutes → registerExtrasRoutes → requireAuth(handleTrashSub,false) → handleTrashList / handleTrashRestore(mutate.RestoreFromTrash) / handleTrashEmpty(os.RemoveAll)`. 기본 백엔드가 Go이므로 exe와 소스 실행 사용자 전원이 영향을 받는다.
- **권장 수정 방향:** `handleTrashSub`에서 `list`/`restore`/`empty`일 때 `SessionOf(r).role != "admin"`이면 403을 반환하거나, 하위 경로별로 `requireAuth(..., true)`를 등록한다.
- **필요한 회귀 테스트:**
  - Go 단위: 게스트 쿠키 + CSRF로 3개 경로 → 403, 휴지통 디렉터리와 메타데이터 불변.
  - live parity: 같은 시나리오를 Go `go_live_server` fixture(`tests/quality/live_harness.py`)에도 실행.

---

### [ISSUE-002] 같은 이름 청크 업로드 동시 완료 시 한쪽 업로드가 조용히 덮어써짐 (Go·Python 공통)

- **위치:**
  - Go: `go-core/internal/handlers/upload.go::handleChunkComplete`. 513행 `os.Lstat(targetPath)`로 중복 회피 이름을 고른 뒤 병합하고, 584행 `os.Rename(mergeTmp, targetPath)`로 커밋한다.
  - Python: `webshare_app/routes/upload_routes/chunk_finalize.py::complete_chunk_upload`. 93행 `os.path.exists` 루프 → 병합 → 147행 `os.replace(merge_temp_path, target_path)`.
- **우선순위:** High
- **신뢰도:** Confirmed
- **문제:** 최종 파일명을 **병합 시작 전에** 존재 여부 검사로만 정하고, 병합이 끝난 뒤 "덮어쓰는" rename(`os.Rename` / `os.replace`)으로 커밋한다. 선택한 이름을 예약하거나 배타적으로 생성(O_EXCL)하지 않는다. 경쟁 창은 대용량 파일일수록 길어진다(최대 10GB 병합 시간 전체).
- **발생 조건:** 두 세션(다른 사용자, 다른 기기, 같은 사용자의 탭 두 개)이 같은 폴더에 같은 이름(예: `IMG_0001.jpg`)을 업로드하고, 한쪽의 병합 중에 다른 쪽이 완료된다. 병합 중 일반 업로드·이름 변경·복사로 같은 이름이 생긴 경우에도 해당한다.
- **영향:** 먼저 커밋된 파일이 나중 파일로 대체된다. 많은 경우 **두 클라이언트 모두 `200 {"filename":"IMG_0001.jpg"}`** 를 받아 유실을 알 수 없다. Windows에서는 일부가 `WinError 5`(500)로 실패하는데, 이때 실패한 쪽의 청크와 세션은 정리되어 재전송이 필요하다.
- **근거:**
  - Go 프로브 `TestProbeSameNameConcurrentComplete`(8MB×2): 15/15 라운드에서 파일이 1개만 남았다. 이 중 8라운드는 양쪽 모두 200이었다.
  - Python 프로브(같은 시나리오, Flask test client 2개 + Barrier): 8/8 라운드에서 파일이 1개만 남았다. 6라운드는 양쪽 모두 200, 2라운드는 `WinError 5` → 500이었다.
- **반증 확인:**
  - Python의 `upload_session_lock`은 세션 상태만 보호하고 대상 파일명은 보호하지 않는다.
  - 디스크 예약(`reserve_upload_disk_space`)은 용량만 다룬다.
  - 같은 이름 회피 로직(`_1` 접미사)은 검사 시점에만 유효하다.
  - 웹 클라이언트는 한 세션의 청크를 순차 전송하지만, 서로 다른 세션 간 경쟁은 막지 못한다.
- **호출/영향 범위:**
  - Go: `handleChunkSub → handleChunkComplete`.
  - Python: `upload_bp complete_chunk_upload` (caller: `templates/partials/scripts.html` 청크 업로더, 1750행).
  - 같은 계열: Go `handleUpload`(단일 요청 업로드), Python 단일 업로드 저장도 검사 후 쓰기 패턴이다. 경쟁 창은 짧다.
- **권장 수정 방향:** 커밋 단계에서 이름을 원자적으로 확보한다.
  - (a) 최종 이름을 `O_CREAT|O_EXCL`로 placeholder 생성하고, 실패하면 다음 접미사로 넘어간 뒤 그 위로 rename한다.
  - (b) 또는 하드링크/`link()` 후 temp를 삭제하는 no-replace 커밋을 쓴다.
  - (c) 또는 프로세스 내 "대상 경로 예약" 맵을 락으로 보호하고, 병합 후 커밋 직전에 다시 검사한다.
  - 응답의 `filename`은 실제로 커밋된 이름이어야 한다.
- **필요한 회귀 테스트:** 같은 디렉터리·같은 이름으로 세션 2개(내용 A/B)를 초기화하고 청크를 전송한 뒤 `complete`를 동시에 호출한다. 기대 결과: 파일 2개(`IMG_0001.jpg`, `IMG_0001_1.jpg`)가 생기고, 각 응답의 `filename`이 실제 파일과 일치하며 내용이 A/B로 보존된다. Go·Python 모두 적용한다.

---

### [ISSUE-003] 기본(Go) 백엔드의 브라우저 UI가 읽기 전용 최소 셸이라 핵심 웹 기능을 쓸 수 없음

- **위치:**
  - `go-core/internal/handlers/pages.go::writeBrowseHTML`, `writeLoginHTML`
  - `go-core/internal/handlers/app.go::RegisterRoutes`(`/static/`, 템플릿 라우트 없음)
  - `webshare_app/server/__init__.py::start_server`(Go 기본)
  - `WebSharePro.spec:149`(`webshare-core.exe` 번들)
- **우선순위:** High
- **신뢰도:** Confirmed
- **문제:** Go는 브라우저에 로그인 폼과 "목록·다운로드·페이지 이동"만 있는 셸을 제공한다. 코드 주석에도 "full template port is still pending"이라고 적혀 있다. 업로드(드래그 앤 드롭·청크), 삭제, 이름 변경, 공유 링크 발급, 미리보기·뷰어·편집기, 휴지통, 태그·메모, 관리자 화면 등 README §7·§8의 웹 기능이 기본 실행 경로에서 하나도 노출되지 않는다. Python 전용 API(HLS, 썸네일, 권한 관리, 중복 검사, Google Drive, UPnP 등)는 Go에서 404다. Python 폴백은 Go **시작 실패** 시에만 동작한다.
- **발생 조건:** 기본 설정으로 exe를 실행하거나 `go-core`를 빌드하고 `python main.py`를 실행한 뒤, 브라우저에서 접속한다.
- **영향:**
  - 주 사용 경로에서 업로드 등 핵심 기능을 쓸 수 없다.
  - v7.4.5의 "웹 UI 복원·다운로드 흐름 수리"(`db28613`)는 Python 백엔드에서만 보여, 기본 사용자에게는 효과가 없다.
- **근거:**
  - Go 라우트 목록(`HandleFunc`)에 `/static`, `/preview`, `/thumbnail`, `/api/permissions` 등이 없다.
  - `pages.go`의 HTML은 `/api/list/`, `/download/`, `/logout` 링크만 만든다.
  - `RELEASE_NOTES.md` v7.4.4에도 "기본 파일 목록 HTML"로 기술되어 있다.
- **반증 확인:**
  - 의도된 단계적 이식일 수 있다(문서화된 한계).
  - 하지만 README는 이 한계를 언급하지 않는다. README는 Go 기본 백엔드와 함께 전체 웹 UI를 핵심 기능으로 소개하고, §8에서 "로그인·파일 브라우저도 동일합니다"라고 적고 있다.
  - API 자체(업로드·삭제 등)는 Go에 존재하므로 API 클라이언트는 쓸 수 있다. UI만 없다.
- **호출/영향 범위:** `GUI 서버 시작 → start_server → GoServerProcess`. `[🌐 브라우저 열기]`·QR 접속 사용자 전원이 영향을 받는다.
- **권장 수정 방향:** 단기적으로 다음 중 하나를 고른다.
  - (a) 전체 UI 이식이 끝날 때까지 기본 백엔드를 `python`으로 되돌리거나 GUI에 백엔드 선택을 노출한다.
  - (b) Go가 Python 템플릿 렌더 결과(정적 HTML·JS)를 서빙하도록 `/static/`과 index 템플릿을 이식한다.
  - (c) 최소 셸에 "이 모드에서는 업로드 등 미지원 — Python 백엔드로 전환" 안내를 표시하고 README를 정정한다.
- **필요한 회귀 테스트:** Go live 서버에 브라우저 헤더(`Accept: text/html`)로 `GET /browse/`를 보내, 응답 HTML이 업로드 진입점(파일 input 또는 `/upload/chunk/init` 호출 코드)과 `/static/` 자산 참조를 포함하는지 확인한다. 또는 정책상 최소 셸을 유지한다면, README에 그 사실이 명시되어 있는지 확인하는 문서 테스트를 둔다.

---

### [ISSUE-004] Go 휴지통 메타데이터 lost-update: 동시 삭제 시 원래 경로 정보 유실

- **위치:** `go-core/internal/mutate/trash.go`
  - `MoveToTrash`(96~131): 121행 `loadTrashMetadata` → 수정 → `saveTrashMetadata`. 락이 없다.
  - `RestoreFromTrash`(198), `ExtractOriginalName`(189)
- **우선순위:** Medium
- **신뢰도:** Confirmed
- **문제:** 메타데이터 파일을 락 없이 read-modify-write한다. 동시 요청이 서로의 항목을 덮어쓴다. 메타데이터가 없는 항목은 `ExtractOriginalName`의 `SplitN(name,"_",3)`가 `{uuid}_{파일명}`을 반환하므로, **원래 하위 폴더가 아닌 공유 루트에 uuid 접두사가 붙은 이름**으로 복원된다. Python은 v7.4.1에서 pending → 확정 2단계, self-heal, uuid 접두사 제거로 이 문제를 고쳤다(이전 ISSUE-003). Go에는 이식되지 않았다.
- **발생 조건:** 두 클라이언트 이상이 거의 동시에 삭제(`/delete/`, `/trash`, `/batch_delete/`)한다. 복원(`RestoreFromTrash`)과 자동 정리(`AutoCleanupTrash`)도 같은 파일을 RMW하므로 함께 경쟁한다.
- **영향:** 파일은 휴지통에 남지만 복원 위치와 이름이 틀어진다(무결성 저하). Windows에서는 동시 rename 실패로 이동은 됐는데 500을 반환할 가능성도 있다(Speculative).
- **근거:** 프로브 `TestProbeConcurrentDeleteMetadata`(`docs/` 하위 파일 20개 동시 삭제)를 3회 실행했다. 휴지통 항목은 20개였지만 메타데이터는 5/3/2개만 남았다. 메타데이터 없는 항목을 복원하면 `0277624c2d1c4be1b3ef49a2df11a424_f3.txt`처럼 **루트에** 생성됐다.
- **반증 확인:** `atomicWriteFile`은 temp + rename이라 파일 손상은 막지만 lost-update는 막지 못한다. `App` 구조체에 휴지통 전용 mutex가 없다.
- **호출/영향 범위:** `handleDelete`, `handleBatchDelete`, `handleTrashMove` → `MoveToTrash`. `handleTrashRestore` → `RestoreFromTrash`. `handleTrashCleanup` → `AutoCleanupTrash`.
- **권장 수정 방향:**
  - `mutate` 패키지에 메타데이터 파일 단위 `sync.Mutex`를 두고 load → modify → save를 한 임계구역으로 묶는다.
  - Python과 같은 pending → 확정 순서를 적용한다.
  - `ExtractOriginalName`을 4필드(`date_time_uuid_name`)로 파싱한다.
- **필요한 회귀 테스트:** 하위 폴더 파일 N=20개를 동시 삭제했을 때 메타데이터가 20개이고, 각 항목을 복원하면 원래 경로에 원래 이름으로 생성되어야 한다.

---

### [ISSUE-005] Go 청크 업로드 상태 전이가 원자적이지 않음 (완료 중 취소, 이중 완료, 맵 data race)

- **위치:** `go-core/internal/handlers/upload.go`
  - `handleChunkComplete`(423): 상태 확인과 454행 `Update(...StatusCompleting)`가 분리되어 있다.
  - `handleChunkCancel`(616): COMPLETING 검사가 없다.
  - `handleChunkTransfer`: 364행 `us.Chunks[index]`를 락 없이 읽는다.
  - `upload.Store.Get`(`internal/upload/upload.go:184`)이 공유 `*Session` 포인터를 반환한다.
- **우선순위:** Medium
- **신뢰도:** Confirmed (취소·이중 완료) / Likely (맵 race로 인한 프로세스 crash)
- **문제:**
  1. **완료 중 취소:** Python은 v7.4.1부터 COMPLETING 상태의 취소를 409로 거부하고, 병합 중 상태를 다시 확인해 중단한다. Go `handleChunkCancel`은 상태를 보지 않고 `Cleanup`(임시 디렉터리 삭제 + 세션 제거)을 실행한다. 그래서 병합 중인 청크가 사라지거나, 취소가 "성공"했는데 파일이 커밋된다.
  2. **이중 완료:** `Get` → `Status` 검사 → `Update` 사이에 다른 요청이 끼어들 수 있다. 두 요청이 모두 병합을 수행하고, 먼저 끝난 쪽이 temp를 지운 뒤 늦은 쪽은 `500 merge failed`와 함께 세션을 정리한다. 이때 파일은 이미 커밋된 상태다.
  3. **data race:** 핸들러가 `Store.mu` 밖에서 `us.Chunks`를 읽고 순회하고, 다른 요청은 `Update` 안에서 같은 맵에 쓴다. Go 런타임이 이를 감지하면 `fatal error: concurrent map read and map write`로 **프로세스 전체가 종료**된다. 이 오류는 recover로 잡히지 않는다.
- **발생 조건:**
  - (1) API 클라이언트나 스크립트가 complete 진행 중에 cancel을 보낸다. 웹 UI는 청크 실패 시에만 cancel을 호출하고, 이는 complete 이전이다(`scripts.html` 1733~1738행). 따라서 웹 UI 단독으로는 발생하지 않는다.
  - (2) complete 타임아웃 후 클라이언트나 프록시가 재시도한다.
  - (3) API 클라이언트가 한 세션에 청크를 병렬로 전송한다. 웹 UI는 순차 전송이라 해당하지 않는다.
- **영향:**
  - (1)(2): 상태 불일치. 사용자는 실패나 취소로 알지만 파일은 생성되어 있다.
  - (3): Go 서버가 크래시한다. 이후 폴백은 "시작 실패" 시에만 동작하므로 GUI에는 비정상 종료로만 표시된다.
- **근거:**
  - `TestProbeCancelWhileCompleting`: COMPLETING 세션에 cancel → `200 {"success":true}`, 세션 제거됨. Python은 409.
  - `TestProbeDoubleComplete`(40라운드×3회): 일부 라운드에서 양쪽 모두 200(43/40), 다른 라운드에서는 `500 chunk upload merge failed`가 나왔다.
  - `TestProbeConcurrentChunks`(64 병렬×30라운드×3회): crash는 재현되지 않았다. `-race`는 windows/arm64 미지원이라 Likely로 남겼다.
- **반증 확인:**
  - `Store.Update`는 락을 잡지만, 그 전의 `Get` 결과 판독과 결정은 락 밖에서 일어난다.
  - `server.withMiddleware`의 `recover()`는 panic은 잡지만 런타임 fatal error는 잡지 못한다.
- **호출/영향 범위:** `handleChunkSub → {handleChunkTransfer, handleChunkComplete, handleChunkCancel}` ↔ `upload.Store{Get, Update, Cleanup}`.
- **권장 수정 방향:**
  - `Store`에 `TryBeginComplete(id, owner) (snapshot, ok, status)` 같은 원자적 CAS 메서드를 추가한다.
  - cancel은 COMPLETING이면 409를 반환한다.
  - 병합 루프에서 상태를 다시 확인해 중단한다(Python 동작과 동일하게).
  - `Get`은 깊은 복사본을 반환하고, 청크 맵 판독은 락 안에서 한다.
- **필요한 회귀 테스트:**
  - COMPLETING 세션에 cancel → 409, 세션 유지.
  - 같은 세션에 complete 2건 동시 → 정확히 1건 200, 1건 409. 파일 1개.
  - 리눅스 CI에서 `go test -race`로 같은 세션에 청크 32건 병렬 전송 → race 보고 0건.

---

### [ISSUE-006] Go 모드에서는 주기 정리가 돌지 않음 (휴지통 자동 삭제 미동작)

- **위치:**
  - `go-core/cmd/webshare-core/main.go::runServe`: 주기 작업 goroutine이 없다.
  - `webshare_app/server/thread.py:107`: `start_periodic_cleanup()`은 Python `ServerThread`에서만 호출된다.
  - `go-core/internal/handlers/extras.go:200`: `AutoCleanupTrash`는 관리자 수동 API에서만 호출된다.
- **우선순위:** Medium
- **신뢰도:** Confirmed
- **문제:** Python 백엔드는 5분 주기로 만료 세션, 공유 링크, 업로드 세션, 휴지통 자동 삭제(기본 30일), 로그인 시도, 다운로드 트래커, 감사 로그 flush를 수행한다. Go 경로에는 이에 해당하는 스케줄러가 없다. Go에서 `ExpiredIDs()`는 새 `chunk/init` 요청 때만 호출된다.
- **발생 조건:** 기본(Go) 백엔드로 장기간 운영한다.
- **영향:**
  - README의 "30일 이상 경과한 파일은 자동으로 디스크에서 정리"가 동작하지 않아 휴지통이 무한히 커진다.
  - 버려진 업로드 임시 청크가 다음 업로드 초기화 전까지 디스크에 남는다. 서버 재시작 시에는 `cleanup_temp_files()`가 정리한다.
  - 감사 로그는 5초 스로틀 flush라, 마지막 쓰기 이후 강제 종료(`_terminate`)되면 소량 유실될 수 있다. 정상 종료 시에는 `FlushState`가 저장한다.
- **근거:** `grep`으로 `AutoCleanupTrash`·`ExpiredIDs`의 production caller를 확인했다(위 2곳뿐). `start_periodic_cleanup` caller는 `thread.py`뿐이다.
- **반증 확인:** GUI 프로세스가 Go 모드에서 별도로 Python 정리 스케줄러를 띄우는지 확인했고, 띄우지 않는다(`server/__init__.py` Go 분기에 호출 없음).
- **호출/영향 범위:** `runServe`, `server.start_server`(Go 분기).
- **권장 수정 방향:** Go `runServe`에서 `time.Ticker(5m)`로 `AutoCleanupTrash`, `Uploads.ExpiredIDs`와 임시 디렉터리 삭제, 공유 링크 만료 정리, `FlushState`(dirty일 때만)를 실행한다. 또는 GUI 프로세스가 Go 모드에서도 Python 정리 스케줄러를 시작한다. 둘이 같은 파일을 쓰게 되므로 첫 번째 방식을 권장한다.
- **필요한 회귀 테스트:** 31일 전 타임스탬프 이름의 휴지통 항목을 두고 Go 서버를 기동한 뒤, 정리 주기(테스트에서는 짧게 주입) 이후 항목이 삭제되었는지 확인한다.

---

### [ISSUE-007] Go 서버는 설정을 기동 시 1회만 읽음: GUI에서 바꾼 비밀번호가 재시작 전까지 적용되지 않음

- **위치:**
  - `go-core/cmd/webshare-core/main.go:96`: `config.Load` 1회. 그 외 reload 경로가 없다(`grep config.Load` 결과 2곳, 모두 시작 시).
  - `go-core/internal/handlers/routes.go:84`: 메모리의 `a.Config.AdminPw`, `GuestPw`를 사용한다.
  - `webshare_app/gui/actions/server_actions.py::save_settings`(210~232)
- **우선순위:** Medium
- **신뢰도:** Confirmed
- **문제:** GUI 설정 저장은 `conf.save()`로 파일만 갱신하고 "일부 설정은 재시작 후 적용됩니다"라고만 안내한다. Python 백엔드는 `conf`를 실시간으로 참조하므로 비밀번호, 게스트 업로드 허용, 세션 타임아웃이 즉시 적용된다. Go는 재시작 전까지 **이전 비밀번호를 계속 허용하고 새 비밀번호는 거부한다.**
- **발생 조건:** 서버 실행 중 GUI에서 관리자나 게스트 비밀번호를 바꾼다. 비밀번호 유출을 의심해 교체하는 경우가 대표적이다. `allow_guest_upload`, `session_timeout`을 바꿔도 같다.
- **영향:** 보안 조치(비밀번호 교체, 게스트 업로드 차단)가 실제로 적용되지 않았는데 사용자는 적용됐다고 믿는다. 백엔드에 따라 동작이 달라진다.
- **근거:** 코드 경로 확인. Go `App.Config`는 `handlers.New(cfg, ...)`에서 복사된 값이다.
- **반증 확인:**
  - GUI 저장 경로에 서버 재시작이나 Go 통지 호출이 없다.
  - Go에 파일 감시나 SIGHUP 처리가 없다.
- **호출/영향 범위:** `save_settings → conf.save` ↛ Go 프로세스. 로그인(`handleLogin`), `mutationAllowed`(게스트 업로드), `loadSession`(타임아웃).
- **권장 수정 방향:**
  - 저장 시 서버가 실행 중이면 Go를 자동으로 재시작하거나 재시작을 명확히 요구한다(최소 조치: 보안 관련 키 변경 시 경고 대화상자).
  - 또는 Go에 control-token으로 보호된 `/_control/reload` 엔드포인트를 추가한다.
- **필요한 회귀 테스트:** Go 실행 중 설정 파일의 `admin_pw`를 새 해시로 바꾸고 reload(또는 재시작) 경로를 실행했을 때, 이전 비밀번호 로그인은 401, 새 비밀번호는 302여야 한다.

---

### [ISSUE-008] Go 다운로드 쿼터가 세션 단위라 재로그인으로 일일 한도를 초기화할 수 있음

- **위치:** `go-core/internal/quota/quota.go::Key`(33). `session:<sid>`가 우선이다. 호출부는 `handlers/files.go:179,227,245,332,345`.
- **우선순위:** Medium
- **신뢰도:** Confirmed (코드 대조)
- **문제:** Python은 v7.4.1(이전 ISSUE-004)부터 `reserve_combined_download_quota`(`utils/helpers/download_quota.py:101`)로 **세션 + IP 합산**에 상한을 적용한다. Go는 세션 ID 단일 키만 쓰므로, 로그아웃 후 다시 로그인하면 새 세션 ID로 카운트와 바이트가 0부터 시작한다.
- **발생 조건:** `daily_download_limit` 또는 `daily_bandwidth_limit_mb`를 설정한 운영자. 게스트가 재로그인을 반복한다.
- **영향:** 일일 다운로드 횟수와 대역폭 제한을 우회할 수 있다. 같은 설정인데 백엔드마다 다르게 동작한다.
- **근거:** Go `Key`의 주석 "session id wins, else IP"와 Python `build_quota_key_set(session_id, ip)` 합산 로직(117~125행)을 대조했다.
- **반증 확인:** Go `Tracker.Reserve`는 단일 `entryLocked(key)`만 검사하며, 다른 키를 합산하는 경로가 없다.
- **정정 (2026-10-23, 조치 중 확인):** Python의 "합산" 상한도 재로그인 우회를 막지 못한다. 로그인 다운로드는 `session:` 키에만 기록되고 `ip:` 키는 공유 링크 경로에서만 증가하므로, 새 세션에서는 두 키가 모두 0이다. `daily_download_limit=2`, 세션 2개로 재현한 결과는 `[200, 200, 200]`이었다. 이 이슈는 **Go·Python 양쪽 문제**다.
- **호출/영향 범위:** `handleDownload`, `handleZip`, `handleBatchDownload`. 공유 링크(`share.go`)는 별도의 trackerKey를 쓴다.
- **권장 수정 방향:** Python과 같이 `{session:<sid>, ip:<ip>}` 키 집합의 당일 합계로 상한을 검사하고, 예약은 primary 키에 기록한다.
- **필요한 회귀 테스트:** `daily_download_limit=2`로 설정하고 같은 IP에서 로그인 → 2회 다운로드 → 로그아웃 → 재로그인 → 3번째 다운로드가 429여야 한다(Go·Python 동일).

---

### [ISSUE-009] Go 압축 해제에 디스크 여유 검사와 실패 시 부분 추출물 정리가 없음

- **위치:** `go-core/internal/mutate/ops.go::UnzipArchive`(294), `go-core/internal/handlers/mutate.go::handleUnzip`(509)
- **우선순위:** Medium
- **신뢰도:** Confirmed (코드)
- **문제:** Python은 v7.4.1(이전 ISSUE-005)에서 해제 전 디스크 여유 검사와 실패 시 정리를 추가했다. Go는 Zip Slip과 선언 크기 기반 Zip Bomb 검사만 한다. 추출 중 오류(디스크 부족, 잘못된 엔트리, Windows에서 쓸 수 없는 이름)가 나면 새로 만든 `extractTo` 디렉터리에 부분 결과를 남긴 채 500을 반환한다.
- **발생 조건:** 남은 디스크 공간보다 큰 ZIP(최대 `MaxUnzipBytes`까지 허용)을 해제하거나, 엔트리 중간에 쓰기 오류가 난다.
- **영향:** 디스크가 가득 차 다른 업로드와 상태 저장이 연쇄 실패할 수 있다. 부분 추출 폴더가 남아 사용자 혼란을 준다.
- **근거:** `UnzipArchive`에 free-space 조회와 `RemoveAll(extractTo)` 경로가 없다.
- **반증 확인:**
  - Go `archive/zip`은 실제 데이터가 선언된 `UncompressedSize64`를 넘으면 `ErrFormat`을 반환하므로, 헤더를 위조한 Zip Bomb는 라이브러리가 막는다. 이것은 문제로 보지 않았다.
  - 디스크 예약 로직(`Uploads.Reserve`)은 업로드와 공유 ZIP에만 연결되어 있다.
- **호출/영향 범위:** `/unzip/` → `handleUnzip` → `UnzipArchive`.
- **권장 수정 방향:** 사전 스캔에서 얻은 `total`로 `Uploads.Reserve(folder, total, "unzip-…")`를 호출하고, 실패 시 400 또는 507을 반환한다. 추출 실패 시 `os.RemoveAll(extractTo)`로 정리하고, 성공·실패와 관계없이 예약을 해제한다.
- **필요한 회귀 테스트:**
  - `freeDiskBytes`를 작은 값으로 주입하고 해제 → 507(또는 400), `extractTo` 미생성.
  - 3번째 엔트리에서 쓰기 실패를 주입 → 500, `extractTo` 삭제됨.

---

### [ISSUE-010] Go가 기록한 휴지통 `deleted_at`의 ISO 형식이 깨져 있음

- **위치:** `go-core/internal/mutate/trash.go::isoTime`(42). `sprintf06(us)`를 `.` 없이 이어 붙인다.
- **우선순위:** Low
- **신뢰도:** Confirmed
- **문제:** Go가 `"2026-10-22T23:02:16486171"`처럼 소수점이 빠진 값을 저장한다. 같은 저장소의 `audit.isoTimestamp`는 `".%06d"`로 올바르게 쓴다.
- **발생 조건:** Go 백엔드에서 삭제한 뒤 Python 백엔드(폴백, Docker, HTTPS 사용자)에서 휴지통을 연다.
- **영향:** 복원된 v7.4.1 UI의 `new Date(item.deleted_at)`(`templates/partials/scripts.html:931`)가 `Invalid Date`를 표시한다. Python에서 이 값을 `fromisoformat`으로 파싱하는 코드는 확인되지 않았다(표시 문제로 한정).
- **근거:** `TestProbeGuestTrash` 출력의 `"deleted_at":"2026-10-22T23:02:16486171"`.
- **반증 확인:** 마이크로초가 정확히 0일 때만 정상 형식이 된다.
- **권장 수정 방향:** `s += "." + sprintf06(us)`.
- **필요한 회귀 테스트:** `isoTime(time.Date(...,123456000,...))` == `"...T..:..:...123456"`. Python `datetime.fromisoformat`으로 파싱 가능해야 한다.

---

### [ISSUE-011] 툴바의 "현재 폴더 ZIP" 링크가 URL 인코딩되지 않음

- **위치:** `templates/partials/toolbar.html:38`의 `<a href="/zip/{{ current_path }}">`. 같은 화면의 브레드크럼(`header.html:99`)은 `|urlencode`를 쓴다.
- **우선순위:** Low
- **신뢰도:** Confirmed (코드)
- **문제:** Jinja 자동 이스케이프는 HTML 특수문자만 처리한다. 폴더 이름의 `#`, `?`, `%`는 URL 구분자로 해석된다.
- **발생 조건:** Python 백엔드에서 `C# 자료`, `50% 할인`, `Q&A?` 같은 폴더 안에서 ZIP 버튼을 누른다.
- **영향:** `#` 이후가 잘려 다른 폴더를 ZIP하거나 404 또는 잘못된 경로 오류가 난다.
- **권장 수정 방향:** `encodePath`와 같은 세그먼트 단위 `urlencode`를 적용한다.
- **필요한 회귀 테스트:** `a#b` 폴더에서 렌더된 툴바 href가 `/zip/a%23b`인지 확인한다.

---

## 5. Potential Functional Gaps

| 구분 | 내용 | 근거 |
|---|---|---|
| **Confirmed Gap** | **Windows 자동 실행 미구현.** 설정 탭의 "윈도우 시작 시 자동 실행" 체크는 `conf['autostart']`에 저장만 되고, 읽어서 레지스트리나 시작프로그램을 등록하는 코드가 없다. | `grep autostart` 결과는 `manager.py` 기본값, `schema.py`, `settings_tab.py`, `server_actions.py` 저장뿐이다. |
| **Confirmed Gap** | **대소문자만 다른 이름으로 변경 불가**(Windows·macOS 기본 FS). `a.txt` → `A.txt`가 "동일한 이름이 이미 존재합니다"로 거부된다. Go와 Python이 같다. | Python `mutation_handlers.py::rename`의 `os.path.exists(new_path)`, Go `handleRename`의 `os.Lstat(newPath)`. 대소문자 무시 FS에서는 같은 파일로 판정된다. |
| **Confirmed Gap** | **Python `/batch_download/`가 최상위 폴더를 처리하지 못함.** `<path:path>`는 빈 경로와 매칭되지 않아 404가 난다. v7.4.5는 클라이언트에서 개별 다운로드로 우회했다. 브라우저의 다중 다운로드 차단 정책에 걸릴 수 있다. | `download_handlers.py:194`, `scripts.html:450` 주석. |
| **Likely Gap** | Go 단일 요청 업로드(`handleUpload`)와 Python 일반 업로드도 "존재 검사 → 쓰기" 패턴이라 ISSUE-002와 같은 계열의 경쟁이 있다(창은 짧다). | 업로드 경로 전체에 `O_EXCL` 사용이 없다(`grep`). |
| **Likely Gap** | Go `maybeRehash`는 레거시(SHA-256) 해시로 로그인할 때 **메모리의 기동 시점 Config 전체**를 설정 파일에 저장한다. 그 사이 GUI에서 저장한 설정(폴더, 포트, 새 비밀번호)이 되돌려질 수 있다. 레거시 해시가 남아 있는 업그레이드 사용자에 한정된다. | `routes.go::maybeRehash` → `config.Save(path, a.Config)`. `Save`는 알려진 키를 메모리 값으로 덮어쓴다. |
| **Likely Gap** | 설정 파일과 기본 공유 폴더가 **CWD 상대 경로**(`webshare_config.json`, `./shared_files`)다. 바로가기의 "시작 위치"나 터미널 위치가 바뀌면 새 기본 설정(`1234`/`0000`)으로 기동한다. | `core/config/defaults.py:14`, Go `defaultConfigPath()`. |
| **Likely Gap** | Go가 Python 전용 API(썸네일, HLS, 권한 관리, 중복 검사, 클라우드, UPnP, 사용자 관리)를 제공하지 않아, API 클라이언트도 기본 백엔드에서 404를 받는다(ISSUE-003의 API 측면). | Go `HandleFunc` 목록과 Python 라우트 비교. |
| 추정 | Go `share.Store.SaveLinks`는 스냅샷을 락 안에서 만들고 파일 쓰기는 락 밖에서 한다. 동시 다운로드에서 오래된 스냅샷이 나중에 기록되면, 재시작 후 `download_count`가 실제보다 작게 복원될 수 있다(1회용 링크 재사용 가능성). 메모리 내 예약은 원자적이다. | `share/share.go:195`, `share/persist.go:67`. |
| 추정 | GUI가 Go 프로세스의 실행 중 크래시(`crashed()`)를 감지한 뒤 Python으로 자동 전환하는지 확인하지 못했다. 폴백 코드는 "시작 실패"에만 있다. README의 "1초 이내 무중단 폴백"이 실행 중 장애에도 해당하는지는 불명확하다. | `server/__init__.py::start_server`. |

---

## 6. Documentation Mismatches

1. **README 웹 UI 가이드 전반(§7·§8, Highlights) ↔ 기본 Go 백엔드.** README는 업로드, 뷰어, 편집기, 휴지통, 공유 발급 등을 기본 기능으로 설명한다. 기본 백엔드의 브라우저 UI는 목록과 다운로드뿐이다(ISSUE-003). §8 "백엔드 동일 동작" 항목은 "기본 파일 목록 HTML"이라고만 적고 "Python 백엔드와 동일한 contract"라고 표현한다. 이 때문에 업로드 등 UI 기능이 Go 기본 실행에서 빠진다는 사실이 드러나지 않는다.
2. **README §1-1 "파일 선택 & 다운로드 흐름 (v7.4.2)"와 README_EN 280행.** 44px 열 정렬, 선택 바 헤더, 헤더 체크박스, `Shift+클릭` 범위 선택, 드래그 영역 선택을 설명한다. v7.4.5가 이 UI를 되돌렸다. `RELEASE_NOTES`에도 "정렬 컬럼 헤더·전체선택 헤더·행 클릭 다중선택은 제외"라고 적혀 있다.
3. **README "30일 이상 경과한 파일은 자동으로 디스크에서 정리".** 기본 Go 백엔드에서는 동작하지 않는다(ISSUE-006).
4. **README 설정 탭 "윈도우 부팅 시 자동 시작 설정".** 구현이 없다(§5 Confirmed Gap).
5. **버전 표기 혼재.** README 제목과 배지는 7.4.5다. 반면 비교표(84행), Quick Start 다운로드 파일명(161행 `WebSharePro-v7.4.2.exe`, 하이픈), Go 섹션(248행), GUI 목업(289행)은 v7.4.2다. README_EN은 스모크 테스트 경로까지 `WebSharePro_v7.4.2.exe`다. 실제 빌드 산출물은 `WebSharePro_v7.4.5.exe`(밑줄)다.
6. **README "Go 바이너리 누락·비정상 종료 시 1초 이내 무중단 자동 폴백".** 코드상 폴백은 `start_server`의 **시작 실패** 분기뿐이다. 실행 중 비정상 종료 후 자동 전환은 확인되지 않았다(§5 추정).
7. `CLAUDE.md`, `AGENTS.md`는 없다(의도된 정책). 이와 관련한 불일치는 없다.

---

## 7. Recommended Fix Plan

### Phase 1 — Immediate

1. **ISSUE-001:** Go `/trash/{list,restore,empty}`에 관리자 검사를 추가한다. 게스트 회귀 테스트를 Go 단위와 Go live 양쪽에 추가한다.
2. **ISSUE-002:** 업로드 커밋을 원자적 이름 확보 방식(O_EXCL placeholder, no-replace link, 경로 예약 맵 중 하나)으로 바꾼다. Go와 Python에 같은 방식을 적용한다.
3. **ISSUE-003:** 정책을 결정한다. 전체 UI 이식 전까지 기본 백엔드를 `python`으로 하거나 GUI에서 선택하게 할지, 아니면 최소 셸에 제한 안내를 넣고 README를 정정할지 정한다.
4. **ISSUE-007(최소 조치):** 서버 실행 중 비밀번호나 게스트 권한을 바꾸면 Go 재시작을 강제하거나 명시적으로 경고한다.

### Phase 2 — Stability

1. **ISSUE-004:** Go 휴지통 메타데이터에 mutex, pending → 확정 순서, `ExtractOriginalName` 4필드 파싱을 적용한다(v7.4.1 Python 수정 이식).
2. **ISSUE-005:** Go 업로드 `Store`에 원자적 상태 전이 API를 추가한다. cancel은 COMPLETING이면 409를 반환하고, 병합 루프에서 상태를 다시 확인하며, `Get`은 복사본을 반환한다.
3. **ISSUE-006:** Go 내부 5분 주기 정리 goroutine(휴지통 자동 삭제, 만료 업로드, 링크, dirty flush)을 추가한다.
4. **ISSUE-008:** Go 쿼터에 세션 + IP 합산 상한을 적용한다.
5. **ISSUE-009:** Go 압축 해제에 디스크 예약과 실패 시 `RemoveAll`을 추가한다.
6. **ISSUE-010, ISSUE-011:** 한 줄 수정.
7. §5의 Confirmed Gap(대소문자만 다른 이름 변경, 최상위 `batch_download`, 자동 실행)을 구현하거나, 해당 UI와 문서를 제거한다.

### Phase 3 — Structural

1. **Go/Python 수정 이식 누락 방지.** 이번 감사 이슈의 절반 이상이 "Python에서만 고쳐진 결함"이다. `docs/quality/server-parity/CONTRACT_MATRIX.md`에 감사 이슈 → Go·Python 각각의 테스트 ID 매핑 열을 추가한다. 또한 `tests/quality/test_live_security_boundary.py`와 `test_live_fault_recovery.py`를 Go `go_live_server` fixture에도 파라미터화한다.
2. **Go 공유 상태 접근 규칙 통일.** `Store.Get`이 내부 포인터를 반환하지 않게 하고, 모든 변경은 `Update`/CAS를 거치게 한다. Linux CI에서 `go test -race ./...`를 상시 실행한다(windows/arm64는 미지원).
3. **설정 단일 소유자화.** GUI와 Go가 같은 파일을 각자 전체 덮어쓰는 구조를 없앤다. Go는 읽기 전용으로 두고, 변경은 reload 신호로 전달한다.
4. 설정과 데이터 경로를 CWD 대신 실행 파일 기준이나 `%APPDATA%` 기준으로 고정한다.

---

## 8. Test Recommendations

| 유형 | 테스트 | 입력 조건 | 기대 결과 |
|---|---|---|---|
| Unit (Go) | 게스트 휴지통 차단 | 게스트 쿠키 + CSRF로 `GET /trash/list`, `POST /trash/restore {"name":X}`, `POST /trash/empty` | 각각 403. `.webshare_trash/`와 `.webshare_trash.json` 바이트 불변 |
| Unit (Go) | `isoTime` | `time.Date(2026,10,22,23,2,16,486171000,UTC)` | `"2026-10-22T23:02:16.486171"` |
| Unit (Go) | `ExtractOriginalName` | `"20261022_230216_<32hex>_report.pdf"` | `"report.pdf"` |
| Integration (Go·Python) | 같은 이름 동시 업로드 | 세션 A(내용 `A`×8MB), 세션 B(`B`×8MB), 같은 폴더, 같은 이름, `complete` 동시 호출 | 파일 2개. 응답 `filename`이 서로 다르고 실제 파일과 일치. 내용 보존 |
| Concurrency (Go) | 동시 삭제 메타데이터 | 하위 폴더 파일 20개 동시 `/delete/` | 메타데이터 20개. 전부 원래 경로로 복원 가능 |
| Concurrency (Go) | 완료 중 취소 | COMPLETING 세션에 `/cancel` | 409. 세션과 임시 디렉터리 유지 |
| Concurrency (Go) | 이중 완료 | 같은 세션 `complete` 2건 동시 | 정확히 200 1건, 409 1건, 파일 1개. 500 없음 |
| Concurrency (Go, Linux CI) | 청크 병렬 전송 race | `-race`, 같은 세션 index 0..31 병렬 | race 보고 0, 32청크 모두 기록 |
| Integration (Go) | 쿼터 재로그인 | `daily_download_limit=2`, 로그인 → 다운로드 2회 → 로그아웃·재로그인 → 다운로드 | 3번째 429 |
| Integration (Go) | 압축 해제 디스크 부족 | `freeDiskBytes` 주입값 < ZIP 선언 합계 | 400 또는 507. `extractTo` 미생성 |
| Integration (Go) | 압축 해제 부분 실패 | 3번째 엔트리 쓰기 실패 주입 | 500. `extractTo` 제거 |
| Integration (Go) | 주기 정리 | 31일 전 이름의 휴지통 항목, 정리 주기 1초로 주입 | 주기 후 항목 삭제, 메타데이터 갱신 |
| E2E (live, 양쪽 백엔드) | 설정 변경 반영 | 실행 중 `admin_pw` 교체 → reload 또는 재시작 경로 | 이전 비밀번호 401, 새 비밀번호 302 `/browse/` |
| E2E (live, Go) | 브라우저 UI 기능 | `Accept: text/html`로 `GET /browse/` | 정책에 따라 업로드 진입점 포함, 또는 "미지원" 안내 문구 포함 |
| Regression (Python) | 툴바 ZIP href | `current_path="a#b"` 렌더 | href `/zip/a%23b` |
| Regression (문서) | README 버전 동기화 | README·README_EN의 `v7.4.x` 표기와 exe 파일명 | `APP_VERSION`과 일치, 파일명 형식 `WebSharePro_v{ver}.exe` |
| Platform-specific | 대소문자만 다른 이름 변경 | Windows·macOS에서 `a.txt` → `A.txt` | 200, 파일명 변경 반영 |
| Platform-specific | `os.Rename` 덮어쓰기 의존 제거 확인 | Windows·Linux 각각 ISSUE-002 시나리오 | 두 OS 모두 파일 2개 |
| Platform-specific | Windows loopback 안정성 | `tests/quality` 하네스를 Windows arm64에서 실행 | `TimeoutError`, `ConnectionResetError` 없이 통과. 현재는 26/61건이 네트워크 계층 오류로 실패한다. 하네스 timeout과 재시도 정책을 재검토하거나, CI는 Linux 러너에서도 실행한다. |

---

## 9. Final Assessment

| 항목 | 평가 | 근거 |
|---|---|---|
| Functional Correctness | **Needs Work** | Python 경로는 양호하다. 기본 Go 경로는 웹 UI가 최소 셸이고(ISSUE-003), 관리자 검사가 누락되어 있다(ISSUE-001). |
| Runtime Stability | **Acceptable** | 우아한 종료와 `FlushState`, 부모 PID 감시, 원자적 쓰기를 갖췄다. 다만 Go 맵 race의 프로세스 crash 가능성(ISSUE-005, Likely)이 있고 주기 정리가 없다(ISSUE-006). |
| Data Integrity | **Needs Work** | 같은 이름 동시 업로드의 조용한 덮어쓰기(ISSUE-002, 양쪽 백엔드)와 Go 휴지통 메타데이터 lost-update(ISSUE-004). |
| Error Resilience | **Acceptable** | 오류 정규화, 예약 롤백, 손상 설정 백업(Python)은 양호하다. Go 압축 해제 부분 실패 정리 누락(ISSUE-009), 완료 후 500 응답(ISSUE-005). |
| Cross-platform Robustness | **Acceptable** | NFC 정규화와 Windows 예약어 처리는 양호하다. 대소문자만 다른 이름 변경 불가, CWD 상대 설정 경로, Windows loopback 테스트 불안정이 있다. |
| Test Confidence | **Needs Work** | Go 단위 테스트는 전부 통과하고 Python 테스트도 풍부하다. 하지만 보안·장애 live 테스트가 Python 서버에만 걸려 있어 ISSUE-001·004·005를 놓쳤다. 또 이 Windows arm64 환경에서는 live 테스트 23~26건이 timeout과 연결 리셋으로 실패해, 루프백 계약 검증을 신뢰할 수 없었다(304 passed / 23 failed, 실패는 모두 네트워크 계층). |

### 실제로 먼저 수정할 문제 3개

1. **[ISSUE-001]** Go `/trash/list|restore|empty` 관리자 검사 누락. 한 줄 수준의 수정이고, 게스트가 영구 삭제할 수 있는 문제를 막는다.
2. **[ISSUE-002]** 같은 이름 업로드 동시 완료 시 조용한 덮어쓰기(Go·Python). 데이터 유실이 성공 응답으로 가려진다.
3. **[ISSUE-004 + ISSUE-005]** v7.4.1 Python 수정분(휴지통 메타데이터 2단계 커밋, 청크 상태 원자 전이)을 Go에 이식하고, 이식을 강제하도록 live 보안·장애 테스트를 Go에도 실행한다.

---

## 10. Remediation Status (2026-10-23)

> 위 감사 결과를 토대로 적용한 수정 기록이다. 정책 결정 3건은 사용자 선택에 따랐다: ISSUE-003은 Go가 전체 UI를 서빙, ISSUE-007은 Go reload 엔드포인트, 자동 실행은 실제 구현.

| 이슈 | 조치 | 주요 변경 | 회귀 테스트 |
|---|---|---|---|
| ISSUE-001 | `/trash/*`를 관리자 전용으로 등록하고 `/trash/cleanup` 별칭 추가 | `handlers/extras.go` | `TestTrashAdminRoutesRejectGuest`, `tests/quality/test_live_security_go.py` |
| ISSUE-002 | 커밋 시점 `O_EXCL` placeholder로 이름을 확보한 뒤 rename. 병합 전 이름 선택 제거 (Go·Python, 청크·단일 업로드) | `upload.CommitNoReplace`, `atomic_io.commit_no_replace` | `TestChunkCompleteSameNameNeverOverwrites`, `tests/test_upload_same_name_race.py` |
| ISSUE-003 | GUI가 Jinja 템플릿을 `go_shell` 모드로 렌더(언어×역할 셸)해 `--ui-dir`/`--static-dir`로 전달. Go는 CSRF와 경로 placeholder를 치환해 서빙. 텍스트 편집·스트리밍·플레이리스트·갤러리·미리보기·최근 파일·클립보드·metrics·dashboard summary API를 Go에 추가. Python 전용 관리 기능은 셸에서 숨김 | `server/go_ui.py`, `handlers/ui.go`, `handlers/media.go`, 템플릿 `go_shell` 분기 | `handlers/ui_test.go`, `handlers/media_test.go`, `tests/test_go_ui_render.py`, 실제 바이너리 E2E 수동 확인 |
| ISSUE-004 | 메타데이터 RMW를 mutex/RLock으로 직렬화. Go에 pending→확정, self-heal, 4필드 원본 이름 추출 이식. Python도 락 추가 | `mutate/trash.go`, `features/trash.py` | `TestMoveToTrashConcurrentKeepsAllMetadata`, `tests/test_trash_metadata_race.py` |
| ISSUE-005 | `Store.BeginComplete`/`BeginCancel` 원자 전이, 병합 중 상태 재확인, `Get`은 복사본 반환 | `upload/upload.go`, `handlers/upload.go` | `TestChunkCompleteConcurrentSingleMerge`, `TestChunkCancelWhileCompletingConflicts`, `TestChunkTransferParallelSameSession` |
| ISSUE-006 | Go 5분 주기 `RunMaintenance` (세션·링크·업로드·휴지통·로그인 시도·트래커 정리, dirty flush) | `handlers/maintenance.go`, `cmd/webshare-core/main.go` | `TestMaintenanceOnceCleansTrashAndUploads` |
| ISSUE-007 | `atomic.Pointer` 설정 스냅샷과 `ReloadConfig`, `/_control/reload`. GUI 저장 시 `apply_config_changes()`로 반영하고 재시작 필요 항목 안내. `maybeRehash`는 해당 키만 디스크에 반영 | `handlers/app.go`, `server/server.go`, `server/__init__.py`, `gui/actions/server_actions.py` | `TestReloadConfigAppliesPasswordChange`, `TestControlReloadGuardsAndCallsHook`, `tests/test_config_apply.py` |
| ISSUE-008 | 다운로드를 세션·IP 키 모두에 기록하고, 상한은 키별 최대 사용량으로 판정 (Go·Python) | `quota/quota.go`, `helpers/download_quota.py` | `client_test.go`, `tests/test_quota_relogin.py` |
| ISSUE-009 | 사전 스캔 합계로 디스크 예약(부족 시 507), 실패 시 `RemoveAll(extractTo)` | `mutate/ops.go`, `handlers/mutate.go` | `unzip_test.go` |
| ISSUE-010 | `isoTime`에 `.` 추가. 자동 삭제 나이 계산을 `ParseInLocation(Local)`로 변경 | `mutate/trash.go` | `TestIsoTimeHasFractionSeparator` |
| ISSUE-011 | 툴바 ZIP 링크에 `urlencode` 적용 | `templates/partials/toolbar.html` | `test_toolbar_zip_link_encodes_current_path` |

**§5 Gap 조치**

- 자동 실행 구현 (`core/autostart.py`, `main.py --workdir`).
- 대소문자만 다른 이름 변경 허용 (Go `os.SameFile`, Python `os.path.samefile`).
- `/batch_download/` 루트 지원과 클라이언트 단일 ZIP 다운로드.
- `share.SaveLinks` 스냅샷/쓰기 순서 보장 (`saveMu`).
- `maybeRehash`의 설정 덮어쓰기 수정.
- 미조치: 설정 파일의 CWD 상대 경로 자체(기존 사용자 설정 위치 이동이 필요해 보류, 자동 실행은 `--workdir`로 우회). 실행 중 Go 크래시 시 자동 Python 전환(문서를 실제 동작으로 정정).

**§6 문서 조치:** README/README_EN의 v7.4.2 잔재 정리, 현행 UI 설명, 백엔드별 기능 범위, 폴백·설정 반영·휴지통 자동 삭제·자동 실행 설명 정정. `RELEASE_NOTES.md`에 Unreleased 섹션 추가.

**Phase 3:** `tests/quality/test_live_security_go.py`(Go 실서버 관리자 경계 검증), CI `go-race` 잡(ubuntu, `go test -race ./...`) 추가. 이 잡은 아직 CI에서 실행되지 않았다.

**검증 결과 (2026-10-23, Windows 11 arm64)**

- `go vet ./...` 경고 없음. `go test ./...` 전체 ok.
- `python -m pyright`: 1 error. 미설치 선택 의존성 `flask_compress` import 하나로, 조치 전과 동일하다.
- `python -m pytest -q` 전체: **325 passed, 24 failed, 2 skipped**.
  - 실패는 전부 `tests/quality`(실제 루프백 HTTP)에서 났다.
  - `tests/quality` 재실행 결과 42 passed, 17 failed였고, 원인은 `TimeoutError` 16건, `ConnectionResetError` 1건이었다. **assertion 실패는 0건**이다.
  - 실행마다 실패 목록이 바뀌는 환경 문제이며, 조치 전 기준선(23~26건 실패, 모두 네트워크 계층)과 같은 양상이다.
  - 조치 전 실패하던 twin 계약 테스트 2건(`test_milestone_c/def`)은 이번 실행에서 통과했다.
- 실제 Go 바이너리 E2E 수동 확인:
  - 전체 로그인 페이지 → 로그인 302 → `/browse/C%23%20docs` 셸(경로·CSRF 치환, placeholder 잔존 0, Python 전용 메뉴 숨김)
  - `/static/*`, `/manifest.json`, `/sw.js` 200. 디렉터리 목록 404
  - 파일 경로 302 → `/download/`, 없는 경로 404
- 미실행: CI `go-race` 잡(리눅스), PyInstaller exe 빌드, GUI 실조작.
