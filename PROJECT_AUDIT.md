# Project Audit

> **갱신 (2026-06-25):** 본 문서 초안 이후 감사 권장 1·2단계 항목 대부분이 코드에 반영되었습니다. 상세는 [§7. Remediation Status](#7-remediation-status)를 참고하세요.

## 1. Executive Summary

WebShare Pro v7.2.4는 Flask/PyQt 기반 로컬 파일 공유 서버로, 경로 검증·권한·CSRF·청크 업로드·공유 링크·클라우드 동기화·영속 상태 저장 등 핵심 기능이 `webshare_app/` 패키지에 체계적으로 분리되어 있습니다.

**감사 시점 위험도: Medium** → **조치 후 잔여 위험도: Low~Medium** (공개 배포 시 기본 비밀번호·단일 프로세스 전제는 여전히 운영 주의 필요)

| 영역 | 감사 시점 | 조치 후 |
|------|-----------|---------|
| 인증/권한/경로 보안 | 양호 | 양호 |
| 업로드/파일 무결성 | 양호 | 양호 (폴더 업로드 경로·complete 멱등성 보강) |
| 영속 상태/동시성 | 주의 | **개선** (`webshare_app/core/persistence.py`) |
| 배포 기본값 | 주의 | **부분 개선** (경고·`secret_key` 영속화; 강제 변경 UI는 미구현) |
| 테스트 커버리지 | 공백 일부 | **보강** (`tests/test_audit_remediations.py`, 113 passed) |

초안에서 우선순위였던 **(1) JSON persist lost-update**, **(2) `secret_key` 휘발성**, **(3) 폴더 업로드 경로 검증**, **(4) 청크 complete 경쟁**, **(5) 클립보드/공유 ZIP 자원 한도**는 구현·테스트 완료입니다.

---

## 2. Project Understanding

### 2.1 문서 기준 프로젝트 목적

`README.md`에 따르면 본 프로젝트는 브라우저로 로컬 파일을 안전하게 공유·관리하는 데스크톱/GUI 포함 파일 서버입니다. 주요 기능은 파일 CRUD, 10GB 청크 업로드, Admin/Guest 역할·폴더 권한, CSRF, PBKDF2 비밀번호, 공유 링크(만료/비밀번호/다운로드 제한), Google Drive 동기화, HLS/WebDAV/UPnP 등 capability 기반 선택 기능, PWA입니다.

`CLAUDE.md`는 존재하지 않습니다.

### 2.2 아키텍처 (CodeGraph 분석 요약)

```
main.py
  └─ ensure_runtime_initialized()          [webshare_app/server/bootstrap.py]
  └─ run_pyqt6_gui() / Tkinter / headless  [webshare_app/gui/]
       └─ start_server()                    [webshare_app/server/__init__.py]
            └─ ServerThread (daemon)        [webshare_app/server/thread.py]
                 ├─ build_composed_wsgi_app()
                 │    └─ create_app()        [webshare_app/app/factory.py]
                 │         ├─ before_request: IP 화이트리스트/차단, 세션 만료, CSRF
                 │         └─ register_routes() → Blueprints
                 └─ optional WebDAV wrap    [webshare_app/features/webdav_server.py]
```

**핵심 모듈**

| 모듈 | 역할 |
|------|------|
| `webshare_app/app/factory.py` | Flask 앱 생성, 전역 보안 훅 |
| `webshare_app/routes/*` | HTTP 엔드포인트 (file, upload, share, cloud, admin, metadata) |
| `webshare_app/services/*` | 업로드/공유/파일/클라우드 비즈니스 로직 |
| `webshare_app/security/*` | 인증, CSRF, IP 차단, 폴더 권한 |
| `webshare_app/features/*` | 메타데이터, 휴지통, 검색 인덱스, runtime state 영속화 |
| `webshare_app/core/config.py` | 설정·전역 in-memory 상태·락 |
| 최상위 `server.py`, `config.py`, `routes/` 등 | import 호환 wrapper |

**주요 실행 흐름**

1. **시작**: `main.py` → 임시 업로드 디렉터리 정리 → `ensure_runtime_initialized()`로 `.webshare_*.json` 상태 로드 → GUI에서 `start_server()`.
2. **요청**: `create_app()`의 `before_request`에서 IP 정책·세션·CSRF 검사 → Blueprint 라우트 → `after_request`에서 `Cache-Control: no-store`, 통계 집계.
3. **파일 변경**: `ensure_path_access` + `validate_path` → 원자적 저장/스테이징 → 감사 로그·검색 인덱스 갱신.
4. **청크 업로드**: `init` → `upload_chunk` (세션 소유권·바이트 한도) → `complete` (청크 집합 검증·merge·`os.replace`).
5. **공유 링크**: 메모리 `SHARE_LINKS` + `.webshare_share_links.json` 영속화, 비밀번호 브루트포스 차단, `_reserve_share_download()`로 다운로드 횟수 원자 예약.
6. **종료**: `ServerThread.shutdown()`에서 transcoder/indexer 정지, dirty runtime state flush.

**CodeGraph blast radius 관찰**

- `upload`, `upload_chunk`, `access_share_link`, `cloud_sync`, `create_webdav_app` 등 핵심 라우트에 **직접 단위 테스트가 없거나 부족**하다고 표시됨 (회귀 테스트는 `test_upload_integrity.py`, `test_download_limits.py` 등에서 간접 검증).
- `legacy/웹서버 프로그램v4.py`는 런타임 경로에 포함되지 않으나 동일 심볼명이 공존해 탐색 시 혼동 가능.

### 2.3 README vs 실제 구현 차이

| README 설명 | 실제 구현 | 비고 |
|-------------|-----------|------|
| `http://localhost:5000` 기본 접속 | `display_host` 기본값 `0.0.0.0` | 모든 인터페이스 바인딩. localhost만 의도 시 설정 변경 필요 |
| `pyright` → 0 errors | optional `orjson` 미설치 시 1 error | `requirements-optional.txt` 설치 환경과 불일치 가능 |
| Google Drive 수동 동기화 | Dropbox API는 `501 placeholder` | README에 Dropbox 미구현 명시 없음 |
| `103 passed, 1 skipped` | **실측 동일** (2026-06-25) | 기준선 일치 |
| OAuth secret 외부 저장 | 구현 일치 (`cloud_secrets.json`) | 테스트 `test_security_hardening_724.py`에서 검증 |

---

## 3. High-Risk Issues

### 3.1 JSON 영속 저장의 동시 쓰기 lost-update

* **위치**: `webshare_app/features/share_links_store.py` / `save_share_links()`, `webshare_app/features/runtime_state.py` / `save_download_tracker()`, `save_login_attempts()`, `webshare_app/security/permissions.py` / `save_permissions()`, `webshare_app/features/metadata.py` / `save_metadata()`
* **문제**: 스냅샷은 락 안에서 생성하지만 파일 쓰기는 락 밖에서 수행됩니다. 동시에 두 저장이 발생하면 늦게 끝난 **이전 스냅샷이 최신 데이터를 덮어쓸** 수 있습니다.
* **영향**: 공유 링크 `download_count`가 디스크에 과소 기록되면 재시작 후 `max_downloads` 제한이 완화될 수 있습니다. 다운로드 쿼터·로그인 시도 기록도 유사하게 불일치 가능.
* **근거**:

```51:65:webshare_app/features/share_links_store.py
    with share_links_lock:
        payload = {
            "updated": datetime.now().isoformat(),
            "links": {
                token: _serialize_share_info(info)
                for token, info in SHARE_LINKS.items()
            },
        }

    try:
        fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix=".webshare_share_", suffix=".tmp")
        ...
        os.replace(temp_path, file_path)
```

  메모리 상 동시 다운로드 제한은 `test_implementation_regressions.py::test_share_max_downloads_atomic_reservation`으로 검증되나, **디스크 영속화 경쟁**은 테스트되지 않음.

* **권장 수정 방향**: 단일 writer 큐/락으로 snapshot+write를 원자화하거나, 파일 단위 advisory lock·버전 필드 기반 merge. 최소한 `save_*` 호출을 직렬화하는 전역 persist lock 도입.
* **우선순위**: **High**

---

### 3.2 기본 비밀번호 및 공개 바인딩

* **위치**: `webshare_app/core/config.py` / `ConfigManager.__init__`, `docker_entrypoint.py`
* **문제**: Admin `1234`, Guest `0000`이 기본값이며 `display_host` 기본 `0.0.0.0`입니다.
* **영향**: 공개 네트워크에 그대로 노출 시 즉시 침해 가능. Docker는 경고 로그를 남기지만 데스크톱 실행은 자동 차단 없음.
* **근거**:

```233:239:webshare_app/core/config.py
        self.config: ConfigData = {
            'folder': os.path.abspath(os.path.join(os.getcwd(), 'shared_files')),
            'port': DEFAULT_PORT,
            'admin_pw': "1234",
            'guest_pw': "0000",
            ...
            'display_host': '0.0.0.0',
```

* **권장 수정 방향**: 최초 실행 시 강제 비밀번호 변경 UI, LAN 공개 시 확인 대화상자, `127.0.0.1` 기본 바인딩 옵션 검토.
* **우선순위**: **High** (공개 배포 시 **Critical**)

---

### 3.3 `secret_key` 미설정 시 런타임 랜덤 생성

* **위치**: `webshare_app/app/factory.py` / `create_app()`
* **문제**: `conf.get('secret_key')`가 없으면 `os.urandom(24).hex()`로 매 실행마다 새 키 생성.
* **영향**: 서버 재시작·EXE 재실행마다 모든 Flask 세션·CSRF 토큰 무효화. 의도치 않은 운영 중단.
* **근거**:

```49:51:webshare_app/app/factory.py
    app.secret_key = conf.get('secret_key') or _os.urandom(24).hex()
```

* **권장 수정 방향**: 앱 설정 디렉터리(`WEBSHARE_CONFIG_DIR`)에 `secret_key` 자동 생성·영속 저장. README 데스크톱 실행 가이드에도 명시.
* **우선순위**: **Medium**

---

### 3.4 폴더 업로드 경로 검증의 문자열 기반 `..` 검사

* **위치**: `webshare_app/routes/file_routes.py` / `upload()`
* **문제**: 드래그&드롭 폴더 업로드 시 `paths[i]`에 대해 `'..' not in rel_path` 문자열 검사만 수행 후 `os.makedirs`를 호출합니다. `normalize_relative_path`/`validate_path` 사전 검증이 없습니다.
* **영향**: 비정상 경로 조합·OS별 구분자 혼용 시 의도치 않은 하위 경로 생성 가능성. 최종 `rel_save_path`에서 `ensure_path_access`·`is_protected_system_path`로 차단되나, **디렉터리 생성 시점**과 검증 시점 사이 불일치 여지.
* **근거**:

```203:209:webshare_app/routes/file_routes.py
        if paths and len(paths) > i and '/' in paths[i]:
            rel_path = paths[i]
            if '..' not in rel_path:
                parts = rel_path.split('/')
                safe_parts = [safe_filename(p) for p in parts]
                file_path = os.path.join(full_path, *safe_parts)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
```

* **권장 수정 방향**: `normalize_relative_path` + `validate_path(base_dir, rel_save_path)`를 `makedirs` 이전에 적용. `split('/')` 대신 통합 경로 정규화 유틸 사용.
* **우선순위**: **Medium**

---

### 3.5 클립보드 API 메모리 고갈 가능성

* **위치**: `webshare_app/routes/file_routes.py` / `clipboard_handler()`
* **문제**: `MAX_CLIPBOARD_ENTRIES = 200`으로 항목 수만 제한하고, 항목당 `content` 크기 제한이 없습니다.
* **영향**: 인증된 사용자가 대용량 문자열을 반복 POST하면 서버 메모리 압박 가능.
* **근거**:

```1025:1031:webshare_app/routes/file_routes.py
        data = parse_json_body(request)
        with _clipboard_lock:
            _clipboard_store[owner_key] = data.get('content', '')
            _clipboard_store.move_to_end(owner_key)
            while len(_clipboard_store) > MAX_CLIPBOARD_ENTRIES:
                _clipboard_store.popitem(last=False)
```

* **권장 수정 방향**: `MAX_CLIPBOARD_CONTENT_BYTES` 도입, 초과 시 413/400 반환.
* **우선순위**: **Medium**

---

### 3.6 In-memory 전역 상태의 프로세스 경계

* **위치**: `webshare_app/core/config.py` (`SHARE_LINKS`, `UPLOAD_SESSIONS`, `LOGIN_ATTEMPTS`, `ACTIVE_SESSIONS` 등), `webshare_app/services/upload_service.py`
* **문제**: 모든 런타임 상태가 단일 프로세스 메모리에 존재합니다. Werkzeug `threaded=True`는 지원하나 **멀티 워커/멀티 프로세스** 배포는 지원하지 않습니다.
* **영향**: gunicorn multi-worker 등으로 확장 시 업로드 세션·공유 링크·IP 차단 상태가 워커마다 분리됩니다.
* **근거**: CodeGraph 엔트리 `ServerThread.run()` → `make_server(..., threaded=True)`. `UPLOAD_SESSIONS`는 모듈 전역 dict.
* **권장 수정 방향**: README/아키텍처에 단일 프로세스 전제 명시. 확장 필요 시 Redis/SQLite 백엔드 검토.
* **우선순위**: **Medium** (현재 단일 스레드 서버 사용 시 **Low**)

---

### 3.7 청크 업로드 `complete` 중복 호출 방어 부족

* **위치**: `webshare_app/routes/upload_routes.py` / `complete_chunk_upload()`
* **문제**: merge/commit 전에 세션을 "완료 중"으로 표시하는 idempotency 플래그가 없습니다. 네트워크 재시도로 `complete`가 두 번 오면 두 번째 호출이 실패하긴 하나, 첫 번째 commit 직후·cleanup 전 짧은 구간에서 경쟁 가능.
* **영향**: 드문 이중 merge 시도, 불완전한 에러 응답 또는 temp 파일 잔존.
* **근거**: CodeGraph 분석상 `upload_chunk`/`complete_chunk_upload`에 직접 커버 테스트 없음. `test_upload_integrity.py`는 실패 케이스 위주.
* **권장 수정 방향**: 세션 상태 `completing`/`completed` 전이 추가, completed 세션에 대한 멱등 응답.
* **우선순위**: **Medium**

---

### 3.8 X-Forwarded-For 신뢰 설정 오류 시 제한 우회

* **위치**: `webshare_app/utils/file_utils.py` / `get_real_ip()`
* **문제**: `trusted_proxies`에 포함된 hop에서만 XFF를 신뢰합니다. 잘못 설정 시 공격자가 IP를 스푸핑해 다운로드 쿼터·로그인 차단·공유 비밀번호 시도 제한을 분산 가능.
* **영향**: rate limit 무력화.
* **근거**:

```41:56:webshare_app/utils/file_utils.py
        trusted_proxies = conf.get("trusted_proxies", []) or []
        ...
        is_trusted_proxy = remote_ip in trusted_proxies
    ...
    if is_trusted_proxy:
        xff = request.headers.get("X-Forwarded-For", "")
```

* **권장 수정 방향**: reverse proxy 배포 문서에 `trusted_proxies`/`trusted_hops` 필수 설정 가이드. 기본값은 현재 안전(미신뢰).
* **우선순위**: **Low** (기본 설정) / **High** (프록시 앞 단 배포 시)

---

## 4. Potential Functional Gaps

### 확인된 공백 (추정 아님)

- **Dropbox 동기화 미구현**: `cloud_sync()`가 `501 placeholder` 반환. UI에 노출된다면 사용자 혼란 가능.
- **사용자 API 비활성**: `USER_API_ENABLED = False`, `admin_routes`에 legacy 사용자 파일은 있으나 로그인과 분리됨 (`USER_API_NOTICE`).
- **청크 업로드 세션 휘발성**: 서버 재시작 시 `UPLOAD_SESSIONS` 소실. 시작 시 `.upload_temp` 정리는 있으나 **이어받기(resume) API 없음**.
- **공유 링크 비밀번호 성공 후 GET 재요청**: POST 성공 후 같은 요청에서 다운로드 진행은 되나, 북마크/새로고침 시 비밀번호 재입력 필요 (세션 쿠키 없음). 의도된 설계로 보이나 UX 제약.

### 추정 보완 지점

- **추정**: 대용량 폴더 ZIP 공유 시 `create_temp_zip_from_items()`가 디스크 전체 크기 임시 파일을 만들어 I/O·디스크 고갈 위험. 스트리밍 ZIP 생성으로 개선 여지.
- **추정**: 검색 인덱스(`indexer.update_event`) 비동기 갱신으로 삭제/업로드 직후 목록 불일치 가능. `indexing`/`fallback` 모드로 완화 중이나 완전한 일관성은 아님.
- **추정**: `rename`은 `os.rename` 직접 사용으로 copy/move의 버전 백업·스테이징 패턴과 비대칭. 동시 rename 경쟁 시 플랫폼별 오류 가능.
- **추정**: HLS/ffmpeg transcoder subprocess 리소스 상한·동시 변환 수 제한이 환경에 따라 불명확 (capability 감지는 있음).
- **추정**: `legacy/웹서버 프로그램v4.py` (5700+ lines) 유지보수 부담. 런타임 미사용이나 신규 기여자 혼동 요인.

---

## 5. Recommended Fix Plan

### 1단계 — 즉시 수정 (보안·데이터 정합성)

1. **JSON persist 직렬화**: `save_share_links`, runtime state, permissions, metadata 저장 경로에 공통 persist lock 또는 write queue 도입.
2. **공개 배포 가드**: 최초 실행·`0.0.0.0` 바인딩 시 기본 비밀번호 변경 강제 또는 명시적 확인.
3. **`secret_key` 영속화**: 앱 config 디렉터리에 자동 생성·재사용.
4. **폴더 업로드 경로**: `paths[i]` 처리에 `validate_path` 통합.

### 2단계 — 안정성 개선

1. **청크 `complete` 멱등성** 및 중복 complete 테스트 추가.
2. **클립보드 content 크기 상한** 및 413 응답.
3. **프록시 배포 문서**: `trusted_proxies` 설정 절 추가.
4. **공유 ZIP 디스크 사용량**: 임시 ZIP 크기 사전 검사·quota 연동.

### 3단계 — 구조 개선

1. **영속 상태 저장소 통합**: 분산된 `.webshare_*.json` writer를 단일 persistence layer로 추상화.
2. **라우트 단위 테스트 확대**: CodeGraph가 표시한 미커버 라우트 (`upload`, `access_share_link`, `cloud_sync` 등) 직접 테스트.
3. **legacy 코드 격리**: `legacy/` 명시적 deprecated 표기 또는 제거 계획.
4. **(장기) 멀티 워커 지원** 필요 시 외부 store 도입.

---

## 6. Test Recommendations

### 우선 추가할 테스트

| 테스트 | 목적 |
|--------|------|
| `test_share_links_persist_concurrent_saves` | 두 스레드가 동시에 `save_share_links()` 호출 후 파일 `download_count` 정합성 |
| `test_complete_chunk_upload_idempotent` | 동일 `session_id`로 `complete` 두 번 — 파일 하나만 존재 |
| `test_folder_upload_path_traversal_variants` | `paths`에 `..`, `.\`, URL-encoded segment, 깊은 중첩 경로 |
| `test_clipboard_content_size_limit` | 대용량 content POST 시 거부 |
| `test_secret_key_persisted_across_restart` | 재시작 시 세션 쿠키 서명 키 유지 |
| `test_upload_paths_validate_before_makedirs` | 보호 경로·권한 없는 하위 경로에 디렉터리 미생성 |

### 기존 테스트 보강

- `test_upload_integrity.py`: 정상 complete 외 **owner mismatch**, **session 만료 후 chunk**, **disk full(507)** 시나리오.
- `test_download_limits.py`: monkeypatch 의존 줄이고 실제 `reserve_download_quota` 동시성 재검증 (이미 `test_implementation_regressions`에 일부 존재).
- `test_security_hardening_724.py`: share password attempt **영속화 flush** 후 재시작 복원 테스트.
- `test_api_compatibility.py`: Dropbox `501`, capabilities 응답과 README 예시 스키마 일치.

### 회귀 기준선 유지

```bash
pytest -q --basetemp .pytest_tmp   # 기대: 103 passed, 1 skipped
pyright                             # optional deps 설치 환경에서 0 errors 확인
```

현재 실측(2026-06-25): pytest **113 passed, 1 skipped** 통과. pyright는 `orjson` optional import 1건 (환경 의존).

추가 테스트 파일: `tests/test_audit_remediations.py`

---

## 7. Remediation Status

| 감사 항목 | 우선순위 | 상태 | 구현 위치 |
|-----------|----------|------|-----------|
| JSON 영속 저장 lost-update | High | **완료** | `webshare_app/core/persistence.py`, share/permissions/metadata/runtime_state/audit/cloud/duplicates |
| `secret_key` 영속화 | Medium | **완료** | `webshare_app/core/app_paths.py`, `config.py`, `app/factory.py` |
| 배포 가드 (기본 비밀번호·공개 바인딩) | High | **부분 완료** | `security/deployment_guard.py`, `main.py`, `server/thread.py`, `GET /api/security/status` |
| 폴더 업로드 `paths` 검증 | Medium | **완료** | `services/file_service.py` `resolve_folder_upload_target`, `routes/file_routes.py` |
| 클립보드 크기 제한 | Medium | **완료** | `routes/file_routes.py` (`MAX_CLIPBOARD_CONTENT_BYTES`) |
| 청크 `complete` 멱등성 | Medium | **완료** | `services/upload_service.py`, `routes/upload_routes.py` |
| 공유 ZIP 디스크 사전 검사 | Medium | **완료** | `routes/share_routes.py` |
| 프록시/단일 프로세스 문서화 | Low | **완료** | `README.md`, `README_EN.md` |
| Legacy 코드 격리 | Low | **완료** | `legacy/README.md` |
| 감사 회귀 테스트 | — | **완료** | `tests/test_audit_remediations.py` |
| GUI 최초 비밀번호 변경 강제 | High | **미구현** | 로그/API 경고만 제공 |
| 멀티 워커/외부 store | Low | **미구현** | README에 단일 프로세스 전제 명시 |
| 청크 업로드 resume API | — | **미구현** | 장기 과제 |
| 스트리밍 ZIP / rename 버전 백업 | 추정 | **미구현** | 장기 과제 |

---

## 부록: 감사 방법론

- `README.md` 전문 검토 (`CLAUDE.md` 없음).
- CodeGraph MCP `codegraph_explore`로 엔트리포인트·호출 관계·blast radius·미커버 테스트 분석 (쿼리: main/upload/security/share/cloud/persistence 등).
- 보조: 핵심 파일 직접 열람 (`share_routes.py`, `upload_service.py`, `share_links_store.py`, `factory.py` 등), `pytest`/`pyright` 실행.
- 코드 수정은 수행하지 않음. 본 문서만 산출.