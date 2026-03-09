# WebShare Pro 기능 구현 점검 보고서 (2026-03-05)

## 점검 범위
- 문서: `README.md`, `README_EN.md`
- 코드: `routes/`, `features/`, `security/`, `utils/`, `server.py`, `main.py`, `docker_entrypoint.py`
- 요청 문서: `claude.md` (저장소 내 파일 미발견)
- 실행 검증: `pytest -q`

## 실행 결과 요약
- 테스트 결과: `31 passed, 1 skipped` (2026-03-05 실행)
- 현재 회귀 테스트는 전반적으로 안정적이지만, 아래 리스크는 테스트 공백 또는 정책 미정 영역에서 발생 가능

## 주요 발견 사항 (우선순위순)

### 1) [High] 청크 업로드 실제 수신 바이트 미검증으로 디스크 고갈(DoS) 가능
- 근거:
  - 선언된 총량(`total_size`)만 검사: `routes/upload_routes.py:126`
  - 세션 압력 제한도 선언 총량 기반: `routes/upload_routes.py:165`, `routes/upload_routes.py:172`
  - 실제 chunk 파일 크기 검증 없이 저장: `routes/upload_routes.py:249`
- 영향:
  - 공격자가 `total_size`를 작게 선언하고 실제로 큰 chunk를 반복 업로드하면, 현재 세션/총량 제한을 우회해 임시 디렉터리(`.upload_temp`)를 급격히 키울 수 있습니다.
  - 서버 디스크 고갈로 업로드/다운로드/로그 저장 등 핵심 기능이 연쇄 장애를 일으킬 수 있습니다.
- 권장 조치:
  - `upload_chunk`에서 `chunk_file.content_length`/실측 파일 크기 기준으로 `chunk_size` 상한을 강제.
  - 세션에 `uploaded_bytes`를 저장하고 `uploaded_bytes <= total_size`를 실시간 검증.
  - owner별 제한을 선언 총량이 아니라 실제 수신 바이트 기반으로 병행 적용.

### 2) [High] JSON 문서 미리보기 XSS 가능성
- 근거:
  - JSON preview HTML 생성 시 escape 없이 삽입: `routes/media_routes.py:360`
  - 프론트에서 해당 값을 `innerHTML`로 직접 렌더링: `templates/index.html:3752`
  - 문서에는 XSS 방지 강화가 명시됨: `README_EN.md:75`, `README_EN.md:78`
- 영향:
  - JSON 파일 값에 HTML/이벤트 핸들러 문자열이 포함될 경우, 문서 미리보기 모달에서 스크립트 실행(Stored XSS) 가능성이 있습니다.
- 권장 조치:
  - JSON preview는 `escape()` 후 `<pre>`에 넣거나, 클라이언트에서 `innerText` 기반 렌더링으로 변경.
  - 회귀 테스트 추가: 악성 JSON payload(`"<img src=x onerror=...>"`) 미리보기 시 스크립트가 실행되지 않음을 검증.

### 3) [Medium] 폴더 업로드 충돌 처리 시 원래 하위 경로가 유실되는 로직
- 근거:
  - 폴더 구조 업로드 경로 생성: `routes/file_routes.py:175`, `routes/file_routes.py:180`
  - 동일 파일명 충돌 시 재경로가 루트(`full_path`)로 재설정됨: `routes/file_routes.py:199`, `routes/file_routes.py:200`
- 영향:
  - 예: `sub/a.txt` 충돌 시 `sub/a_1.txt`가 아니라 상위 폴더의 `a_1.txt`로 저장될 수 있습니다.
  - 대량 폴더 업로드에서 파일 위치가 의도와 달라지고, 사용자 관점에서 "유실"로 인지될 수 있습니다.
- 권장 조치:
  - 충돌 시 `os.path.dirname(file_path)`를 유지한 상태에서 파일명만 변경.
  - 케이스 테스트 추가: nested path 충돌 시 동일 디렉터리 내 rename되는지 검증.

### 4) [Medium] 배치 다운로드에서 제한 체크 순서가 비효율적
- 근거:
  - ZIP 생성 먼저 수행: `routes/file_routes.py:716`
  - 다운로드 제한 체크는 생성 후 수행: `routes/file_routes.py:719`
- 영향:
  - 이미 제한 초과 상태인 사용자 요청에도 ZIP 생성 CPU/디스크 비용이 먼저 발생해 자원 낭비가 큽니다.
  - 반복 요청 시 서비스 성능 저하 요인이 됩니다.
- 권장 조치:
  - ZIP 생성 전에 1차 `check_download_limit()` 수행.
  - 필요 시 예상 크기 기반 사전 차단(soft limit) 추가.

### 5) [Medium] 메타데이터 조회 API가 전역 데이터 전체를 그대로 반환
- 근거:
  - 태그 전체 반환: `routes/metadata_routes.py:44`
  - 즐겨찾기 전체 반환: `routes/metadata_routes.py:93`
  - 북마크 전체 반환: `routes/metadata_routes.py:181`
- 영향:
  - 로그인 사용자(guest 포함)가 본인 권한과 무관한 경로 메타데이터를 열람할 수 있습니다.
  - 멀티 사용자/조직 환경에서 정보 노출로 해석될 수 있습니다.
- 권장 조치:
  - 반환 전 `ensure_path_access(..., 'read')` 필터를 적용.
  - 정책적으로 전역 공유가 맞다면 README에 명시적으로 "전역 메타데이터"라고 선언.

### 6) [Low] 사용자 저장 파일 쓰기 원자성 부재
- 근거:
  - 사용자 파일 직접 overwrite 저장: `routes/admin_routes.py:80`
  - 동일 프로젝트의 다른 저장 로직은 임시파일+rename 원자적 쓰기 사용 (`features/share_links_store.py`, `features/audit_log.py` 등)
- 영향:
  - 비정상 종료/디스크 오류 시 `.webshare_users.json` 손상 가능성이 상대적으로 높습니다.
- 권장 조치:
  - 사용자 저장도 temp file + rename 패턴으로 통일.

### 7) [Low] 텍스트 파일 편집기 조회 시 대용량 파일 메모리 급증 가능
- 근거:
  - 전체 파일 내용을 한 번에 읽음: `routes/media_routes.py:397`, `routes/media_routes.py:398`
- 영향:
  - 매우 큰 로그/텍스트 파일 요청 시 워커 메모리 압박 및 응답 지연 가능.
- 권장 조치:
  - 조회 상한(예: 5~10MB) 또는 부분 읽기(페이징/offset) API로 분리.

## 추가 구현 권장 사항
- 에러 응답 표준화: 현재 여러 엔드포인트가 `str(e)`를 그대로 반환하고 있어 내부 경로/예외 정보 노출 위험이 있습니다. 사용자 메시지와 내부 로그를 분리하는 공통 핸들러를 권장합니다.
- 클립보드 스코프 분리: `routes/file_routes.py:868`의 전역 클립보드는 사용자 간 상호 덮어쓰기 가능성이 있어 `session_id` 단위 저장으로 분리 권장.
- 보안 회귀 테스트 추가:
  - chunk 실제 바이트 초과 업로드 차단 테스트
  - JSON preview XSS 차단 테스트
  - 폴더 업로드 충돌 시 경로 유지 테스트

## 참고 메모
- `README_EN.md` 기준으로 보안/기능 설명은 전반적으로 잘 정리되어 있으며, 특히 WebDAV/Cloud(Mock) 관련 최근 보강 사항은 코드 반영 상태가 양호합니다.
- 다만 이번 점검에서 식별된 항목은 "기능은 동작하지만 운영 환경에서 사고로 이어질 수 있는 구현 디테일" 성격이므로 우선순위대로 보강하는 것이 좋습니다.

---

## 후속 정합성 반영 결과 (2026-03-05)

- 본 문서의 개선 권고 사항은 one-shot으로 반영 완료.
- 현재 기준 검증 결과: `pytest -q` -> `44 passed, 1 skipped` (2026-03-05).
- 추가 정합성 반영:
  - `webshare.spec`, `WebSharePro.spec`에 `utils.api_errors` hidden import 반영.
  - `.gitignore`에 WebShare 런타임 임시 파일/디렉터리 패턴(`.webshare_*.tmp`, `.webshare_*.json`, `.upload_temp`, `.webshare_uploads`, `.webshare_transcode`) 보강.
  - `README.md`, `README_EN.md`에 최신 구현/빌드/무시 규칙 동기화 내용 추가.

---

## 정적분석 정합성 반영 결과 (2026-03-09)

- 범위 고정:
  - `pyrightconfig.json` 추가
  - 실사용 코드 + 테스트만 분석 대상으로 유지
  - `legacy/웹서버 프로그램v4.py`는 보관 코드로 간주해 분석 범위에서 제외
- 타입 정합성 반영:
  - `config.py`의 `ConfigManager.get()`에 주요 키별 타입 오버로드 추가
  - Flask 라우트의 암묵적 `None` 반환 경로 제거
  - GUI/WebDAV/UPnP/트랜스코더 관련 nullable 및 선택 의존성 흐름 정리
- 외부 의존성 경고 정리:
  - `typings/cachetools/__init__.pyi` 로컬 스텁 추가
  - `pyrightconfig.json`에서 외부 wheel source 부재로 발생하던 `reportMissingModuleSource` 노이즈 정리
  - `utils.dashboard_service`, `utils.listing`의 `cachetools` 관련 경고 제거
- 빌드 스펙 정합성 추가 반영:
  - `webshare.spec`, `WebSharePro.spec`에 `miniupnpc`, `wsgidav.dc.base_dc`, `wsgidav.fs_dav_provider`, `wsgidav.wsgidav_app` hidden import 동기화
  - `importlib` 기반 선택 의존성 로딩이 동결 빌드에서도 누락되지 않도록 맞춤
- 무시 규칙 보강:
  - `.gitignore`에 `.venv/`, `venv/`, `env/`, `.mypy_cache/`, `.ruff_cache/` 추가
- 검증 결과:
  - `pyright` -> `0 errors, 0 warnings`
  - `pytest -q` -> `44 passed, 1 skipped`
  - UTF-8 / replacement char 스캔 -> 문제 없음
