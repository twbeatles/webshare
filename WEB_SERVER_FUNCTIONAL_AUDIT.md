# WebShare 웹서버 기능 점검 리포트

## 1. 개요
- 점검 대상: `D:/twbeatles-repos/webshare` 웹서버 기능 구현 전반(인증/권한/보안/다운로드/스트리밍/운영성/성능 관점).
- 기준 문서: `README.md` (요청 반영).
- 점검 일시: 2026-02-26.
- 점검 방식: 코드 정적 점검 + 라우트/설정 구조 분석 + README 요구사항 매핑.
- 점검 제외 범위:
  - 실제 침투 테스트/동적 공격 시뮬레이션.
  - 코드 수정/배포/마이그레이션 실행.
  - 외부 인프라(Nginx, LB, WAF) 구성 검증.

## 2. 공개 API/인터페이스 영향(권고)
- `GET/POST/PUT/DELETE` 공통 정책:
  - 상태 변경 엔드포인트 전부에 CSRF 검증 강제.
- 보호 경로 정책:
  - `/download/*`, `/stream/*`, `/preview/*`, WebDAV에서 `.webshare*` 및 숨김 파일 접근 시 `403`.
- 라우팅 정리:
  - 중복 `GET /api/audit_log` 단일화(호환 alias는 명시적 처리).
- 운영 진단 API 추가:
  - `GET /healthz` (프로세스 생존성)
  - `GET /readyz` (의존성/런타임 준비상태)
- 권한 모델 적용:
  - `check_permission()`을 `browse/list/download/upload/delete/stream` 경로에 공통 적용.

## 3. 심각도 기준
- `Critical`: 인증/권한 우회, 민감정보 노출, 서비스 중단으로 직결 가능.
- `High`: 보안/운영 리스크가 높고 실제 운영 장애로 이어질 가능성이 큼.
- `Medium`: 즉시 치명적이지 않지만 누적 시 장애/품질 저하를 유발.
- `Low`: 개선 권장 수준(품질/운영 편의/관측성 중심).

## 4. 핵심 발견사항

### F-01. CSRF 검증 범위 공백
- ID: `F-01`
- 심각도: `Critical`
- 증거(파일:라인):
  - `routes/main_routes.py:27` (`@main_bp.before_request`)
  - `routes/main_routes.py:54` (`validate_csrf_token()` 호출)
  - `server.py:174` (Jinja 전역 `csrf_token` 등록만 존재)
- 영향:
  - `main_bp` 외 블루프린트의 상태변경 API(POST/PUT/DELETE)에 CSRF 강제가 누락될 수 있음.
- 재현 조건:
  - 인증된 세션 쿠키가 있는 브라우저에서 타 블루프린트 상태변경 API 호출.
- 권장 조치:
  - 앱 전역 `before_request`에서 메서드 기반 CSRF 강제 또는 공통 데코레이터 도입.
  - 예외 엔드포인트(웹훅 등)만 allowlist로 관리.
- 예상 난이도: `중`

### F-02. 실제 IP 판별 신뢰 경계 부재
- ID: `F-02`
- 심각도: `High`
- 증거(파일:라인):
  - `utils/file_utils.py:22`
  - `utils/file_utils.py:25`
  - `utils/file_utils.py:28`
- 영향:
  - `X-Forwarded-For` 헤더를 무조건 신뢰해 IP 스푸핑 가능.
  - IP 차단/화이트리스트/감사로그 정확도 저하.
- 재현 조건:
  - 프록시 비신뢰 환경에서 `X-Forwarded-For` 임의 주입.
- 권장 조치:
  - 신뢰 프록시 목록 기반 파싱(예: `ProxyFix` + trusted hops).
  - 미신뢰 환경에서는 `remote_addr` 우선.
- 예상 난이도: `중`

### F-03. `.webshare_*` 운영 파일 직접 접근 가능성
- ID: `F-03`
- 심각도: `High`
- 증거(파일:라인):
  - `routes/file_routes.py:32`, `routes/file_routes.py:78` (`/download/*` 직접 전송)
  - `routes/media_routes.py:34`, `routes/media_routes.py:236`, `routes/media_routes.py:341`
  - `routes/share_routes.py:205` (`send_from_directory`)
  - `utils/listing.py:149` (UI 목록에서 숨김만 수행)
- 영향:
  - 운영 메타 파일(`.webshare_*`)이 URL 직접 접근으로 노출될 위험.
- 재현 조건:
  - 경로를 직접 알고 `/download/.webshare_...` 등 호출.
- 권장 조치:
  - `/download/*`, `/stream/*`, `/preview/*`, WebDAV 공통 denylist(`.webshare*`, 숨김) 적용.
- 예상 난이도: `중`

### F-04. 폴더 권한 엔진 미적용
- ID: `F-04`
- 심각도: `Critical`
- 증거(파일:라인):
  - `security/permissions.py:16` (`check_permission()` 정의)
  - 전역 검색 결과: `check_permission()` 호출처가 정의부 외 없음
- 영향:
  - README의 폴더 권한 기능이 실질 enforcement 없이 관리 UI 수준에 머무를 수 있음.
- 재현 조건:
  - 권한 설정 후 browse/download/upload/delete API 접근 테스트.
- 권장 조치:
  - browse/list/download/upload/delete/stream 전 경로에 권한 체크 삽입.
- 예상 난이도: `중~상`

### F-05. 권한 변경 영속화 누락 가능성
- ID: `F-05`
- 심각도: `High`
- 증거(파일:라인):
  - `routes/admin_routes.py:238`, `routes/admin_routes.py:264`, `routes/admin_routes.py:271`
  - `security/permissions.py:52` (`save_permissions()` 정의)
  - `server.py:50` (`load_permissions()`만 초기화 시 호출)
- 영향:
  - 권한 API 변경이 재시작 시 소실될 가능성.
- 재현 조건:
  - 권한 API 호출 후 서버 재시작하여 값 유지 여부 확인.
- 권장 조치:
  - 권한 변경 API에서 `save_permissions()` 호출 표준화.
- 예상 난이도: `하`

### F-06. 클라우드 설정 저장 경로/스키마 불일치
- ID: `F-06`
- 심각도: `High`
- 증거(파일:라인):
  - `routes/cloud_routes.py:17`, `routes/cloud_routes.py:23`, `routes/cloud_routes.py:24`
  - `features/cloud_sync.py:14`, `features/cloud_sync.py:17`, `features/cloud_sync.py:34`
  - `config.py:59` (`CLOUD_SYNC_FILE = ".webshare_cloud.json"`)
- 영향:
  - 저장 위치/내용(민감값 포함 여부) 불일치로 설정 일관성 저하 및 보안 리스크 증가.
- 재현 조건:
  - Cloud 설정 저장 후 재시작 시 반영 상태 비교.
- 권장 조치:
  - `routes/cloud_routes.py` 저장 로직 제거 후 `features.cloud_sync.save_cloud_config()` 단일화.
- 예상 난이도: `중`

### F-07. `GET /api/audit_log` 라우트 중복 등록
- ID: `F-07`
- 심각도: `High`
- 증거(파일:라인):
  - `routes/api_routes.py:174`
  - `routes/admin_routes.py:318`
  - `routes/__init__.py:28`, `routes/__init__.py:35`
- 영향:
  - 라우팅 충돌/핸들러 비결정성으로 응답 스키마 불일치 위험.
- 재현 조건:
  - 동일 엔드포인트 호출 시 반환 스키마 비교(`logs` 페이징 유무).
- 권장 조치:
  - 단일 라우트로 통합하고 나머지는 301/호환 alias로 정리.
- 예상 난이도: `중`

### F-08. 다운로드 제한 정책 우회 경로 존재
- ID: `F-08`
- 심각도: `High`
- 증거(파일:라인):
  - 제한 적용: `routes/file_routes.py:54`, `routes/file_routes.py:65`, `routes/media_routes.py:446`, `routes/media_routes.py:455`
  - 제한 미적용 고용량 경로: `routes/file_routes.py:422`, `routes/file_routes.py:511`, `routes/share_routes.py:143`, `routes/share_routes.py:203`
- 영향:
  - ZIP/공유 ZIP/배치 ZIP 경로로 정책 우회 가능.
- 재현 조건:
  - 일일 다운로드 제한 설정 후 ZIP/공유 링크 다운로드 시도.
- 권장 조치:
  - 공통 다운로드 정책 미들웨어(또는 헬퍼)로 모든 바이너리 전송 경로 통합 적용.
- 예상 난이도: `중`

### F-09. `request.get_json()` 널 처리 미흡
- ID: `F-09`
- 심각도: `Medium`
- 증거(파일:라인):
  - 직접 체이닝: `routes/media_routes.py:371`, `routes/file_routes.py:669`, `routes/admin_routes.py:392`
  - 다수 라우트에서 `data = request.get_json()` 후 `data.get(...)` 패턴 사용(널 가드 불충분)
- 영향:
  - 잘못된 Content-Type/빈 바디에서 `NoneType` 오류로 500 가능.
- 재현 조건:
  - JSON 바디 누락/비JSON 요청으로 상태변경 API 호출.
- 권장 조치:
  - `request.get_json(silent=True) or {}` 패턴 공통화 + 입력 스키마 검증.
- 예상 난이도: `하`

### F-10. WebDAV 보안 강도 부족(Basic 중심/TLS 강제 없음)
- ID: `F-10`
- 심각도: `High`
- 증거(파일:라인):
  - `features/webdav_server.py:27` (Basic Auth)
  - `features/webdav_server.py:48` (Digest 미지원)
  - `features/webdav_server.py:68` (메서드 기반 단순 권한)
  - `server.py:189` (`use_https=False` 기본)
  - `server.py:202`, `server.py:237` (HTTP 기본 + `/webdav` 마운트)
- 영향:
  - 네트워크 구간 보호/브루트포스 방어가 약하면 자격증명 노출 및 무차별 대입 위험.
- 재현 조건:
  - HTTP 운용 또는 외부 노출 환경에서 WebDAV 접근.
- 권장 조치:
  - TLS 강제(리버스 프록시 포함), 인증 시도 제한, IP 기반 보호, 감사로그 확장.
- 예상 난이도: `중~상`

### F-11. 세션 타임아웃/통계 갱신이 `main_bp` 중심
- ID: `F-11`
- 심각도: `Medium`
- 증거(파일:라인):
  - `routes/main_routes.py:27`, `routes/main_routes.py:37`, `routes/main_routes.py:38`, `routes/main_routes.py:62`
  - `routes/main_routes.py:80`, `routes/main_routes.py:86`
  - `routes/root_api_routes.py:89` (타임아웃 기본값 30으로 상이)
- 영향:
  - API 중심 사용 패턴에서 세션/통계 일관성 저하 가능.
- 재현 조건:
  - 메인 페이지 접근 없이 API만 반복 호출하는 세션 시나리오.
- 권장 조치:
  - 앱 전역 미들웨어로 세션/통계 처리 일원화.
- 예상 난이도: `중`

### F-12. 검색 exact match 결과 타입 왜곡 가능
- ID: `F-12`
- 심각도: `Medium`
- 증거(파일:라인):
  - `features/search_indexer.py:151` (exact match 분기)
  - `features/search_indexer.py:158` (`'is_dir': False` 고정)
  - `features/search_indexer.py:28` (`doc_index`는 is_dir 보유)
- 영향:
  - 디렉터리 검색 결과가 파일로 오인되어 UI/동작 불일치 가능.
- 재현 조건:
  - 폴더명 exact 검색 시 결과 클릭 동작 확인.
- 권장 조치:
  - exact index에도 `is_dir` 메타 포함하거나 doc_index와 통합 조회.
- 예상 난이도: `하~중`

### F-13. `set_language` 비인증 GET으로 서버 설정 변경
- ID: `F-13`
- 심각도: `High`
- 증거(파일:라인):
  - `routes/main_routes.py:261` (`@main_bp.route('/set_language/<lang>')`, 인증 데코레이터 없음)
  - `routes/main_routes.py:267` (`conf.save()` 호출)
- 영향:
  - 비인증 요청이 서버 전역 설정 파일(`webshare_config.json`)을 변경 가능.
- 재현 조건:
  - 로그인 없이 `/set_language/en` 호출 후 설정 파일 변경 확인.
- 권장 조치:
  - 세션 단위 언어와 서버 전역 설정 분리.
  - 최소 `login_required()` + POST 전환 + CSRF 적용.
- 예상 난이도: `중`

### F-14. 자동화 테스트 부재
- ID: `F-14`
- 심각도: `Medium`
- 증거:
  - 리포지토리 검색 시 `tests/`, `test_*.py`, `*_test.py` 확인되지 않음(2026-02-26 점검).
- 영향:
  - 보안/성능 회귀를 조기에 탐지하기 어려움.
- 재현 조건:
  - 기능 변경 후 수동 테스트 의존.
- 권장 조치:
  - 우선순위 높은 API부터 pytest 기반 스모크/권한/보안 테스트 작성.
- 예상 난이도: `중`

## 5. README 요구사항 매핑
- `README.md` 보안 강화 항목(XSS/경로보호/권한)과 관련: `F-01`, `F-03`, `F-04`, `F-10`, `F-13`
- `README.md` 폴더 권한 세분화 관련: `F-04`, `F-05`
- `README.md` 성능/안정성 관련(다운로드/ZIP/인덱싱): `F-08`, `F-11`, `F-12`, `F-14`
- `README.md` WebDAV/PWA/운영 항목 관련: `F-10`, `F-14`

## 6. 추가 구현 권고

### 5.1 즉시(Immediate)
- 전역 CSRF 강제(상태변경 메서드 전부).
- `.webshare*` 및 숨김 경로 다운로드/스트림/미리보기/WebDAV 차단.
- `set_language` 인증/메서드/저장 정책 수정.
- 중복 `/api/audit_log` 단일화.

### 5.2 단기(Short-term)
- `check_permission()` 라우트 전면 적용.
- 권한 API 저장 로직 `save_permissions()` 연동.
- 다운로드 제한 공통화(파일/ZIP/공유/HLS 일원화).
- 클라우드 설정 저장 경로/스키마 단일화(`features.cloud_sync` 기준).

### 5.3 중기(Mid-term)
- `healthz/readyz` 추가 및 관측성(메트릭, 에러율, 큐 깊이) 확장.
- 입력 스키마 검증 도입(Pydantic/Marshmallow 등).
- WebDAV 보안 강화(TLS 강제, 레이트리밋, 감사로그 세분화).
- 자동화 테스트 체계 구축(권한/보안/성능 회귀).

## 7. 검증 시나리오

### 6.1 기능/권한 회귀
- 비인증/게스트/관리자 권한 매트릭스 점검.
- 폴더 권한 설정 후 browse/download/upload/delete/stream 강제 여부 점검.
- 세션 타임아웃 후 API 응답 일관성(401/redirect) 점검.

### 6.2 보안 검증
- 숨김 운영 파일 직접 접근 차단 점검(다운로드/스트림/미리보기/WebDAV).
- CSRF 토큰 누락 상태변경 요청 차단 점검.
- 프록시 헤더 조작 시 실제 IP 판별/차단 정책 점검.
- WebDAV 인증 실패 반복 시 브루트포스 방어 동작 점검.

### 6.3 성능/리소스 검증
- ZIP/공유 ZIP/배치 ZIP 경로에서 다운로드 제한 정책 일관성 점검.
- 10k/100k 파일 기준 browse/list/search/zip 응답시간 및 메모리 스모크 점검.
- 인덱싱 중 동시 요청 지연/오류율 점검.

## 8. 결론: 우선 착수 항목 Top 5
1. 전역 CSRF 보호 적용(`F-01`).
2. 폴더 권한 엔진 실제 enforcement 적용(`F-04`).
3. `.webshare*` 운영 파일 접근 차단(`F-03`).
4. 다운로드 제한 정책 전 경로 통합(`F-08`).
5. `set_language` 비인증 설정 변경 제거(`F-13`).

---

### 가정 및 기본값
- 기준 문서는 `README.md`만 사용.
- 산출물은 루트 단일 파일 `WEB_SERVER_FUNCTIONAL_AUDIT.md`.
- 초기 작성 범위는 점검 리포트 작성(코드 수정 미포함)이었으며, 후속 반영 결과는 9장에 별도 기록.
- 개선 권고는 하위호환 우선(기존 URL 유지, 정책/내부 강화 중심).

---

## 9. 구현 반영 상태 업데이트 (2026-02-26)

아래 항목은 본 리포트 작성 이후 코드에 실제 반영된 상태를 요약한 것입니다.

### 9.1 F-01~F-14 반영 요약
- `F-01` CSRF 전역 강제: **반영 완료**
  - `server.py` 전역 `before_request`에서 로그인 세션의 `POST/PUT/PATCH/DELETE` 검증.
- `F-02` 실제 IP 신뢰 경계: **반영 완료**
  - `utils/file_utils.py`에 `trusted_proxies`, `trusted_hops` 기반 판별 로직 적용.
- `F-03` 시스템/숨김 경로 차단: **반영 완료**
  - `/download`, `/stream`, `/preview`, WebDAV 경로에서 `.webshare*`/숨김 세그먼트 403 차단.
- `F-04` 권한 엔진 enforcement: **반영 완료**
  - `ensure_path_access()` 경유로 browse/list/download/upload/delete/stream 계열 적용.
- `F-05` 권한 변경 영속화: **반영 완료**
  - 권한 변경 API에서 `save_permissions()` 호출 보장.
- `F-06` 클라우드 설정 저장 단일화: **반영 완료**
  - `features.cloud_sync.save_cloud_config()` 단일 저장 경로 사용.
- `F-07` `/api/audit_log` 중복 제거: **반영 완료**
  - canonical 구현(`routes/admin_routes.py`) 단일화, `limit` 호환 유지.
- `F-08` 다운로드 제한 우회 방지: **반영 완료**
  - 파일/ZIP/배치 ZIP/공유/공유 ZIP/HLS 세그먼트에 일관 적용.
- `F-09` JSON 널 안전화: **반영 완료**
  - 라우트 전반 `parse_json_body()` 적용으로 `NoneType` 500 경로 제거.
- `F-10` WebDAV 보안 강화: **반영 완료**
  - 보호 경로 차단, 비TLS 쓰기 거부(기본), Basic 실패 카운트/임시 차단 추가.
- `F-11` 세션/통계 전역화: **반영 완료**
  - `main_bp` 편중 로직을 app 전역 훅으로 이동.
- `F-12` 검색 exact 타입 정합성: **반영 완료**
  - exact index 결과에 `is_dir` 메타 반영.
- `F-13` 언어 API 보안/호환: **반영 완료**
  - 표준 `POST /set_language` + CSRF, 구형 `GET /set_language/<lang>`은 호환 래퍼+Deprecation.
- `F-14` 자동화 테스트 부재: **반영 완료**
  - `tests/test_security_policies.py`
  - `tests/test_permissions_enforcement.py`
  - `tests/test_api_compatibility.py`
  - `tests/test_download_limits.py`

### 9.2 검증 결과
- `pytest -q` 실행 결과: **9 passed**
- `python -m compileall`로 변경 파일 문법 검증 통과

### 9.3 문서 해석 주의
- 본문 4장(F-01~F-14)은 “점검 시점의 발견사항”이며, 9장은 “후속 구현 반영 결과”입니다.
- 운영 적용 시에는 9장 상태와 최신 코드를 기준으로 해석하는 것을 권장합니다.
