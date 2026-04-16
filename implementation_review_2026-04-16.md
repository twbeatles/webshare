# WebShare Pro 구현 점검 메모

작성일: 2026-04-16

## 구현 반영 상태

- `WebShare Stabilization Pass` 구현 완료
- 반영 범위:
  - `password-only(admin/guest)` 모델에 맞춘 사용자 관리 UI/API 정리
  - Google Drive only 클라우드 동기화 정리, 작업 ledger 영속화, 충돌 정책 `skip`
  - 검색 인덱스 스냅샷/`watchdog` fallback, 중복 스캔 cancel API, 청크 merge 스트리밍화
  - 로그인 세션 기반 다운로드 quota 분리, 공유 링크는 IP 기준 유지
- 최신 검증 실행: `pytest -q --basetemp .pytest_tmp` -> `70 passed, 1 skipped`

## 검토 범위

- 참조 문서: `README.md`, `README_EN.md`
- 코드 확인 범위: `routes/`, `features/`, `security/`, `utils/`, `templates/index.html`
- 검증 실행: `pytest -q --basetemp .pytest_tmp` -> `64 passed, 1 skipped`
- 참고: 요청하신 `claude.md`는 현재 저장소 내에서 찾지 못했습니다.

## 핵심 판단

- 현재 코드는 최근 회귀 방어가 잘 되어 있고 테스트도 모두 통과합니다.
- 다만 "기능이 아예 깨진 상태"보다는, 실제 사용자가 기대하는 제품 동작과 구현이 어긋나는 구간이 몇 군데 남아 있습니다.
- 특히 `사용자 관리`, `클라우드 동기화`, `대규모 파일/폴더 운용`, `장시간 백그라운드 작업 제어` 쪽은 우선순위를 두고 정리할 필요가 있습니다.

## 우선순위 높은 이슈

### 1. 사용자 관리 기능이 실제 로그인/권한 체계와 연결되어 있지 않음

근거:

- `routes/admin_routes.py:31, 108-158` 에서 사용자 API가 `login_linked: False` 를 명시하고, `quota_mb`, `folders` 를 저장합니다.
- `routes/main_routes.py:40-60` 에서 실제 로그인은 `admin_pw`, `guest_pw` 두 비밀번호만 검사합니다.
- `features/webdav_server.py:219-250` 도 WebDAV 인증 대상을 `admin`/`guest` 두 계정으로만 고정합니다.
- `templates/index.html:4044-4102` 에서는 `/api/users` 를 호출하는 UI가 그대로 노출됩니다.
- `routes/admin_routes.py:100-123, 137-154, 191-205` 기준으로 `quota_mb`, `folders` 는 조회/저장만 되고 다른 실행 경로에서 소비되지 않습니다.

영향:

- 관리 UI에서 사용자를 만들어도 실제 로그인에 쓸 수 없습니다.
- 폴더 제한, 용량 제한을 설정해도 실질적으로 강제되지 않습니다.
- 운영자 입장에서는 "계정 기능이 있는 것처럼 보이지만 실제로는 메타데이터만 저장되는 상태"라 혼선을 만들 가능성이 큽니다.

권장 보완:

- 두 방향 중 하나를 빠르게 결정하는 것이 좋습니다.
- 방향 A: `/api/users` 와 사용자 관리 UI를 숨기거나 "실험 기능/미연동" 배지로 명확히 내립니다.
- 방향 B: 로그인 진입점, 세션 role 모델, `check_permission`, WebDAV 인증을 모두 사용자 엔터티 기준으로 재설계합니다.
- 방향 B를 택하면 최소한 `username`, `role`, `quota_mb`, `folders` 가 실제 업로드/다운로드/브라우징에 반영되는 통합 테스트를 추가해야 합니다.

### 2. 클라우드 동기화가 대용량 파일과 재시작 상황에 취약함

근거:

- `README.md:67, 395-397` 에서 Cloud Sync는 현재 Google Drive만 실제 구현이고 Dropbox는 placeholder라고 명시합니다.
- 하지만 `templates/index.html:2444-2473, 4839-4875` 에서는 Dropbox 상태 UI와 클라우드 모달이 그대로 노출됩니다.
- `features/cloud_sync.py:253-297` 의 sync 루틴은 전체 폴더를 순회해 수동 upload/download 작업을 수행합니다.
- `features/cloud_sync.py:361-365` 에서 업로드 시 파일 전체를 `file_bytes = handle.read()` 로 메모리에 올립니다.
- `features/cloud_sync.py:387-393` 에서 다운로드도 응답 전체를 메모리에 받은 뒤 `atomic_write_bytes()` 로 저장합니다.
- `features/cloud_sync.py:32-33, 110-170` 기준으로 작업 상태는 `_cloud_jobs` 메모리 딕셔너리에만 존재하고, 영속 저장은 `last_job_id` 정도만 남습니다.
- `routes/cloud_routes.py:72-93` 의 상태 API는 메모리 job 조회 실패 시 재구성할 수 있는 저장소가 없습니다.

영향:

- 대용량 Google Drive 파일 업로드/다운로드 시 메모리 사용량이 급격히 커질 수 있습니다.
- 앱 재시작 후에는 마지막 동기화 작업 상태를 UI가 제대로 설명하지 못할 수 있습니다.
- Dropbox는 "있는 것처럼 보이지만 실제로는 동작하지 않는 UI" 라서 사용자 기대를 깨뜨릴 여지가 큽니다.
- 현재 구현은 이름 충돌 시 원격/로컬 파일을 조용히 덮어쓸 가능성이 있어 수동 동기화라도 안전장치가 약합니다.

권장 보완:

- Google Drive는 스트리밍 또는 resumable upload/download 로 바꾸는 것이 우선입니다.
- 동기화 정책을 `skip`, `rename`, `overwrite` 중 선택 가능하게 만들어야 합니다.
- job 메타데이터를 JSON으로 영속화하거나, 재시작 시 "이전 작업 상태는 복구 불가"를 명시적으로 반환하도록 바꾸는 것이 좋습니다.
- Dropbox UI는 실제 구현 전까지 숨기거나 "미구현" 상태를 버튼 레벨에서 막는 편이 안전합니다.

## 중간 우선순위 이슈

### 3. 검색 인덱스가 메모리 풀빌드 기반이라 대규모 공유 폴더에서 cold start 비용이 큼

근거:

- `features/search_indexer.py:27-28` 에서 인덱스를 메모리 구조체 두 개로 유지합니다.
- `features/search_indexer.py:51-107` 은 전체 `os.walk()` 기반 풀빌드입니다.
- `features/search_indexer.py:206-216` 은 변경 시 5초 debounce 후 재빌드합니다.
- `routes/file_routes.py:601-647` 에서 인덱싱 중이면 `_search_files_fallback()` 로 파일시스템 전체 탐색 fallback 을 수행합니다.
- `routes/file_routes.py:110-138` 의 fallback도 `os.walk()` 기반입니다.

영향:

- 공유 폴더가 커질수록 서버 시작 직후 검색 품질과 응답시간이 흔들릴 수 있습니다.
- 파일 변경이 잦은 환경에서는 rebuild 빈도와 fallback scan 비용이 함께 증가합니다.

권장 보완:

- 인덱스 스냅샷 영속화 또는 최소한 startup warm cache를 넣는 편이 좋습니다.
- 가능하면 파일 이벤트 기반 incremental update로 전환하는 것이 맞습니다.
- fallback 결과 수, 탐색 시간, 대상 디렉터리 깊이에 대한 보호값을 두는 것이 안전합니다.

### 4. 중복 파일 스캔은 취소 로직이 있는데 외부에서 제어할 API/UI가 없음

근거:

- `features/duplicates.py:102-117` 에 취소용 함수와 취소 플래그가 이미 있습니다.
- 그러나 외부 라우트는 `routes/duplicate_routes.py:22, 36, 63` 의 조회/시작/삭제만 있습니다.

영향:

- 공유 폴더가 큰 환경에서는 스캔이 오래 걸릴 수 있는데, 관리자 UI에서 중단할 방법이 없습니다.
- 장시간 스캔 중 다른 유지보수 작업과 충돌해도 운영자가 제어하기 어렵습니다.

권장 보완:

- `POST /api/duplicates/cancel` 추가
- UI에 `running` 상태일 때 cancel 버튼 노출
- 가능하면 현재 phase, ETA, 최근 처리 파일도 같이 내려주면 운영성이 좋아집니다.

### 5. 청크 업로드 완료 단계가 chunk 단위 전체 읽기라 동시 업로드에서 메모리 피크가 커질 수 있음

근거:

- `routes/upload_routes.py:24-26` 에서 청크 최대 크기는 `100MB`, 사용자별 pending 총량은 `20GB` 입니다.
- `routes/upload_routes.py:437-447` 에서 병합 시 각 chunk 파일을 `chunk_file.read()` 로 통째로 읽어 `output_file.write()` 합니다.

영향:

- 단일 업로드는 통과하더라도, 완료 시점이 겹치면 worker 메모리 사용량이 커질 수 있습니다.
- 특히 EXE 배포나 저사양 NAS/미니PC 환경에서는 체감 문제가 생길 가능성이 있습니다.

권장 보완:

- 병합은 `shutil.copyfileobj()` 같은 스트리밍 방식으로 바꾸는 것이 안전합니다.
- 완료 단계에서도 진행률을 기록하면 장시간 merge에 대한 관측성이 좋아집니다.

### 6. 다운로드/대역폭 제한이 IP 단위라 NAT/프록시 환경에서 사용자 간 간섭이 발생할 수 있음

근거:

- `README.md:220-221, 298` 에서 일일 다운로드/대역폭 제한 기능이 문서화되어 있습니다.
- `utils/helpers.py:244-280` 의 실제 추적 키는 `DOWNLOAD_TRACKER[ip]` 하나입니다.
- 실제 다운로드 경로도 `routes/file_routes.py:179-184, 703, 860` 과 `routes/share_routes.py:356-377` 에서 모두 IP 기준으로 집계합니다.

영향:

- 같은 회사/가정망 뒤에 있는 여러 사용자가 하나의 quota를 공유하게 됩니다.
- 리버스 프록시나 모바일 캐리어 NAT 환경에서는 제한이 예상보다 빠르게 소진될 수 있습니다.

권장 보완:

- 최소한 `session_id + ip` 또는 `account + ip` 조합으로 선택 가능하게 하는 것이 좋습니다.
- 공유 링크는 비로그인 접근이므로 현재 IP 기준을 유지하되, 일반 로그인 트래픽은 세션 기준 옵션을 별도로 두는 편이 현실적입니다.

## 추가하면 좋은 구현 항목

### 1. 사용자 기능 정리

- "사용자 API 미연동" 상태를 README뿐 아니라 UI에도 명시
- 실제 로그인 통합 전까지 user CRUD 버튼 비활성화

### 2. 클라우드 동기화 안전장치

- overwrite 정책 선택
- dry-run 또는 변경 미리보기
- 취소 API, 재시도 API
- 대용량 파일 스트리밍 전송

### 3. 운영성 개선

- duplicate scan cancel
- search index 상태/최근 build duration 경고
- long-running task 공통 job registry 정리

### 4. 테스트 보강

- "생성한 user로는 로그인되지 않는다" 현재 제약을 명시하는 테스트
- cloud sync large-file 경계 테스트
- cloud sync restart 후 status 복구/실패 동작 테스트
- duplicate cancel API 테스트
- chunk merge 메모리/스트리밍 경로 테스트

## 추천 처리 순서

1. 사용자 관리 기능을 숨길지, 실제 계정 모델로 통합할지 먼저 결정
2. Google Drive sync를 스트리밍/충돌정책/작업영속성 기준으로 재설계
3. duplicate scan cancel과 검색 인덱스 운영성 개선
4. chunk merge 스트리밍화와 quota scope 개선

## 결론

- 지금 상태는 "기능이 많은 단일 서버 앱"으로서는 꽤 안정적입니다.
- 다만 사용자 관리와 클라우드 동기화는 현재 구현 범위와 UI 노출 범위가 어긋나 있어, 제품 완성도 관점에서 가장 먼저 정리해야 합니다.
- 위 항목들만 정리해도 실제 사용자 혼선과 운영 리스크가 크게 줄어들 가능성이 높습니다.
