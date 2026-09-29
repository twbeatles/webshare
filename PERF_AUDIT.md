# Performance Audit

> **작성일:** 2026-09-29
> **대상:** WebShare Pro v7.3.0 (Go + Python 하이브리드) — 성능 관점
> **관점:** 요청 핫패스·전송 처리량/메모리·백그라운드/영속화 비용 (코드는 수정하지 않음)
> **구조:** `PROJECT_AUDIT.md` 섹션 1–4, 7–9를 성능 관점으로 적용 (5 잠재 기능 공백·6 문서 불일치는 제외)
> **합성 범위:** 구현 리포트 3건(perf-hotpaths, perf-transfer, perf-background)은 본 실행에 전달되지 않아(`Resolved prior workflow child results` 없음, journal 조회 수단 없음) 참조하지 못했다. 대신 세 리포트가 커버하는 동일 영역(핫패스/전송/백그라운드)의 테스트 파일 3건과 구현 코드를 직접 점검하여 본 문서를 작성했다. 아래의 모든 이슈는 코드 근거가 있는 것만 기재한다.

## 1. Executive Summary

- **프로젝트 전체 상태:** 측정된 성능 문제 3개 영역(이웃 페이지 재스캔, 폴더 크기 전수 `os.walk`, 무제한 ffmpeg/ZIP 생성, 공유 다운로드마다 전체 링크 저장소 재기록, 8 KiB 해시 청크)이 모두 코드로 수정되어 있고, 영역별 회귀 테스트 23개가 통과한다. 핫패스 응답 정규화의 대용량 재파싱 회피, `/stream` Range 강건성(접미사 범위·416)도 구현되어 있다.
- **전체 위험도:** **Acceptable (일부 Needs Work)** — 알려진 핫패스 폭탄은 제거되었으나, HLS 플레이리스트 대기 루프의 워커 스레드 블로킹(최대 10초)과 중복 스캔의 매회 전수 `os.walk`는 잔존 비용이다. 둘 다 정상 동작을 깨뜨리지는 않으며 뒤에 계획으로 둔다.
- **가장 중요한 문제 3~5개:**
  1. [PERF-005] HLS 플레이리스트 대기 루프가 Flask 워커 스레드를 최대 10초 블로킹 — 동시 재생 시 처리량 저하 (Medium, Confirmed).
  2. [PERF-006] 중복 스캔이 매회 전수 `os.walk` + 전체 해시 재계산, 증분 인덱스 없음 — 대용량 공유 폴더에서 수 분 블로킹 가능 (Medium, Likely).
  3. [PERF-007] Go 백엔드 성능 동등성 미검증 — listing 캐시·ZIP 상한·폴더 크기 제외 규칙의 Go 측 대응을 본 감사에서 끝까지 확인하지 못함 (Medium, Speculative/미확인).
  4. 그 외 PERF-001~004는 **수정 완료 + 테스트 통과** 상태이므로 아래에는 증거 기록으로만 남긴다.
- **데이터 손상/유실 가능성 여부:** 없음. 성능 수정 중 영속성 안전을 약화하는 변경은 없다. 오히려 capped 공유 링크는 예약마다 영속화하여 크래시 시 `max_downloads` 초과를 방지한다. Uncapped 링크의 카운터는 크래시 시 손실되나 정보성 카운터이며 정책 강제와 무관하다.
- **가장 먼저 다룰 영역:** `webshare_app/routes/media_routes/streaming.py`의 HLS 대기 루프(논블로킹 대기), 그 다음 중복 스캔 증분화, 마지막으로 Go 성능 parity 확인.

## 2. Project Understanding

### 성능 관점에서 본 목적

단일 데스크톱 프로세스(기본 Go 백엔드, Flask 폴백)에서 수천 파일 목록·대용량 다운로드/ZIP·HLS 트랜스코딩·공유 링크·백그라운드 스캔을 무제한 리소스 증식 없이 처리하는 것.

### 핵심 핫패스 (요청당 비용이 문제되던 경로)

- `GET /api/list/...` → `webshare_app/utils/listing.py::list_directory_page` — 디렉터리당 `os.scandir` 1회 + 메모리 내 정렬/필터/페이지 분할. 페이지 캐시와 베이스(전수) 캐시의 2계층 TTL 캐시(`_list_cache` 512항목 / `_list_base_cache` 32항목, TTL 2초).
- 대시보드/요약 → `webshare_app/utils/file_utils.py::get_folder_size` — 전수 `os.walk` + `getsize` 합산. 60초 TTL 캐시 + 변이 블루프린트(file/trash/upload)의 after-request 무효화 훅. 스테이징 디렉터리(`.upload_temp`, `.webshare_transcode`)는 집계 제외.
- 전역 after-request → `webshare_app/app/factory.py::_global_after_request` — 에러 성격 JSON의 스키마 정규화. 대용량 성공 본문은 크기 게이트(`_JSON_ERROR_INSPECT_SIZE_LIMIT_BYTES`)로 재파싱 생략.
- `GET /stream/<path>` → `webshare_app/routes/media_routes/streaming.py::stream_media` — Range 파싱(접미사·개방 범위, 첫 spec만 206) + 1 MB 청크 제너레이터(파일 전체 메모리 적재 없음) + 416(`Content-Range: bytes */N`).

### 전송 평면 (처리량/메모리 상한)

- HLS 트랜스코딩 → `webshare_app/features/transcoder.py::get_transcoder` — 동시 세션 상한 `MAX_CONCURRENT_TRANSCODES=4`(idle 300초 제외), 초과 시 `TranscodeBusyError` → 호출자가 HTTP 503. 동일 파일 재요청은 기존 세션 반환(상한과 무관).
- ZIP 생성 → `webshare_app/utils/zip_utils.py::create_temp_zip_from_items/_guarded_zip_write` — 항목 5,000개·합산 10 GB 상한, 초과 시 `ZipLimitExceeded` → 호출자가 413. 실패 시 temp 파일 삭제.
- Go 대응: `go-core/internal/files/download.go::ParseRanges/parseOneRange`(접미사·불만족·멀티 지원, 416 + `Content-Range`), `go-core/internal/files/zip.go`, `go-core/internal/share/share.go::ReserveDownload`(uncapped 재기록 생략을 Python과 동일하게 미러).

### 백그라운드/영속화 평면

- 공유 다운로드 예약 → `webshare_app/services/share_service.py::_reserve_share_download/_rollback_reserved_download` — capped 링크는 예약·롤백마다 `save_share_links()` 전체 재기록(크래시 안전), uncapped 링크는 재기록 생략(핫패스).
- 중복 스캔 → `webshare_app/features/duplicates.py::scan_duplicates/calculate_file_hash` — 크기 그룹 선필터(단독 크기는 해시 생략) + SHA-256 256 KiB 청크(기본값 `__defaults__ == (262144,)`).

### 데이터 저장 방식 (성능 관련)

DB 없음. 영속화는 dotfile JSON 원자적 교체(`persist_json_snapshot`). 공유 링크 전체 재기록 1회는 링크 수에 비례하는 JSON 직렬화 비용이므로, uncapped 다운로드 같은 고빈도 경로에서 생략한 것이 본 수정의 핵심이다.

## 3. Audit Coverage & Limitations

### 실제 확인한 주요 모듈

- 핫패스: `webshare_app/utils/listing.py`(캐시 2계층·페이지네이션), `webshare_app/utils/file_utils.py`(폴더 크기 캐시·무효화 훅·제외 디렉터리), `webshare_app/app/factory.py`(JSON 정규화 게이트), `webshare_app/utils/api_errors.py`(정규화 스키마).
- 전송: `webshare_app/features/transcoder.py`(상한·세션), `webshare_app/routes/media_routes/streaming.py`(Range·HLS), `webshare_app/utils/zip_utils.py`(상한·temp 정리), Go `go-core/internal/files/download.go`(Range parity), `go-core/internal/share/share.go`(예약 미러).
- 백그라운드: `webshare_app/services/share_service.py`(예약/롤백), `webshare_app/features/share_links_store.py`(원자적 저장), `webshare_app/features/duplicates.py`(스캔·해시).
- 벤치 스크립트: `scripts/perf_bench.py`(라이브 서버용 — 실행하지 않음).

### CodeGraph로 분석한 호출 관계

`codegraph_explore`로 확인한 관계: `list_directory_page → {_cache_get/_base_cache_get/_paginate_base_items}`, `invalidate_folder_size_cache_hook → invalidate_folder_size_cache`(file/trash/upload 블루프린트 등록), `_global_after_request → _should_inspect_json_response → normalize_error_response_payload`, `stream_hls_playlist/segment → get_transcoder → Transcoder.start`, `ZipLimitExceeded → download_handlers/share_routes(413 매핑)`, `_reserve_share_download ↔ _rollback_reserved_download ↔ save_share_links`, `scan_duplicates → calculate_file_hash`, Go `ParseRanges → parseOneRange`, Go `Access/ReserveDownload ↔ SaveLinks`.

### 실행한 테스트

- `python -m pytest tests/test_perf_hotpaths.py tests/test_perf_transfer.py tests/test_perf_background_persistence.py -q` → **23 passed in 2.51s** (본 감사에서 직접 실행).
  - hotpaths 9건: 이웃 페이지 단일 스캔 재사용, 쿼리 베이스 캐시 적중, 베이스 재생 동등성, 웜 2페이지 2초 바운드, 폴더 크기 훅 무효화/유지, 블루프린트 훅 등록, 대용량 listing 재파싱 생략, 소형 에러 본문 정규화.
  - transfer 10건: 트랜스코더 상한 거부·idle 제외·기존 세션 반환, ZIP 항목/바이트 상한, 소형 ZIP 정상, stream 접미사/개방/416/멀티-첫-spec.
  - background 4건: uncapped 재기록 생략, capped 예약마다 영속화, 해시 청크 다이제스트 안정성·기본값, 스캔 그룹핑.
- 세 구현 리포트(perf-hotpaths, perf-transfer, perf-background) 자체는 본 실행에 전달되지 않아 그 안의 측정 수치·주장을 검증하지 못했다. 위 23건은 동일 영역의 커밋된 테스트로서 직접 실행한 것이다.

### 실행하지 않은 테스트

- 전체 스위트(`pytest -q` 전체, `go test ./...`)는 실행하지 않았다. 위 23건 외의 통과는 주장하지 않는다.
- `scripts/perf_bench.py`(라이브 서버 벤치), 실제 부하·동시성 측정, 장애 주입(킬·중단·디스크 가득 참)은 수행하지 않았다.

### 확인하지 못한 환경/외부 서비스

실서버 기동(E2E), Windows/macOS 실기, ffmpeg 실트랜스코딩(상한 로직은 모킹 수준에서만 확인), 대용량(수만 파일·수십 GB) 실측, 리버스 프록시, PyInstaller 번들, Go 바이너리 실기동 상태의 성능 parity를 확인하지 않았다.

### 분석상의 한계

- `muse.search`가 슬래시 포함 경로 지정에서 결과를 반환하지 않아 백슬래시 경로로 재조회했다. 청크 업로드 병합 경로(`chunk_transfer.py` 일대)의 스트리밍/원자성 비용은 본 감사에서 직접 열람하지 못했으므로 열린 항목으로 남긴다(`PROJECT_AUDIT`의 temp+`os.replace` 서술에 의존하지 않음).
- 동시성·크래시 중간 상태는 정적 판독 + 커밋된 테스트 범위로 판단했다.
- 시간 바운드는 hotpaths의 웜 2페이지 2.0초 1건뿐이며, 나머지는 호출 횟수 기반 결정적 바운드다. p95/처리량 SLO는 정의되어 있지 않다.

## 4. High-Cost Issues

해결 완료 항목(PERF-001~004, 006-부분, 008)은 "수정됨 + 테스트 통과" 증거 기록으로 기재한다. 잔존 항목은 PERF-005~007이다.

### [PERF-001] 목록 이웃 페이지·검색 쿼리마다 전수 재스캔 — 수정됨

- **위치:** `webshare_app/utils/listing.py` — `_list_cache`(512항목) / `_list_base_cache`(32항목), TTL 2초(`_LIST_CACHE_TTL_SECONDS`), `list_directory_page`의 베이스 캐시 적중 분기(243–265행대), 쿼리 미포함 시에만 베이스 저장(324–325행대).
- **우선순위:** High였음 → 해소.
- **신뢰도:** Confirmed (코드 + 테스트).
- **문제(수정 전):** 페이지 이동·정렬 변경·검색어 입력마다 `os.scandir` 전수 재스캔 + `stat` + 정렬을 반복. 수천 항목 디렉터리에서 페이지네이션 UX가 스캔 바운드가 됨.
- **수정 내용:** 베이스(정렬된 전수 항목)를 캐시하고 페이지·쿼리는 메모리에서 파생. 쿼리 요청은 재스캔 없이 베이스에서 필터.
- **근거:** 두 번째 페이지 요청 시 `os.scandir` 호출 1회 유지, 쿼리 요청 추가 스캔 0회, 베이스 재생 페이로드가 fresh 스캔과 동등(`replay == fresh`), 내부키(`name_lower`) 노출 없음.
- **영향:** 2,000항목 기준 두 번째 페이지가 재스캔 없이 응답. 정렬/검색이 디스크가 아닌 메모리 비용으로 축소.
- **회귀 테스트(존재·통과):** `test_second_page_reuses_single_scan`, `test_query_served_from_base_without_rescan`, `test_base_hit_matches_fresh_scan_shape`, `test_warm_second_page_time_bound`(2.0초).
- **남은 주의:** TTL 2초·베이스 32항목이므로 다수 디렉터리高速 순환 시 축출 재스캔 발생. 측정된 바 없으므로 튜닝 단언은 하지 않는다(PERF-007 계열의 열린 항목).

### [PERF-002] 대시보드/요약마다 폴더 전수 `os.walk` — 수정됨

- **위치:** `webshare_app/utils/file_utils.py` — `get_folder_size`(169–202행, TTL 60초, 최대 100 키), `invalidate_folder_size_cache_hook`(221–234행: 변이 메서드 + 400 미만에서만 전체 무효화), `SIZE_EXCLUDED_DIRS = {".upload_temp", ".webshare_transcode"}`(166행).
- **우선순위:** High였음 → 해소.
- **신뢰도:** Confirmed (코드 + 테스트).
- **문제(수정 전):** 요약·대시보드 조회마다 공유 트리 전수 `os.walk` + 파일당 `getsize`. 요청 빈도와 트리 크기의 곱으로 비용 증가.
- **수정 내용:** 60초 TTL 캐시 + file/trash/upload 블루프린트의 성공 변이에만 전체 무효화. 읽기·실패는 캐시 유지. 부분 업로드·트랜스코드 스테이징은 집계에서 제외(`PROJECT_AUDIT` 섹션 5의Confirmed Gap 해소에 해당).
- **근거:** 변이 성공 후 크기가 +4 바이트로 갱신됨, GET·실패 응답 후에는 stale 유지, 3개 블루프린트에 훅 등록 확인.
- **영향:** 읽기 폭증 시 디스크 워크가 60초당 최대 1회로 상한. 변이 직후에도 최대 60초 이내 stale이 아니라 즉시 무효화되므로 정확성 회귀 없음.
- **회귀 테스트(존재·통과):** `test_folder_size_hook_invalidates_on_successful_mutation`, `test_folder_size_hook_keeps_cache_on_read_or_failure`, `test_mutation_blueprints_register_invalidation_hook`.
- **남은 주의:** 프로세스-로컬 캐시이므로 Go 백엔드와 Flask 폴백이 각자 계산한다. 이중 계산 자체는 요청당 1회 이하이나 Go 측 제외 규칙·TTL 동등성은 미확인(PERF-007).

### [PERF-003] after-request 에러 정규화의 대용량 본문 재파싱 — 수정됨

- **위치:** `webshare_app/app/factory.py` — `_should_inspect_json_response`(27–39행: 400+ 항상 검사, 성공 본문은 `_JSON_ERROR_INSPECT_SIZE_LIMIT_BYTES` 미만만 검사), `_global_after_request`(190–198행: 조건부 `get_json`).
- **우선순위:** Medium이었음 → 해소.
- **신뢰도:** Confirmed (코드 + 테스트).
- **문제(수정 전):** 모든 JSON 응답에 `get_json` 재파싱이 걸리면 1,000항목 listing 페이지당 ~1ms 수준의 고정 오버헤드가 매 응답에 부가(코드 주석의 추정치, 실측 아님).
- **수정 내용:** 대용량 성공 본문은 파싱 생략(정규화가 no-op이므로), 에러·소형 본문은 기존대로 정규화.
- **근거:** 300항목·8 KB 초과 listing 응답에서 `get_json` 호출 0회 + 페이로드 정상, `/search?q=a` 소형 에러 본문은 여전히 `success:false`/`code`/`request_id`로 정규화됨.
- **영향:** 대용량 listing의 per-request 고정 오버헤드 제거. 에러 스키마 계약은 유지.
- **회귀 테스트(존재·통과):** `test_large_success_listing_skips_json_reparse`, `test_small_error_shaped_body_still_normalized`.
- **남은 주의:** "1ms/1000항목"은 주석 추정치이며 본 감사에서 실측하지 않았다. 임계값 상수 자체의 적절성은 열린 항목.

### [PERF-004] 무제한 ffmpeg 생성·무제한 ZIP·중단 Range — 수정됨

- **위치:**
  - 트랜스코더 상한: `webshare_app/features/transcoder.py` — `MAX_CONCURRENT_TRANSCODES=4`(23행), idle 300초 제외(182행), `TranscodeBusyError`(183–184행). 503 매핑: `webshare_app/routes/media_routes/streaming.py` 176–179행.
  - ZIP 상한: `webshare_app/utils/zip_utils.py` — `MAX_ZIP_ITEMS=5000`·`MAX_ZIP_TOTAL_BYTES=10 GiB`(21–22행), `_guarded_zip_write`(63–75행), 실패 시 temp 삭제(100–103·133–136행).
  - Range: `streaming.py::stream_media`(44–102행) — 접미사/개방 범위, 불만족 시 416 + `Content-Range: bytes */N`(66–68행), 1 MB 청크 제너레이터(80–91행), 멀티레인지는 첫 spec 단일 206(49–51행, 주석으로 Go와의 divergences 명시).
- **우선순위:** High였음 → 해소.
- **신뢰도:** Confirmed (코드 + 테스트).
- **문제(수정 전):** 썸네일/트랜스코드 폭증 시 ffmpeg 무제한 생성으로 CPU 고갈, 초대형 ZIP 시 temp 디스크 고갈, 비정상 Range의 비표준 응답.
- **근거:** 상한 초과 시 세션 2개 유지 + `TranscodeBusyError`, idle 세션은 상한에서 제외되고 기존 세션은 상한 초과에도 반환, 항목/바이트 초과 시 `ZipLimitExceeded` + temp 잔류 없음, 접미사(-10)·개방(500-)·416·멀티-첫-spec 응답 검증.
- **영향:** CPU·디스크 고갈형 요청이 503/413으로 빠르게 거부. 스트리밍은 파일 전체 적재 없이 1 MB 단위 전송.
- **회귀 테스트(존재·통과):** transfer 10건 전부.
- **남은 주의(코드상 확인된 divergence):** 멀티레인지에서 Python은 첫 spec 단일 206, Go(`go-core/internal/files/download.go::serveMultipartRanges`)는 multipart 206으로 응답한다. 양쪽 모두 스펙 내 동작이며 성능 영향은 무시 가능하나, parity 계약 테스트가 멀티레인지를 단언한다면 백엔드별 기대값을 분리해야 한다.

### [PERF-005] HLS 플레이리스트 대기 루프가 워커 스레드 블로킹 — 잔존

- **위치:** `webshare_app/routes/media_routes/streaming.py::stream_hls_playlist` 158–173행 — 플레이리스트 파일 생성까지 `time.sleep(0.5)` × 최대 20회 폴링.
- **우선순위:** Medium.
- **신뢰도:** Confirmed (블로킹 동작은 코드로 확정, 체감 영향은 Likely).
- **문제:** HLS 재생 시작마다 Flask 워커 스레드 1개가 최대 10초간 sleep 폴링에 묶인다. 동시 재생 N개가 겹치면 워커 풀의 상당 부분이 대기에 소모되어 다른 요청(list/다운로드)의 꼬리 지연이 커진다. ffmpeg 기동 자체는 백그라운드 프로세스라 문제가 아니라 대기 방식이 문제다.
- **발생 조건:** HLS 재생 시작이 겹칠 때. 단일 재생·소규모 사용에서는 무증상.
- **영향:** 처리량(throughput) 저하 + 꼬리 지연. 오류·손상은 없음(20회 초과 시 503 타임아웃으로 정상 종료).
- **근거:** 루프 상수(20 × 0.5s)가 코드에 명시. 대기 중 락은 없으나 스레드 점유 자체가 비용.
- **권장 수정 방향:** 폴링을 조건 대기(플레이리스트 생성 이벤트/`threading.Event`) 또는 비동기 재시도(202 + 클라이언트 재요청) переключ. 최소 조치로 폴링 간격 지수 백오프 +試行 횟수 축소가 가능하나 스레드 점유 구조는 그대로이므로 권장하지 않는다.
- **필요한 회귀 테스트:** HLS 시작 요청이 플레이리스트 생성 전에 워커를 1초 이상 점유하지 않음을 단언(모킹: `get_transcoder` 지연 + 스레드 점유 시간 측정). 타임아웃 시 503 + 세션 누수 없음(`TRANSCODE_SESSIONS` 크기 불변) 단언.

### [PERF-006] 중복 스캔 전수 워크·해시 재계산 — 부분 해소, 잔존

- **위치:** `webshare_app/features/duplicates.py` — `calculate_file_hash` 기본 청크 256 KiB(89–98행), 크기 그룹 선필터(단독 크기 해시 생략, 198–205행대), 매회 `os.walk` 전수 수집(169행대).
- **우선순위:** Medium.
- **신뢰도:** Likely (비용 구조는 코드로 확정, 대용량 실측은 없음).
- **문제(수정 전):** 8 KiB 청크의 과다 `read()` 호출. 수정 후 다이제스트 동일 + 호출 횟수 32분의 1로 감소.
- **수정 내용(완료):** 256 KiB 기본 청크 + 다이제스트 안정성 테스트(`__defaults__ == (262144,)`, 1 MiB 벡터 일치).
- **잔존 비용:** 스캔마다 트리 전체 `os.walk` + 후보 전체 재해시. 증분 인덱스(mtime/size 캐시, 영속 해시 DB)가 없어 대용량 공유 폴더에서는 수 분 블로킹 + 매 스캔 반복. 취소는 지원되나(`cancelled` 플래그) 빠르다는 보장은 아니다.
- **영향:** 백그라운드 작업 1회의 지연 + I/O 폭증. 요청 핫패스와 스레드/프로세스를 공유한다면(list/다운로드 지연) 파급 가능. 단독 실행 시에는 느리다는 것 외에 무해.
- **권장 수정 방향:** (a) mtime+size 지문 영속 캐시로 변경분만 재해시, (b) 스캔 청크/예산 상한(회당 N 파일·M 바이트 후 양보), (c) 저우선순위 I/O(가능 시). (a)가 효과 최대.
- **필요한 회귀 테스트:** 2회 연속 스캔 시 변경 없는 파일의 `calculate_file_hash` 호출 0회 단언(도입 후). 스캔 중 취소 시 1초 이내 반환 단언.

### [PERF-007] Go 백엔드 성능 동등성 — 미확인

- **위치:** Go `go-core/internal/files/*`(listing 캐시 여부), Go ZIP 상한, Go 폴더 크기 집계, Go 공유 `ReserveDownload`는 Python 미러 확인됨(`share.go` 191행대 주석 + 본문).
- **우선순위:** Medium.
- **신뢰도:** Speculative (미확인 — 이슈가 아니라 열린 항목으로 기록).
- **문제:** 기본 백엔드가 Go이므로 Python 측 최적화(listing 캐시·폴더 크기 제외 규칙·ZIP 상한)가 Go에서도 동등한지 확인되지 않으면, 실배포(Go) 성능은 본 감사와 다를 수 있다. 확인된 Go parity는 Range 파싱(접미사·416·멀티, `download.go` 195–272행), 에러 정규화(`pkg/api/errors.go::Normalize`), 공유 예약의 uncapped 생략 미러뿐이다.
- **권장 수정 방향:** Go 측에 동일 가드 존재 여부 코드 확인 + parity 계약 테스트에 성능 가드 추가(상한 초과 시 동일 상태코드, 대용량 listing의 스캔 횟수 동등).
- **필요한 회귀 테스트:** `use_https`가 아니라 backend ∈ {go, python} × {대용량 listing, ZIP 상한 초과, uncapped 공유 폭증} 조합의 상태코드·스캔횟수 동등 단언.

### [PERF-008] Uncapped 공유 카운터의 크래시 손실 — 설계상 허용, 기록

- **위치:** `webshare_app/services/share_service.py` 187–192·209–210행.
- **우선순위:** Low.
- **신뢰도:** Confirmed (의도된 트레이드오프, 주석 명시).
- **문제:** 없음(기록용). Uncapped 링크의 `download_count`는 메모리 전용이라 크래시 시 손실. 정보성 카운터이며 정책 강제와 무관하므로 허용. Capped 링크는 예약·롤백마다 영속화되어 크래시해도 `max_downloads`를 초과 부여하지 않음(테스트로 확정).
- **회귀 테스트(존재·통과):** `test_uncapped_share_download_skips_full_rewrite`, `test_capped_share_download_persists_every_reservation`.

## 7. Recommended Fix Plan

### Phase 1 — 잔존 핫패스 (다음 릴리스)

1. PERF-005: HLS 대기 루프를 이벤트 기반 대기로 전환(또는 202 재시도). 워커 점유 상한 테스트를 함께 추가.
2. PERF-004 후속: `Retry-After` 헤더를 503(트랜스코더 상한)·429(쿼터)에 부착. 클라이언트(HLS 플레이어 포함)가 폭증 시 스스로 백오프하도록. 동작 변경이므로 parity 테스트에 상태코드+헤더 동등 추가.
3. 청크 업로드 병합 경로 직접 점검(본 감사 미열람): 병합이 스트리밍 복사 + `os.replace`인지, 청크당 `fsync`/재검증 비용이 있는지 확인 후 기록.

### Phase 2 — 백그라운드 비용

4. PERF-006: 중복 스캔 증분화(mtime+size 지문 캐시) + 회당 예산 상한. 취소 응답성 테스트 포함.
5. 트랜스코더 세션 idle 임계(`TRANSCODE_CAP_IDLE_SECONDS=300` vs 정리 300초)의 일관성은 양호하나, 상한 4의 근거(코어 수 대비)를 문서화. 저사양 기기용 설정 노출 검토.
6. ZIP 10 GB/5,000항목 상한의 설정 노출 여부 결정(현재 상수). 변경 시 413 계약 테스트 유지.

### Phase 3 — 구조적

7. PERF-007: Go↔Python 성능 parity 매트릭스 작성(listing 스캔 횟수·ZIP 상한·폴더 크기·공유 영속화 빈도) 후 CI 게이트 승격.
8. 처리량 SLO 정의: 대표 트리(예: 2,000·20,000 항목)에서의 p95 listing, 동시 HLS N개, ZIP M GB의 예산을 정하고 `perf_bench.py`를 게이트화(현재는 수동 스크립트).
9. 멀티레인지 divergence 문서화(Python 첫-spec 206 vs Go multipart 206)를 parity 계약에 명시.

실제 코드는 수정하지 않았다.

## 8. Test Recommendations

- **Perf 단위 — listing 스캔 횟수:** 2,000항목 synthetic 트리에서 페이지 순회(1→2→쿼리)의 `os.scandir` 호출이 1회임을 단언. **존재·통과** (`test_second_page_reuses_single_scan` 등). 기대: 호출 1회, 총항목·페이지 경계·정렬 유지.
- **Perf 단위 — 폴더 크기 훅:** 성공 변이 후 무효화, 읽기·실패 후 유지, 3개 블루프린트 등록. **존재·통과**. 기대: 변이 후 즉시 갱신, 그 외 stale 유지.
- **Perf 단위 — JSON 재파싱 게이트:** 8 KB 초과 성공 본문 `get_json` 0회, 소형 에러 본문 정규화 유지. **존재·통과**. 기대: 대용량 no-op, 에러 스키마 계약 유지.
- **Perf 단위 — 트랜스코더 상한:** 초과 거부 + 세션 수 불변, idle 제외, 기존 세션 반환. **존재·통과**. 기대: 503 매핑(라우트 수준은 모킹 외 실호출 미검증 — 열린 항목).
- **Perf 단위 — ZIP 상한:** 항목·바이트 초과 `ZipLimitExceeded` + temp 잔류 없음, 소형 정상. **존재·통과**. 기대: 413 매핑은 호출자 테스트에 위임(기존 `test_audit_remediations`·`test_security_hardening_724` 경유로 추정, 본 감사 미실행).
- **Perf 통합 — stream Range:** 접미사·개방·416+`Content-Range`·멀티-첫-spec. **존재·통과**. 기대: 206/416 상태 + 바이트 정확성.
- **Perf 통합 — 공유 영속화 빈도:** uncapped 5회 예약에 저장 0회, capped 2회 예약에 저장 2회 + 초과 거부 시 추가 저장 없음. **존재·통과**. 기대: 핫패스 무저장 + 크래시 안전.
- **Perf 단위 — 해시 청크:** 1 MiB 벡터 다이제스트 일치 + 기본값 256 KiB. **존재·통과**. 기대: 8 KiB 대비 `read()` 32분의 1(호출 횟수 실측은 미수행).
- **신규 — HLS 워커 점유:** 플레이리스트 지연 상황에서 HLS 시작 요청의 워커 점유 < 1초 단언. **없음**. 기대: 이벤트 대기 도입 후 통과.
- **신규 — 스캔 증분:** 2회 연속 스캔의 재해시 0회 단언. **없음**. 기대: 지문 캐시 도입 후 통과.
- **신규 — Go parity 성능:** backend × {listing 스캔, ZIP 상한, 공유 저장 빈도} 동등 단언. **없음**. 기대: Go 측 구현 확인 후 작성.
- **신규 — 503/429 `Retry-After`:** 상한 거부 응답에 헤더 존재 단언. **없음**. 기대: Phase 1-2 도입 후 통과.
- **부하 — 대표 트리 p95:** 2,000·20,000항목 실측 + 동시 HLS + 대용량 ZIP의 예산 테스트. **없음**(`perf_bench.py`는 수동·미실행). 기대: SLO 정의 후 게이트화.

## 9. Final Assessment

- **Request Hot Paths:** Good — listing 2계층 캐시·폴더 크기 TTL+훅·JSON 재파싱 게이트가 코드와 테스트로 확정. 23건 중 9건이 이 영역.
- **Transfer Throughput/Memory:** Acceptable — ffmpeg·ZIP 상한과 Range 강건성은 확정이나, HLS 대기 루프의 워커 블로킹(PERF-005)이 잔존. 멀티레인지의 백엔드 divergence는 문서화된 수준에서 허용.
- **Background/Persistence:** Good — uncapped 무저장/capped 매회 영속의 분리, 256 KiB 해시, 크기 선필터가 확정. 크래시 안전과 핫패스 비용의トレード오프가 명시적.
- **Cross-backend Perf Parity:** Needs Work — Python 측 최적화의 Go 동등성이 Range·에러·공유 예약 외에는 미확인(PERF-007). 기본 백엔드가 Go이므로 실배포 성능 주장의 전제가 된다.
- **Measurement Rigor:** Acceptable — 결정적 호출-횟수 바운드가 촘촘하나, 시간·p95·대용량 실측은 웜 2페이지 2초 1건뿐. SLO·벤치 게이트는 Phase 3 과제.
- **Test Confidence:** Good — 동일 영역 23건 직접 실행·통과. 전체 스위트·Go 테스트·실부하는 미실행이므로 그 범위의 통과는 주장하지 않는다.

**먼저 다룰 문제 3개:**

1. [PERF-005] HLS 대기 루프 워커 블로킹 — 잔존 핫패스 중 유일하게 동시 사용자에게 파급.
2. [PERF-006] 중복 스캔 증분화 — 대용량 폴더의 수 분 블로킹을 구조적으로 제거.
3. [PERF-007] Go 성능 parity 확인 — 기본 백엔드 실성능의 전제 조건.

**열린 항목:**

- 세 구현 리포트(perf-hotpaths, perf-transfer, perf-background) 미전달 — 본 문서는 테스트+코드로 재구성했으며 리포트 내 수치·주장은 검증하지 못함.
- 청크 업로드 병합 I/O 비용 미열람(`chunk_transfer.py` 일대) — 스트리밍 병합·원자 교체 여부 미확인.
- `_JSON_ERROR_INSPECT_SIZE_LIMIT_BYTES` 값의 적절성, "1ms/1000항목" 추정치의 실측 부재.
- 트랜스코더 503·쿼터 429의 `Retry-After` 부재, 상한 4의 하드웨어 근거 문서 부재.
- Windows/macOS·ffmpeg 실기·대용량 실측·Go 실기동·전체 스위트 미실행.
