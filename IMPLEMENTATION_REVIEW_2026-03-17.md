# WebShare Pro 기능 구현 점검 보고서 (2026-03-17)

## 점검 범위
- 문서: `README.md`, 기존 점검 문서 `IMPLEMENTATION_REVIEW_2026-03-05.md`
- 코드: `main.py`, `routes/`, `features/`, `utils/`, `templates/index.html`
- 요청 문서: `CLAUDE.md`는 저장소에서 발견되지 않음
- 실행 검증: `pytest -q`

## 실행 결과 요약
- 초기 리뷰 시점 테스트 결과: `44 passed, 1 skipped` (2026-03-17 실행)
- 기존 회귀 테스트는 전반적으로 안정적이지만, 아래 항목들은 테스트 공백 또는 플랫폼/운영 조건에서 실제 문제로 이어질 가능성이 높음

## 주요 발견 사항

### 1) [High] Markdown 미리보기에서 Stored XSS 가능
- 근거:
  - 편집기 Markdown 미리보기에서 원문을 바로 `marked.parse()` 후 `innerHTML`에 주입: `templates/index.html:2909-2916`
  - 별도 Markdown 프리뷰에서도 파일 내용을 그대로 `marked.parse()` 후 `innerHTML`에 주입: `templates/index.html:4447-4461`
  - 서버는 `/get_content/<path>`로 원문 텍스트를 그대로 반환: `routes/media_routes.py:387-411`
- 영향:
  - 공유 폴더 안의 `.md` 파일에 `<script>`, 이벤트 핸들러, `javascript:` 링크 등이 포함되면 관리자/사용자 세션에서 스크립트가 실행될 수 있습니다.
  - 특히 게스트 업로드 허용 환경에서는 권한 상승용 Stored XSS 경로가 됩니다.
- 권장 조치:
  - `marked` 결과를 DOMPurify 같은 sanitizer로 정제한 뒤 렌더링.
  - 또는 Markdown 렌더링 시 raw HTML을 비활성화.
  - 회귀 테스트 추가: 악성 Markdown preview 시 스크립트/이벤트 핸들러가 DOM에 살아남지 않는지 검증.

### 2) [High] 파일 정보 모달이 파일명/경로를 escape 없이 `innerHTML`로 렌더링
- 근거:
  - 파일 정보 API는 파일 시스템의 `name`, `path`를 그대로 반환: `routes/file_routes.py:824-846`
  - 프런트에서 `d.name`, `d.path`를 escape 없이 템플릿 문자열에 넣고 `innerHTML`로 주입: `templates/index.html:3163-3185`
- 영향:
  - Linux/Docker 공유 폴더에서는 `<`, `>` 등이 포함된 파일명이 유효하므로, 악성 파일명을 가진 항목의 "파일 정보" 모달을 열 때 Stored XSS가 가능합니다.
  - Windows 단독 환경에서는 재현이 제한되지만, 프로젝트가 Docker 사용을 문서화하고 있어 운영 환경 기준으로는 실질 리스크입니다.
- 권장 조치:
  - `showFileInfo()`에서 `d.name`, `d.path`, `d.mime_type`를 `escapeHtml()` 처리.
  - 가능하면 문자열 결합 대신 DOM API(`textContent`)로 렌더링.
  - Linux 스타일 악성 파일명에 대한 UI 보안 테스트 추가.

### 3) [High] `python main.py`가 비Windows 환경에서 시작 단계에서 바로 실패할 수 있음
- 근거:
  - `main.py`는 예외가 나면 다시 `ctypes.windll.user32.SetProcessDPIAware()`를 호출: `main.py:15-21`
  - README 기본 실행 방법은 그대로 `python main.py`: `README.md:110-113`
- 영향:
  - Linux/macOS에서는 첫 번째 `ctypes.windll...` 접근이 실패한 뒤, `except` 블록에서 다시 `ctypes.windll`에 접근해 초기화 전에 크래시할 가능성이 큽니다.
  - Docker 엔트리포인트는 별도 경로를 쓰더라도, 문서대로 수동 실행하는 사용자에게는 즉시 실패로 보입니다.
- 권장 조치:
  - DPI 설정을 `sys.platform == "win32"` 조건으로 감싸고, fallback도 Windows에서만 실행.
  - 최소 회귀 테스트 또는 smoke test로 "비Windows에서 import/main 진입 시 예외가 없어야 함"을 보강.

### 4) [High] Linux/Docker에서 HLS 트랜스코더 종료가 서버 프로세스 그룹까지 건드릴 수 있음
- 근거:
  - 비Windows에서는 별도 프로세스 그룹/세션 생성 없이 `ffmpeg` 실행: `features/transcoder.py:58-73`
  - 종료 시에는 `os.killpg(os.getpgid(self.process.pid), ...)`로 프로세스 그룹 단위 종료: `features/transcoder.py:97-115`
- 영향:
  - Linux 계열에서 `ffmpeg`가 서버와 같은 프로세스 그룹에 속해 있으면, HLS 정리/타임아웃/종료 시 서버 본체까지 함께 종료될 위험이 있습니다.
  - 특히 Docker/리눅스 배포에서 스트리밍 사용 중 서버가 예고 없이 내려가는 장애로 보일 수 있습니다.
- 권장 조치:
  - 비Windows `Popen`에 `start_new_session=True` 또는 등가의 분리 옵션을 적용해 `ffmpeg`를 독립 세션으로 실행.
  - Linux 컨테이너 기준 start/stop/cleanup 후 서버 프로세스 생존 여부를 검증하는 회귀 테스트 추가.

### 5) [Medium] 다운로드 제한 카운트가 Range/HLS 세그먼트마다 1건씩 증가
- 근거:
  - `track_download()`는 호출될 때마다 `count += 1`: `utils/helpers.py:197-208`
  - 일반 스트리밍의 Range 응답마다 `track_download()` 호출: `routes/media_routes.py:61-79`
  - HLS 세그먼트 응답마다 `track_download()` 호출: `routes/media_routes.py:500-537`
  - 일반 단일 다운로드도 같은 카운터를 사용: `routes/file_routes.py:109-120`
- 영향:
  - `daily_download_limit`가 설정된 환경에서는 동영상 스트리밍 1회가 여러 "다운로드"로 집계되어 제한을 과도하게 빨리 소진합니다.
  - HLS는 세그먼트 수만큼 카운트가 늘어나므로 사실상 스트리밍이 unusable 해질 수 있습니다.
- 권장 조치:
  - `count`는 논리적 다운로드 1회만 증가시키고, Range/HLS는 bytes만 누적하도록 분리.
  - 예: `track_download_event()`와 `track_download_bytes()`를 분리하거나, `count_once=False` 옵션 도입.
  - 회귀 테스트 추가: Range 요청/HLS 재생이 `daily_download_limit`를 비정상적으로 소진하지 않는지 검증.

### 6) [Medium] ZIP 압축 해제가 기존 동일 폴더와 충돌해도 그대로 덮어쓰거나 혼합될 수 있음
- 근거:
  - 압축 해제 대상 폴더를 무조건 `archive.zip -> archive/`로 계산: `routes/file_routes.py:615-616`
  - 기존 폴더 존재 여부나 충돌 처리 없이 `extractall()` 수행: `routes/file_routes.py:621-650`
- 영향:
  - 사용자는 "압축 해제"를 새 폴더 생성으로 기대하지만, 현재는 기존 `archive/`가 있으면 파일이 섞이거나 일부 파일이 덮어써질 수 있습니다.
  - 복구 가능한 휴지통 경로를 거치지 않기 때문에 데이터 손상 체감이 큽니다.
- 권장 조치:
  - 대상 폴더가 이미 존재하면 `archive_1/` 식으로 충돌 회피.
  - 또는 사용자 확인 없이 기존 경로에 풀지 않도록 차단.
  - 회귀 테스트 추가: 동일 basename 폴더가 이미 있을 때 기존 파일이 보존되는지 검증.

### 7) [Medium] 버전 백업 이름이 경로 충돌을 일으키고, 버전 조회는 같은 basename 이력을 섞어 보여줄 수 있음
- 근거:
  - 버전 파일명은 상대 경로의 `/`를 모두 `_`로 치환해 생성: `utils/helpers.py:50-59`
  - 버전 조회는 전체 경로가 아니라 `basename` suffix만으로 필터링: `routes/metadata_routes.py:232-254`
- 영향:
  - 예를 들어 `a/b_c.txt`와 `a_b/c.txt`는 같은 버전 파일명으로 충돌할 수 있습니다.
  - `/versions/dir1/test.txt` 조회 시 `dir2/test.txt`의 이력까지 섞여 보일 수 있어, 잘못된 버전 복원으로 이어질 수 있습니다.
- 권장 조치:
  - 버전 키를 basename이 아니라 원래 상대 경로 전체를 손실 없이 식별할 수 있는 방식으로 저장.
  - 조회/복원도 `basename` 매칭이 아니라 원본 상대 경로 기준으로 제한.
  - 충돌 케이스와 오복원 방지 회귀 테스트 추가.

### 8) [Medium] "최근 파일" 기능이 UI와 API에는 남아 있지만 실제로는 거의 비어 있는 상태
- 근거:
  - UI는 `/recent_files`를 호출해 최근 파일 모달을 표시: `templates/index.html:3384-3395`
  - API는 전역 `RECENT_FILES`를 그대로 반환: `routes/root_api_routes.py:149-155`, `routes/api_routes.py:158-164`
  - 최근 파일 적재 헬퍼는 존재: `utils/helpers.py:16-35`
  - 하지만 현재 활성 코드 경로에서는 `add_recent_file()` 호출을 찾지 못했고, 검색 결과상 보관용 `legacy/`에만 실제 사용 흔적이 남아 있습니다.
- 영향:
  - UI에 기능은 노출되지만, 실제로는 "최근 파일이 없습니다"만 반복되어 기능 신뢰도를 떨어뜨립니다.
  - 기존 버전에서 제공되던 기능이 리팩터링 과정에서 빠진 상태로 보입니다.
- 권장 조치:
  - 최소한 `download`, `stream`, `get_content`, `browse` 등 실제 접근 이벤트에서 `add_recent_file()`를 호출하도록 연결.
  - 기능을 유지할 계획이 없다면 UI/API를 제거하거나 "최근 활동"으로 대체.

## 추가 구현 권장 사항
- 보안 회귀 테스트 추가:
  - Markdown preview XSS 차단
  - 파일 정보 모달 XSS 차단
  - Linux 스타일 특수문자 파일명 렌더링 검증
- 기능 회귀 테스트 추가:
  - 최근 파일 리스트가 실제 접근 이벤트로 채워지는지
  - Range/HLS 스트리밍이 다운로드 횟수 제한을 과소/과대 집계하지 않는지
  - ZIP 압축 해제 충돌 시 기존 폴더를 덮어쓰지 않는지
  - 버전 백업 충돌 및 잘못된 버전 복원이 방지되는지
  - 휴지통/중복 삭제 후 검색 인덱스가 갱신되는지
- 운영 안정성 보강:
  - `main.py`의 플랫폼 분기 정리
  - 비Windows에서 HLS 트랜스코더를 독립 프로세스 세션으로 실행
  - 설정/권한/메타데이터/공유 링크 저장 로직은 `remove + rename` 대신 `os.replace()`로 통일
  - 설정 파일 로드 시 `set()` 검증을 우회하지 않도록 타입/경로 검증을 적용
  - 에러 메시지의 `str(e)` 직접 노출은 장기적으로 공통 API 에러 스키마로 정리하는 편이 안전

## 참고 메모
- 2026-03-05 점검 문서에서 지적된 업로드 무결성, JSON preview XSS, 메타데이터 필터링 등은 현재 트리에서 상당 부분 보강된 것으로 보입니다.
- 이번 점검은 "이미 구현된 기능이 운영 환경에서 실제로 깨질 수 있는 부분"과 "UI는 있는데 동작 연결이 빠진 부분"에 초점을 맞췄습니다.

---

## 후속 구현 반영 결과 (2026-03-17)

- 본 문서의 핵심 개선 항목은 현재 코드베이스에 반영 완료.
- 반영된 정합성 개선:
  - Markdown preview sanitize 적용
  - 파일 정보 모달 escape 렌더링 적용
  - 비Windows `main.py` DPI 초기화 분리
  - 비Windows HLS 트랜스코더 독립 세션 실행 및 세션 단위 종료
  - Range/HLS는 다운로드 횟수 quota 미소모, bytes만 누적
  - 최근 파일 기능을 실제 접근 이벤트와 연결
  - ZIP 압축 해제 충돌 시 새 sibling 디렉터리로 분리
  - 버전 백업 파일명에 encoded relative path 포함, legacy 조회/복원 호환 유지
  - config/metadata/permissions/share-links/cloud/audit 저장의 `os.replace()` 통일
  - 설정 로드 시 `set()` 기반 검증 적용
  - 휴지통 이동/복원 및 중복 삭제 후 검색 인덱스 갱신 연결
- 추가 자동 테스트 반영:
  - 스트리밍 bytes/count 분리
  - 최근 파일 적재
  - ZIP 압축 해제 충돌 회피
  - 신규/legacy 버전 백업 조회 및 복원 보호
  - 휴지통/중복 삭제 후 인덱스 갱신
  - config load/save 검증
  - 비Windows DPI/트랜스코더 세션 동작
- 최신 검증 결과:
  - `pytest -q` -> `54 passed, 1 skipped`
