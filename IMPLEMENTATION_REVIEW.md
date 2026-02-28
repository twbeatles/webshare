# WebShare Pro 기능 구현 점검 보고서 (2026-02-28)

## 반영 상태 업데이트 (2026-02-28)
- 본 문서의 핵심 개선 계획 항목을 코드에 반영 완료했습니다.
- 완료 항목:
  - `validate_path` 심볼릭 링크 우회 방지 하드닝
  - 청크 업로드 소유권 검증/총량 제한/동시 세션 제한
  - 공유 링크 `max_downloads` 원자적 reserve/rollback 처리
  - WebDAV 마운트 순서 정정 및 Docker 실행 경로 동일화
  - 시작 시 임시 업로드 디렉터리 정리 복구(`.webshare_uploads`, `.upload_temp`)
  - Cloud Sync API Mock 모드 명시(`202 Accepted`, `mode/job_id/state/progress/error`)
  - GUI/문서 버전 표기 `APP_VERSION(7.2.1)` 기준 동기화
  - 회귀 테스트 보강 및 optional dependency 테스트 skip-safe 보강
- 검증 결과: `pytest -q` 통과 (`29 passed, 3 skipped`)

## 점검 범위
- 코드: `routes/`, `features/`, `security/`, `utils/`, `server.py`, `main.py`, `docker_entrypoint.py`
- 문서: `README.md`, `README_EN.md`
- 요청 문서: `claude.md` (저장소 내 파일 미발견)
- 실행 검증: `pytest -q`

## 실행 결과 요약
- 테스트: `29`개 통과, `3`개 skip
- 실패 테스트: 없음

## 참고
- 아래 "핵심 리스크" 섹션은 수정 전 점검에서 식별된 항목이며, 상단 "반영 상태 업데이트"에 실제 조치 결과를 반영했습니다.

## 핵심 리스크 (우선순위순)

### 1) [High] 경로 검증의 심볼릭 링크 우회 가능성
- 근거:
  - `utils/file_utils.py:137` (`os.path.exists(full_path)`일 때만 `realpath` 적용)
  - `utils/file_utils.py:145` (prefix 비교를 비실경로 기준으로 수행 가능)
- 영향:
  - 존재하지 않는 대상 파일/폴더에 대한 쓰기 요청 시, 상위 경로가 심볼릭 링크라면 `base_dir` 바깥으로 이탈할 여지가 있습니다.
  - 업로드/폴더생성/복사/이동 등 “신규 경로 생성” 계열 엔드포인트에 연쇄 영향 가능.
- 권장 조치:
  - `Path.resolve(strict=False)` 또는 “가장 가까운 기존 부모 경로” 기준 실경로 검증으로 변경.
  - `os.path.commonpath([base_dir_real, resolved_target]) == base_dir_real` 검증으로 통일.
  - 회귀 테스트 추가: symlink parent + upload/mkdir/copy/move 케이스.

### 2) [High] 청크 업로드 총량 제한 미적용 + 세션 소유권 미검증
- 근거:
  - 총량 제한 미적용:
    - `routes/upload_routes.py:63` (`total_size >= 0`만 확인)
    - `config.py:42` (`MAX_CHUNK_UPLOAD_SIZE` 정의만 있고 실제 미사용)
  - 세션 소유권 미검증:
    - `routes/upload_routes.py:103-113` (업로드 세션에 소유자 정보 없음)
    - `routes/upload_routes.py:134-137`, `182-185` (세션 ID 존재 여부만 검사)
- 영향:
  - 대용량/장시간 업로드 세션으로 디스크 고갈 위험.
  - 세션 ID 노출 시 다른 로그인 사용자가 세션을 이어받아 조작할 여지.
- 권장 조치:
  - `total_size <= MAX_CHUNK_UPLOAD_SIZE` 강제.
  - 세션 생성 시 `owner_session_id`, `owner_role`, `owner_ip` 저장 후 chunk/complete/cancel에서 검증.
  - 동시 업로드 수/총량 제한(사용자/IP 단위) 추가.

### 3) [High] WebDAV 마운트 순서 문제로 엔드포인트 비활성화 가능성
- 근거:
  - `server.py:296-302`에서 `make_server(..., self.app)` 먼저 생성
  - `server.py:314-316`에서 이후에 `self.app = DispatcherMiddleware(...)`로 교체
- 영향:
  - 서버가 이미 초기 `self.app`을 바인딩한 뒤라 `/webdav`가 실제로 노출되지 않을 가능성이 큼.
- 문서 대비:
  - `README_EN.md:73`, `README_EN.md:289`에서 `/webdav` 기능을 명시.
- 권장 조치:
  - Flask app 생성 -> WebDAV wrap -> 최종 WSGI app을 `make_server`에 전달하는 순서로 재구성.
  - `/webdav/` 스모크 테스트(옵션 의존성 설치 시) 추가.

### 4) [Medium] Docker 경로에서 WebDAV 미마운트
- 근거:
  - `docker_entrypoint.py:50-52`는 `create_app()`을 직접 `app.run()`으로 실행.
  - `DispatcherMiddleware` 결합 로직이 Docker 진입 경로에는 없음.
- 영향:
  - Docker 사용 시 README에 명시된 `/webdav`가 동작하지 않을 가능성.
- 권장 조치:
  - Docker 엔트리포인트에서도 동일한 WSGI 조합(Flask + WebDAV) 적용.

### 5) [Medium] 공유 링크 최대 다운로드 수(max_downloads) 경쟁 조건
- 근거:
  - 제한 확인: `routes/share_routes.py:223-225`
  - 증가 처리: `routes/share_routes.py:293-305`
  - 두 구간이 분리되어 있어 동시 요청 시 초과 허용 가능.
- 영향:
  - `max_downloads=1` 같은 일회성 링크가 동시 다운로드에서 여러 건 허용될 수 있음.
- 권장 조치:
  - 잠금 내 원자적 예약/증가 처리 후 전송.
  - 실패 시 롤백 정책 정의.

### 6) [Medium] 시작 시 임시 업로드 정리 경로 불일치 + 호출 누락
- 근거:
  - `main.py:36` 정리 대상: `.webshare_uploads`
  - 실제 청크 임시 경로: `routes/upload_routes.py:99`의 `.upload_temp`
  - `main.py:51`에서 `cleanup_temp_files()`가 주석 라인에 포함되어 실행되지 않음
- 영향:
  - 비정상 종료 후 임시 파일 누적으로 디스크 압박 가능.
- 권장 조치:
  - 시작 시 정리 함수 확실히 호출.
  - 정리 대상 경로를 `.upload_temp` 및 orphan session 디렉터리로 통일.

## 기능 완성도 관점의 추가 필요 사항

### 7) [Medium] Cloud Sync API는 실동기화가 아닌 플레이스홀더 상태
- 근거:
  - `routes/cloud_routes.py:69-96`에서 실제 동기화 수행 없이 `success`/`note`만 반환.
- 문서 대비:
  - `README_EN.md:68`에 클라우드 동기화 준비 기능 언급.
- 권장 조치:
  - UI/문서에 “Mock/Beta” 명시 또는 실제 provider worker 구현.
  - `job_id`, 진행률, 실패 사유를 반환하는 비동기 작업 API로 확장.

### 8) [Low] 버전 표기 불일치 (운영/캐시 추적 혼선)
- 근거:
  - 코드 버전: `config.py:13-14`, `gui/pyqt_gui.py:404`
  - 문서 버전: `README_EN.md:9`, `README.md:9`, `README.md:139`
- 영향:
  - 릴리스/장애 대응 시 버전 식별 혼선.
  - PWA 캐시 키(`APP_VERSION` 기반)와 문서 버전 간 인지 불일치.
- 권장 조치:
  - 단일 버전 소스(예: `config.py`) 기준으로 README/배지/빌드 산출물 명 자동화.

## 테스트 보강 제안
- WebDAV 실가동 통합 테스트(옵션 의존성 설치 조건).
- symlink 우회 방지 테스트(비존재 타깃 포함).
- share link 동시성 테스트(`max_downloads` 경합).
- chunk upload 소유권 검증 테스트(다중 세션/다중 사용자).
- 의존성 스모크 체크(`cryptography`, `WsgiDAV`, `ffmpeg`)를 CI preflight에 추가.

## 총평
- 현재 구조는 모듈화/권한체크/감사로그 등 기본 토대가 잘 되어 있습니다.
- 다만 “보안 경계(path 검증)”, “동시성(share/download)”, “기능 표방 대비 실제 동작(WebDAV/Cloud)”에서 우선 보완이 필요합니다.
- 우선순위는 `validate_path` 보강과 `upload/share` 동시성·한도 제어부터 진행하는 것이 안전합니다.

## CI Preflight TODO (별도 PR 분리)
- 본 PR에서는 `.github/workflows`를 추가하지 않음.
- 분리 예정 항목:
  - `cryptography` / WebDAV / `ffmpeg` dependency smoke
  - PR 기본 테스트 파이프라인(`pytest -q`)


