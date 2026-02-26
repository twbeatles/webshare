# WebShare 기능 개선 반영 리포트 (2026-02-26)

## 1) 점검 범위
- 대상: `d:/twbeatles-repos/webshare`
- 기준: 기존 `WEB_SERVER_FUNCTIONAL_AUDIT.md`의 F-01 ~ F-10 항목
- 참조 문서: `README.md`, `README_EN.md` (`claude.md`는 저장소 내 미존재)
- 정책: 완전 호환 유지, 공유링크/감사로그 JSON 영속화, 로그인은 `admin_pw/guest_pw` 비밀번호 단독 모델 유지

## 2) 요약
- 상태: **F-01 ~ F-10 전체 반영 완료**
- 보안 우선순위 항목(F-01~F-04) 선반영 후 영속성/통계/암복호화/Docker 순으로 적용
- 회귀 검증: `pytest -q` 기준 **24 passed**

## 3) 항목별 반영 결과

### F-01 목록 노출 차단
- 반영:
  - `utils/listing.py`: `list_directory_page()`에 항목 단위 `access_filter`/`cache_scope` 추가
  - `routes/main_routes.py`, `routes/api_routes.py`: `ensure_path_access(..., "read")` 기반 필터 전달
- 결과:
  - 상위 폴더 목록에서 권한 없는 하위 항목명이 노출되지 않음

### F-02 ZIP 권한 우회 차단
- 반영:
  - `routes/file_routes.py`: `/zip`, `/batch_download`에 파일 단위 권한 필터/보호경로 필터 적용
  - `routes/share_routes.py`: 공유 폴더 ZIP에도 동일 필터 적용
- 결과:
  - 보호 파일/권한 없는 파일 ZIP 포함 차단
  - 포함 가능한 파일이 없으면 `403` 반환

### F-03 청크 업로드 무결성 강화
- 반영:
  - `routes/upload_routes.py`: `init` 입력 검증 강화(`filename`, `total_size`, `chunk_size`, `total_chunks`)
  - `complete` 단계에서 누락 인덱스/청크 부재/병합 후 크기 불일치 검증
  - 실패 시 생성 파일/임시 디렉토리 정리 후 `400` 반환
  - `templates/index.html`: `chunk_size`, `total_chunks` 전달
- 결과:
  - 빈 업로드 완료, 누락 청크, 크기 불일치가 성공 처리되지 않음

### F-04 활성 세션 정보 노출 제한
- 반영:
  - `routes/api_routes.py`: `GET /api/active_sessions`를 관리자 전용으로 변경
  - `security/auth.py`: API/AJAX 접근 시 JSON 형태 `401/403` 응답 정리
- 결과:
  - non-admin 접근 시 `403` 처리

### F-05 감사 로그 영속화
- 반영:
  - `features/audit_log.py`: dirty 플래그 + `flush_audit_log_if_dirty(force=False)` 추가
  - `server.py`: 주기 정리 루프에 flush 추가, shutdown 시 force flush 추가
- 결과:
  - 메모리 누적 로그가 주기/종료 시 JSON(`.webshare_audit.json`)으로 저장

### F-06 공유 링크 영속화 + 입력 검증
- 반영:
  - `config.py`: `SHARE_LINKS_FILE` 추가
  - `features/share_links_store.py` 신규: 저장/로드/만료 정리(원자적 쓰기 + datetime 직렬화)
  - `server.py`: 런타임 초기화 시 공유링크 로드
  - `routes/share_routes.py`: 생성/삭제/다운로드카운트/만료 정리 시 저장
  - `/share/create`: `hours`, `max_downloads` 타입/범위 검증(`400`)
- 결과:
  - 재시작 후 공유 링크 복원
  - 타입 오류가 `500`으로 누수되지 않음

### F-07 전송량 이중 집계 제거
- 반영:
  - `routes/file_routes.py`: `/download/<path>` 수동 `bytes_sent` 증가 제거
  - `server.py`: `after_request` 단일 집계 기준 주석/가드 정리
- 결과:
  - 단일 다운로드의 전송량이 1회만 누적

### F-08 사용자 API-로그인 모델 불일치 명시
- 반영:
  - `routes/admin_routes.py`: `/api/users` GET 응답에 `login_mode`, `login_linked`, `notice` 추가
  - POST/PUT/DELETE 응답에 `warning` 필드 추가
  - `templates/index.html`: 사용자 관리 모달에 로그인 미연동 배너 추가
  - `README.md`, `README_EN.md`: 미연동 사실 명시
- 결과:
  - 기능 오해를 줄이고 호환성 유지

### F-09 암복호화 개선 + 레거시 호환
- 반영:
  - `features/crypto.py` 교체:
    - v2 헤더 기반 AES-GCM 스트리밍 암복호화
    - 기존 CBC 포맷은 레거시 복호화 fallback 유지
    - 임시 파일 기반 원자적 처리
  - `routes/security_routes.py`:
    - `error_type` 분류(`invalid_password`, `file_corrupted_or_format`, `decryption_error`)
- 결과:
  - 무결성 검증 가능한 암복호화 경로 확보
  - 기존 `.enc` 파일 복호화 호환 유지

### F-10 Docker 자산 정합성
- 반영:
  - 신규: `Dockerfile`, `docker-compose.yml`, `docker_entrypoint.py`
  - `docker_entrypoint.py`에서 `WEBSHARE_FOLDER/HOST/PORT` 반영, 런타임 초기화 및 백그라운드 작업 시작
  - README 양언어 Docker 섹션 정합성 보강
- 결과:
  - 문서와 실제 배포 자산 불일치 해소

## 4) Public API 영향 요약
- `GET /api/active_sessions`: 관리자 전용(`403` 가능)
- `POST /upload/chunk/init`: `chunk_size`, `total_chunks` 입력 지원 및 검증 강화
- `POST /upload/chunk/<session_id>/complete`: 불완전 업로드 시 `400`
- `POST /share/create`: `hours`, `max_downloads` 타입/범위 검증(`400`)
- `GET /api/users`: `login_mode`, `login_linked`, `notice` 추가
- 암복호화: v2(AES-GCM) 기본 + 레거시 CBC 복호화 호환

## 5) 영속화 파일
- 감사 로그: `.webshare_audit.json`
- 공유 링크: `.webshare_share_links.json`

## 6) 자동 테스트 결과
- 테스트 스위트:
  - `test_permissions_enforcement.py`
  - `test_api_compatibility.py`
  - `test_upload_integrity.py`
  - `test_persistence_and_metrics.py`
  - `test_crypto_and_docker.py`
  - 기존 보안/다운로드 제한 테스트
- 실행 결과: `pytest -q` → **24 passed**

## 7) 결론
- 기존 감사 리포트의 F-01~F-10은 현재 코드베이스에 반영 완료 상태이며, 핵심 보안 우회 경로/영속성 공백/무결성 결함이 해소됨.
- 문서(`README.md`, `README_EN.md`) 및 빌드 스펙(`*.spec`)도 현재 구현 기준으로 정합성 보강됨.
