# Milestone J — Go Default Cutover (완료)

사용자 결정: 이번 턴에 전환 적용 (`default = go`, `fallback = python`).

## 1. 변경

- `webshare_app/server/go_process.py::backend_name()` 기본값 `python` → `go`.
- `webshare_app/server/__init__.py::start_server()`: Go 시작 실패 시 자동으로
  Python 스레드 기동 (§58 rollback: 설정·데이터·프론트 변환 없음).
  명시적 `WEBSHARE_SERVER_BACKEND=python`이면 기존 경로 그대로.
- `tests/test_go_process.py`: 기본값 단언 갱신 + 폴백 테스트 추가.
- `docs/go-migration/00-migration-plan.md` §12 기본값 갱신.
- 패키징: `webshare.spec`/`WebSharePro.spec`에 `go-core/webshare-core.exe`
  번들 (`_MEIPASS`에서 탐색, 빌드 전 `go build` 필요).

## 2. 전환 게이트 (§56) 결과

- 전체 Python 회귀: 161 passed + 1 skipped.
- Go: build/vet/test 전 패키지 통과.
- 계약: B·C 23개 + D/E/F 10개 (신규 trash/metadata/versions/audit/system 포함).
- 보안: hardening·policies·permissions·audit(1/2)·upload_integrity·download_limits 48개.
- 패키징 스모크: exe 빌드 + `version` + `check-config` 통과.
- Fallback: 단위 테스트로 Go 실패 → Python 기동 확인.

## 3. 롤백

문제 발생 시: Go 중지 → Python 기동. 설정·영속 데이터·프론트 변경 불필요
(양 백엔드가 동일 스키마·동일 naive 시각 파일을 공유).
긴급 시 `WEBSHARE_SERVER_BACKEND=python`으로 즉시 복귀.
