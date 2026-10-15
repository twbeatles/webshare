# Test Verification Report (Phases 0-5)

## 최종 요약

- 실제 루프백 HTTP로 동작하는 신규 스위트 `tests/quality/` 58개 테스트가
  전부 통과한다 (Python 실서버 + Go 실서버 프로세스, 격리 root·랜덤 포트).
- 기존 Python 전체·Go 전체·CI fast 범위에 회귀가 없다 (아래 실행 명령 참고).
- Mutation 10/10 KILLED (baseline GREEN → mutant RED → 원복 GREEN),
  증거는 `MUTATION_EVIDENCE.md`에 자동 생성된다.
- 인증/권한 우회 0, 데이터 유실 0, 잔류 프로세스/임시파일 0을 확인했다.

## 제출 파일

- `docs/quality/server-parity/BASELINE.md` -- 커밋/버전/환경/기존 CI/누락 영역
- `docs/quality/server-parity/CONTRACT_MATRIX.md` -- PAR/FT 기대값·실제·N/A
- `docs/quality/server-parity/MUTATION_EVIDENCE.md` -- 10개 RED/원복 GREEN
  (생성기: `python scripts/run_mutation_check.py`)
- `docs/quality/server-parity/TEST_VERIFICATION_REPORT.md` -- 본 문서
- 테스트: `tests/quality/{live_harness,conftest,test_harness_smoke,
  test_live_backend_parity,test_live_fault_recovery,
  test_live_security_boundary,test_mutation_detection}.py`
- CI: `.github/workflows/ci.yml`에 `live-parity` job 추가
  (fast subset 불변 + `pytest -q tests/quality` 별도 게이트)

## 두 실제 서버 기동 로그/버전/포트

- Python: 동일 프로세스 WSGI를 `127.0.0.1:0`(ephemeral)에 바인드,
  `/healthz` 실응답으로 readiness 확인 후 진행, 테스트마다 격리 root.
- Go: `go-core/webshare-core.exe serve -host 127.0.0.1 -port <free>
  -config <tmp>` 자식 프로세스로 기동, `GET / → 401`로 readiness 확인,
  종료 후 프로세스 잔류 0 확인.
- Go 바이너리 SHA-256:
  `3634e2de7d0f81cb6bc9992b31042599bcb7194e02232697e8f081753e974540`

## 독립 파일/HTTP oracle 성공

- PAR-01 0B/1B/1KiB/1MiB + 한글/이모지: 양 백엔드 수신 바이트 SHA-256이
  송신 oracle과 일치. 동일명·다른바이트 업로드는 rename 보존.
- PAR-03 공유 비번/횟수, PAR-04 만료(410)/없음(404)/소진(429),
  PAR-05 disposition/UTF-8, PAR-06~09 청크·휴지통 바이트 동일성 확인.
- 경합·중단·복원: FT-01~12 전부 PASS (상세는 CONTRACT_MATRIX).

## Mutation 죽음/생존/미실행

- 10/10 KILLED, 0 SURVIVED, 0 BLOCKED, 작업 트리 복원 확인(clear).
- 방법: 소스 1개소 의미적 변이 → 검출기 RED → 바이트 복원 → GREEN.

## 보안 경계 검증 범위

- 역할×변이 8종, 관리자 API 상승 차단(XHR 401/403 + 브라우저 302),
  traversal/이중인코딩/백슬래시/심볼릭/ZIP명 0 escape (dual 포함),
  공유 비번 5회 오답 후 429 차단, 보호경로 거부, 평문 secret 미노출.

## CI·Release 비교

- 기존 `verify` job은 손대지 않았다 (fast subset 동일).
- `live-parity` job이 `needs: verify`로 뒤따르며 Go 빌드 후
  `pytest -q tests/quality`만 실행한다. 느린 fault/perf/GUI/Docker는
  기존처럼 nightly/dispatch 영역에 남긴다.

## 실제 결함 재현/수정/재검증

1. 수정 없이 규명한 테스트-하네스 문제 2건 (제품 코드 변경 없음):
   - 익명 거부 검증이 리다이렉트를 추종해 200 로그인 페이지를
     받던 문제 → 무추종 302 직접 단언으로 수정.
   - 게스트 관리자 API 검증이 브라우저 302를 200으로 오독 → XHR
     헤더 + 무추종 단언으로 수정.
2. 기존 마일스톤 twin 하네스 결함 1건을 수정했다 (테스트만, 제품 무변경):
   - `test_milestone_c_contract.py` TwinClient(DEF가 재사용)가
     `Accept-Encoding` 없이 대형 HTML을 요청해 길이 없는 chunked
     스트림에서 멈추고 4개 테스트가 `TimeoutError`로 실패했다.
     브라우저처럼 `gzip`을 협상·해독하도록 8줄 패치했고, 마일스톤
     33개가 전부 통과한다 (8분 타임아웃 → 57초).
3. 제품 동작으로 확정하고 문서화한 사항 (parity 유지 위해 미변경):
   - 할당량 소진 후 도착(late reserve 실패) 응답이 양 백엔드 모두
     `200 + share_expired.html`이다. 파일 바이트는 원자적 reserve가
     `max_downloads`로 엄격히 제한하므로 우회는 불가능하며,
     FT-07/M5가 이를 경합 하에서 증명한다. 상태 코드 변경은 GUI
     호환성과 parity를 깨므로 이번 hardening에서 고치지 않는다.
   - 무압축 대형 응답의 개발 서버 chunked stall은 하네스·마일스톤 모두
     gzip 협상으로 해소했다. 제품 설정은 바꾸지 않았으므로, gzip을
     보내지 않는 구형 클라이언트의 대형 페이지 수신은 잔여 위험이다.

## 미검증 환경·잔여 위험·필요 승인 (BLOCKED, 합격 문구에서 제외)

- Docker 런타임, 외부 OAuth, ffmpeg 트랜스코딩, UPnP/외부망, GUI 환경:
  개별 BLOCKED. 본 보고의 PASS는 127.0.0.1 실서버 범위에 한정된다.
- Go 공유 만료 live 경로: GAP-1 해소. 영속 저장소에 과거 만료 시각을
  주입하고 재시작하면 404 + 무바이트 + 목록 영구 제거를 live로 확인했다
  (실행 중 만료 410은 Python live + Go 단위 테스트로 각자 검증).

```text
최종 커밋 / 변경 내용:
- tests/quality/** 신규 7개 파일 + scripts/run_mutation_check.py +
  docs/quality/server-parity/*.md 4종 + ci.yml live-parity job
기존 suite 및 신규 suite (실행 명령·결과):
- python -m pytest -q tests/quality .................... 58 passed
- python -m pytest -q (CI fast 범위, quality 포함) .... 292 passed
- milestone B/C/DEF (Release 범위) .................... 33 passed
- (cd go-core && go test ./... && go vet ./...) ....... 전 패키지 ok
- python -m pyright .................................... 0 errors
두 실제 서버 기동 로그/버전/포트: 상단 참조
독립 파일/HTTP oracle 성공·실패: PAR-01~12 / FT-01~12 PASS, 실패 0
경합·중단·복원 결과: FT-01/02/07/10 + PAR-10 PASS
Mutation 죽음/생존/미실행: 10/0/0
보안 경계 검증 범위: 상단 참조
CI·Release 비교 및 실행 링크: ci.yml live-parity (needs: verify)
실제 결함 재현/수정/재검증: 신규 하네스 2건 + 마일스톤 twin 1건 수정,
  제품 동작 2건 문서화(미변경 근거 포함). PAR-03 1회성 실패 1건은
  단언 강화 후 3회 연속 녹색으로 미재현 종결 (원인 미확정, 재발 시 quarantine 승격).
미검증 환경·잔여 위험·필요 승인: Docker/OAuth/ffmpeg/UPnP/GUI = BLOCKED
```