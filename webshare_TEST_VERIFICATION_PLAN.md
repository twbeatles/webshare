# webshare — Go/Python 실서버 계약·파일무결성·장애 복구 테스트 고도화 지시서

> 대상: `twbeatles/webshare` · https://github.com/twbeatles/webshare  
> 조사 기준: 2026-10-15 / `main` HEAD `2664a4b5717b`(update manifest), 실제 코드 검증 시 선행 `ec9d922a2252` 이상 최신 SHA 기록  
> 목표: Flask/Python·Go 백엔드를 실제 루프백 포트에서 가동하고 동일한 요청·실파일·권한·장애 조건에 대해 **동등한 안전 계약**이 성립함을 독립적으로 입증한다.  
> 실행 지시: 이 문서대로 검증 환경, 위험별 자동 테스트, 실패 재현·수정, CI, 보고 증거를 구현한다. 기존 문제를 재선언하기보다 현재 구현에서 이미 수정된 위험을 증명하고 **남은 공백**을 메운다.

## 0. 절대 안전 규칙

- 시작 시 README, AGENTS/CLAUDE 등 프로젝트 지침, `PROJECT_AUDIT.md`, 실제 `main` SHA, `git status --short` 확인. 사용자의 미커밋 변경 보존, force push/reset 금지.
- 모든 테스트는 자체 생성한 작업 폴더·사용자·서버 설정과 **127.0.0.1에서만** 실행. 프로덕션 포트·공유 폴더·Google Drive·실제 계정·외부 공개 바인딩·실업무 자료 접근 금지. Windows 방화벽, UPnP, 외부망, 운영 업데이트 적용 금지.
- 두 서버를 구동했다는 사실, API 200, 단위 테스트 개수만으로 `PASS` 판정 금지. 반드시 전후 파일 SHA-256, 실제 다운로드 바이트, 인증 주체, 상태·응답 의미를 독립 oracle과 비교.
- 두 서버는 **각각 독립된 root/state/temp dir**, 별도 랜덤 포트, 독립 프로세스로 실행. 같은 설정·시드로 시작하며 상태 정규화 시 시각·세션 ID·토큰 등 비결정 항목만 계약상 허용된 방식으로 치환. 서로 다른 메타데이터 구현이 완전히 호환된다고 가정하지 않는다.
- 강제 종료·파일 손상 주입은 격리된 서버 프로세스만, 대량 파일은 생성 상한·용량 상한. 외부 데이터 파괴 또는 실제 폴더 일괄 정리 금지.
- `PASS`, `FAIL`, `BLOCKED`, `NOT RUN` 네 상태 구분. 소켓/인증·상태 차이를 이유 없이 가리는 광범위 필터로 "동일" 판정 금지.

## 1. 현재 확인한 기준선과 중복 금지 범위

- 구조: Python Flask (`webshare_app/app/factory.py`, `webshare_app/routes`, `server/thread.py`, `docker_entrypoint.py`) + 별도 Go 서버(`go-core/cmd/webshare-core/main.go`, `go-core/internal/handlers/`), PyQt6 GUI, 원자 JSON 저장·공유 링크·청크 업로드·휴지통·버전 관리·WebDAV.
- `tests/test_backend_parity_contract.py`는 **현재 실제 프로세스 두 개를 동시에 띄우지 않는 hermetic 계약 테스트**임을 파일 주석에서 확인. 대응 Go `go-core/internal/handlers/share_test.go`는 Go 핸들러를 별도 검증. 둘의 통과는 실제 서버 간 parity의 충분조건이 아님.
- `tests/test_audit_remediation_001_002_005.py`, `test_upload_integrity.py` 등에서 청크 상태·업로드 크기 검사·설정 파일·ZIP 방어 회귀가 이미 있음. `chunk_finalize.py`는 `UPLOAD_STATUS_COMPLETING`과 merge-cancel guard를 구현. `trash.py`는 self-heal 경로 존재. 과거 `PROJECT_AUDIT.md` (2026-10-06)의 ISSUE-001~005를 **미수정이라고 전제하거나 동일 테스트만 복사하지 않는다.** 실제 미검증 틈은 확인 후 재현.
- `.github/workflows/ci.yml`에서 Windows Python 3.15 + Go 빌드/vet/test + Python Fast subset (명시적으로 milestone B/C/DEF contract tests 제외)을 실행. `.github/workflows/release.yml`에서는 전체 pytest + Go + frozen EXE smoke + 서명 manifest를 검증. **Fast vs Release 검증 범위 차이**를 유지하면서 중요한 통합 시나리오를 적절한 게이트로 승격.
- 2026-10-14 [CI 성공](https://github.com/twbeatles/webshare/actions/runs/38557650270), [Release 성공](https://github.com/twbeatles/webshare/actions/runs/38557659248). GitHub Actions 통과는 실서버 두 개의 장애·보안 동등성까지 증명하지 않는다.
- 기본 Go + HTTPS 조합은 현재 명시 거절하도록 설계됨. **지원하지 않는 조합을 억지로 성공시켜 parity 주장하지 않는다**. 안전한 거절 자체가 테스트 기대값이다.

## 2. Phase 0 — 기준선 및 실제 프로세스 하네스

1. HEAD SHA, OS/arch, Python/Go, 바이너리 버전, 두 백엔드 지원 기능, 개발 의존성, CI 실행 결과, 기존 테스트 통과/skip을 `docs/quality/server-parity/BASELINE.md`에 기록.
2. 저장소 CI와 같은 환경에서 `python -m pyright`, `python -m pytest -q`, `(cd go-core && go test ./... && go vet ./...)` 수행. 전체 Python suite가 자원 문제로 실패할 경우 테스트 케이스/로그/재현을 분리해 확인, 일괄 `xfail`/`skip`으로 감추지 않음.
3. 실제 API 실행 방식은 `main.py`/현재 서버 런처·설정 방법 확인 후 결정. `WEBSHARE_SERVER_BACKEND` 등 **현재 지원하는 공식 옵션만** 사용; 127.0.0.1 동적 포트, 디렉터리 격리, `/readyz` 또는 실제 응답과 PID 확인. 서버 중지 후 자식 Go 프로세스·파일 handle·포트 잔류 0 확인.
4. 테스트 드라이버(`tests/quality/test_live_backend_parity.py` 등)는 시작→사용자 로그인 및 CSRF 획득→파일 작업→상태 확인→종료 과정을 **HTTP 클라이언트로 수행**한다. Flask `test_client`/Go `httptest`만 사용하면 'real network E2E'가 아니다.
5. 독립 oracle은 파일 `sha256`, 수신 bytes, 예상 계층/권한 표, 파일·휴지통 manifest, 각 API의 **의미적 계약**(HTTP code, 오류 유형, Content-Type, 인증/인가 동작, 재시도 결과). 운영 구현의 permission helper를 호출해 기대값을 계산하지 않는다.
6. 공통 테스트 데이터: 0B / 1B / 1MiB / 32MiB 바이너리, 한국어·이모지 이름, 동일한 이름의 다른 바이트, 충돌 경로, 폴더 중첩, 비정상 ZIP(Zip Slip/ratio, 위험성 상한 설정), 토큰 만료 및 한도 경계.

## 3. Phase 1 — 백엔드 간 실제 HTTP 계약 차이 검증 (P0)

| ID | 실제 요청 흐름 | 독립 oracle 및 불변식 |
|---|---|---|
| PAR-01 | 관리자 로그인→작은 파일 업로드→다운로드 | 두 서버 응답 코드/파일명/실제 bytes 동일; SHA-256 일치 |
| PAR-02 | 사용자 역할별 list/download/upload/delete | owner/admin, read-only, unauthorized의 허용·거부가 **같은 정책**을 만족; UI 텍스트 차이는 normalize |
| PAR-03 | 공유 링크 생성→비밀번호 폼/JSON challenge→틀린 암호→정상 다운로드 | HTML/JSON content negotiation, 상태/headers, 다운로드 파일 SHA 동일; 사용 횟수 정확 |
| PAR-04 | 공유 링크 만료·없음·한도 소진 | 404/410/429 등 **현재 합의된 계약** 일치, 인증 우회 0 |
| PAR-05 | 미리보기/inline/Content-Disposition/한글 filename | 브라우저 다운로드 의미와 UTF-8 filename 처리 동일 |
| PAR-06 | 중복 업로드·overwrite 거부·충돌 rename | 두 파일 모두 남고 변경 전 원본 SHA 불변, 반환 파일명·파일 내용 일치 |
| PAR-07 | 부분 upload init→chunks out of order/누락/중복→complete | 정상 사례 동일 bytes, 비정상 케이스가 완성 파일을 남기지 않음 |
| PAR-08 | 경로 traversal·symlink root escape·URL 인코딩 변형 | root 밖 read/write 0; 권한 실패/오류 응답 차이 확인 |
| PAR-09 | 휴지통 이동·복원·버전복원 | 원본/복원 bytes·기록 일치; 구현별 내부 메타 차이는 호환성 조건 문서화 |
| PAR-10 | Python backend/Go backend 각각 재시작 | 상태·설정·사용자 권한 유지, 보관 파일·공유 링크 재접근 규칙 동일 |
| PAR-11 | Go 단독 지원·Python 단독 지원·비지원 기능 호출 | 문서화된 차이는 명시 `N/A(계약상)`; 무의식적인 기능 누락 은폐 금지 |
| PAR-12 | Docker(명시 Python) vs Windows GUI/Go | 백엔드 선택 동작 및 지원 기능을 문서·실행과 비교 |

- **정확한 URL/응답 스키마는 테스트 작성 전 라우트·현재 계약을 조사**한다. 표에 적힌 API 존재를 추정해 가짜 endpoint를 만들지 않는다.
- 상태를 비교할 때 단순 문자열 diff 대신 whitelist된 비결정값(토큰·random IDs·날짜)만 정규화한다. 보안 값·파일 바이트·권한 결과는 정규화 금지.
- Go 불지원 HTTP/TLS 조합은 실행이 거절되어야 `PASS`. 서버 parity를 위해 Python 보안 검사를 약화하지 않는다.

## 4. Phase 2 — 장애·경합·재시작·데이터 정합성 (P0)

| ID | 장애 삽입 지점 | 요구 결과 |
|---|---|---|
| FT-01 | 청크 쓰기 중 연결 끊김/서버 종료 | 최종 파일 미완성·원본 불변, 임시 조각 처리·재전송 정책 명확 |
| FT-02 | `COMPLETING` 중 cancel과 complete 경합 | 정책에 따른 완료/취소 중 **정확히 하나**, 잘린 최종 파일 0, idempotent 재호출 |
| FT-03 | temp 병합 후 `os.replace` 직전 실패 | 기존 목적 파일 SHA 보존, temp 정리 또는 재시작 후 회수 |
| FT-04 | `os.replace` 성공 후 세션·감사 로그 업데이트 전 종료 | 완성 파일은 유효; idempotency/상태 복구로 중복 파일 생성·거짓 오류를 통제 |
| FT-05 | 휴지통 파일 이동 직후 메타데이터 쓰기 실패 | self-heal 또는 복구 가능한 고아 항목. 원래 경로 맵핑 유지 |
| FT-06 | 휴지통 복원 시 대상 파일 존재·동일 파일명 충돌 | 기존 대상 보존; 별도 안전명 반환; 서로 다른 바이트 혼합 금지 |
| FT-07 | 공유 링크 동시 다운로드 제한 1 / 클라이언트 중도 중단 | 다운로드 횟수/쿼터가 정의된 계약과 일치; race로 제한 우회 금지 |
| FT-08 | 잘못된 UTF-8 설정·손상된 JSON·read-only root | 서버가 명시적으로 오류를 내거나 안전한 fallback; 무음 설정 초기화·데이터 삭제 금지 |
| FT-09 | 작은 가상 볼륨/제한된 쓰기 공간에서 ZIP 해제·업로드 | 부분 추출과 공간 부족 메시지 구분, 외부 경로 추출 0 |
| FT-10 | Go 자식 프로세스 kill 및 감독자 재시작 | 정책상 허용되는 전환만 수행, 오픈 파일 누락·권한 우회·고아 프로세스 0 |
| FT-11 | 버전 복원·파일 덮어쓰기 중 네트워크/프로세스 실패 | 복원 전 또는 후의 온전한 상태만 허용, 스냅샷 SHA 비교 |
| FT-12 | 동시에 rename/delete/download/version restore | 마지막 상태가 선언한 순서 모델과 합치, 경로 삭제를 권한 오류로 숨기지 않음 |

- Fault injection은 실제 하네스 프로세스에서 안전하게 테스트 파일에만 수행. os.replace/메타데이터 writer/네트워크 스트림에 barrier를 넣어 **결정론적 interleaving**을 재현한다. 무작정 반복해 드물게 성공하는 테스트 금지.
- Go/Python 동등성이 보장되지 않는 기능은 `GAP` 문서와 parity 실패 원인을 남긴 뒤 상호 호환의 필요성 및 우선순위를 결정. 의도적 차이를 테스트 실패로부터 제거하기 위해 애매한 skip을 만들지 않는다.

## 5. Phase 3 — 보안·복구 정책 불변식

- admin/guest/read-only 별 루트 밖 접근 거부; symlink·중첩 경로·URL 이중 디코딩·ZIP 이름·WebDAV 등 **동일 보호 경계**를 검증. 보안 공격 재현은 오직 격리 루트에서만 수행.
- 공개 링크 토큰/비밀번호·횟수·만료·IP 제한·감사 로그의 정보 누출을 확인하되 secret/token 평문을 CI artifact로 노출하지 않는다.
- 공유 링크·청크 상태·휴지통 메타데이터·감사 기록을 **재시작 전후** 비교한다. 파일 시스템이 성공 상태인데 API만 실패라고 응답하면 문제로 기록.
- Python/Go 간 공유 루트의 메타 포맷을 서로 직접 교체 가능한지 실제 확인하지 않으면 "동일 상태 포맷"을 보장했다고 쓰지 않는다. 자동 전환 기능이 없는 경우 임의로 도입하지 말고 계약을 명시.

## 6. Phase 4 — Mutation Testing: 검출 능력 입증

**격리 복사본**에서 하나씩 적용하고 사용한 테스트가 반드시 FAIL인지 확인. 최소 8개 의미적 mutation 검출. 실패하지 않은 mutant는 `SURVIVED` 및 대응 테스트 강화.

| ID | 삽입할 오류 | 반드시 RED가 나야 하는 검증 |
|---|---|---|
| M1 | 업로드 chunk index 누락 검사 제거 | PAR-07 |
| M2 | complete `COMPLETING` 상태 가드 제거 | FT-02 |
| M3 | 파일 실해시 확인 없이 성공 반환 | PAR-01/FT-04 |
| M4 | root path validation 또는 권한 체크 생략 | PAR-02/08 |
| M5 | 다운로드 count 예약 원자성 무효화 | FT-07 |
| M6 | 휴지통 메타데이터 없이 성공 리턴 | FT-05 |
| M7 | rename 충돌 시 목적 파일 덮어쓰기 | PAR-06/FT-06 |
| M8 | 재시작 시 구 세션 유효 처리 | PAR-10/FT-01 |
| M9 | 설정 JSON 읽기 실패를 무조건 기본값으로 처리 | FT-08 |
| M10 | ZIP 안전 검사 한 단계 우회 | FT-09 |

- mutation 증거: mutant diff SHA, baseline GREEN, mutant RED 로그, 원복 후 GREEN, 테스트 ID, 파일 SHA. **mutation한 코드를 실제 배포·커밋하지 않는다.** 모든 mutation 테스트는 운영 외부 파일 경계 우회가 없도록 격리.

## 7. Phase 5 — CI 구조 개선 및 실제 실행

1. 현재 CI는 Go test/vet 및 Python fast subset을 이미 실행. 이를 유지하고 **loopback two-process P0 parity**를 `ci.yml`의 별도 job(또는 선택된 중요 subset)으로, slow fault injection·대용량·성능·GUI·Docker는 주기적/nightly 또는 workflow_dispatch로 분리.
2. Release workflow의 전체 pytest·Go test·EXE smoke·서명 manifest 단계를 훼손하지 않는다. CI 전체를 빠르게 만들겠다며 예전 milestone 계약 테스트를 숨기거나 제거하지 않는다. 반드시 coverage gap 정보를 기록.
3. 실행 준비: 테스트 서버용 port picker, 격리 HOME/AppData, 독립 `WEBSHARE_SERVER_BACKEND`, lock/프로세스 cleanup, 비밀번호 fixture. Windows Go 바이너리를 CI에서 컴파일하고 정확한 SHA/버전을 확인. Docker 경로는 별도 job으로 실제 Python backend 동작 확인.
4. 바이트 불변식을 검증하는 테스트에 시간 상한·실패 후 안전한 teardown 추가. flaky test는 3회 재실행과 원인 분석을 남기고 quarantine 처리 시 위험 게이트 예외로 둔 이유를 명시.
5. 벤치마크는 정확성 이후 수행. 1MB·32MB·100MB 중 리소스에 맞춘 샘플로 throughput/메모리 측정, Go/Python 성능 차이를 기능 불일치와 혼동하지 않는다.

## 8. 제출 파일과 승인 기준

- `docs/quality/server-parity/BASELINE.md` — 현 커밋/버전/실행 환경/기존 CI 및 누락 영역.
- `docs/quality/server-parity/CONTRACT_MATRIX.md` — PAR/FT 개별 기대값·실제 API·기능 N/A.
- `docs/quality/server-parity/MUTATION_EVIDENCE.md` — 최소 8개 mutation RED/원복 GREEN.
- `docs/quality/server-parity/TEST_VERIFICATION_REPORT.md` — 최종 요약/증거/미검증.
- 테스트 파일은 프로젝트 컨벤션의 `tests/quality/`에 두고 결과 스냅샷/디버그 파일은 원칙적으로 Git 제외. 개인정보·토큰·실파일 내용 artifact 금지.

| 테스트 ID | 백엔드 / 명령 | 서버 PID·바이너리 SHA | 독립 oracle | 파일 해시·HTTP 결과 | PASS/FAIL/BLOCKED | 로그 경로 |
|---|---|---|---|---|---|---|
| PAR-01 | Flask+Go/loopback | … | expected SHA | … | … | … |

**완료** = 기존 Python 전체·Go 전체·현재 CI green + 실제 Python/Go HTTP 동작에서 P0 불변식 성립 + 실패 주입에서 데이터 유실 0 + mutation ≥8개 검출 + 인증/권한 우회 0 + 테스트 프로세스/임시파일 정리 + CI 해당 commit green. 사용하지 못한 Docker·외부 OAuth·ffmpeg·UPnP·GUI 환경은 개별 `BLOCKED`로 기록하고 합격 문구에서 제외.

```text
최종 커밋 / 변경 내용:
기존 suite 및 신규 suite (실행 명령·결과):
두 실제 서버 기동 로그/버전/포트:
독립 파일/HTTP oracle 성공·실패:
경합·중단·복원 결과:
Mutation 죽음/생존/미실행:
보안 경계 검증 범위:
CI·Release 비교 및 실행 링크:
실제 결함 재현/수정/재검증:
미검증 환경·잔여 위험·필요 승인:
```
