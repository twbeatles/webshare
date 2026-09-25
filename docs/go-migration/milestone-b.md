# Milestone B — Security Foundation (완료)

> 계획서 Phase 4–5 · 인증/세션/CSRF/오류규격/IP/권한/경로보안 라이브러리 + contract parity

## 1. 구현 (go-core, stdlib only)

| 패키지 | Python 원본 | 내용 |
|---|---|---|
| `internal/auth/password.go` | `security/auth.py` | Werkzeug PBKDF2(sha256/512/sha1) 검증·생성, legacy SHA-256, 평문, constant-time 비교, 미지원 `$` 포맷 fail-closed |
| `internal/auth/flasksession.go` | Flask 3.1.3 + itsdangerous 2.2.0 | 세션 쿠키 서명/검증 완전 호환 (HMAC-SHA1 key-derivation, `cookie-session` salt, base64-url 무패딩, big-endian 최소 timestamp, **zlib 압축 + `.` prefix**, max_age/미래시각 만료, `last_active` 타임아웃 경계 `strict >`) |
| `internal/auth/csrf.go` | `security/csrf.py` | 세션당 토큰, form→header→JSON 우선순위, constant-time 검증 |
| `internal/auth/ip.go` | `security/ip_blocker.py`, `file_utils.get_real_ip` | XFF hops 추출, trusted proxy spoofing 방지, whitelist(빈목록 허용 + `127.0.0.1` literal bypass — `::1` 미포함 quirk 유지), 5회/15분 차단 + 만료/정리 |
| `internal/permission/path.go` | `request_policy.py`, `file_utils.validate_path` | normalize/parent/protected, canonical containment(절대경로 입력은 base破棄 후 판정, 드라이브 불일치 거부, 대소문자 구분 비교 quirk 유지, symlink는 최심층 존재 조상 기준 해석) |
| `internal/permission/permissions.go` | `security/permissions.py`, `request_policy.py` | 상속형 check(admin bypass), entry 정규화, atomic 저장/로드, capabilities 11종, mutation/access 게이트 |

발견된 호환성 함정 2건 (둘 다 Golden vector + 양방향 live 검증으로 확정):
1. 세션 쿠키 페이로드는 유리할 때 zlib 압축 + `.` prefix (`url_safe.py`) — 초기 구현에서 누락했다가 contract test 실패로 발견·수정.
2. `max_age=-1`은 만료 (itsdangerous 의미 그대로) — `<=0 비활성화` shortcut 폐기, `*time.Duration nil`로 구분.

## 2. Contract parity

- `tests/fixtures/go_migration/milestone_b/` — Python reference에서 생성한 golden vector 4종
  (password 13, session 8, path normalize/protected/parent/validate 14+15+5+15, permission 15+8+5, IP 6+7).
- `tests/test_milestone_b_parity.py` 9건: Python 재확인 + `testprobe` 경유 양방향 live 검증
  (Go 해시→Python 검증, Python 해시→Go 검증, Go 쿠키→Python 로드, Python 쿠키→Go 로드).
- Go 단위 테스트: `go test ./...` 전 패키지 통과 (`auth`, `config`, `permission`, `server`).

## 3. 보안 회귀 (Milestone B 범위)

통과: traversal battery(`..`, 혼합 슬래시, 절대경로, 드라이브 탈출, symlink 탈출 시도),
guest→admin 거부, CSRF 누락/오류, 만료 세션, IP whitelist/차단/만료해제, proxy spoofing,
`.webshare` 보호경로. HTTP 라우트 결합형 항목(미인증 접근, brute-force)은 라우트 이관 Phase에서 수행.

## 4. Gate 결과

- Python baseline: 152 → **161 passed, 1 skipped** (parity 9 추가, 회귀 없음)
- Go: `gofmt`/`go vet`/`go test ./...` 통과 (`-race`는 windows/arm64 미지원으로 Linux CI에서 수행)
- 파일 integrity: 해당 없음 (파일 I/O 쓰는 기능 없음 — permission store round-trip만 tmp에서 검증)
- 데이터 영향: 없음 (기존 포맷 읽기만, 쓰기 없음)

## 5. 남은 작업 (Milestone C)

- 로그인 라우트에서 위 라이브러리 사용, 세션/CSRF/IP 미들웨어를 HTTP 체인에 연결
  (현재 skeleton 체인은 request-ID/recovery/로깅만 유지 — 절반 연결 상태로 두지 않음).
- `SECRET_KEY_FALLBACKS` 미사용 확인 유지 (factory에서 설정하지 않음).
- `round(remaining)` — Python banker's rounding vs Go half-up: 초 단위 timestamp에서 `.5`분 경계에
  정확히 걸릴 수 없어 실무 영향 없음, 기록만 유지.
