# Milestone C — Read-Only File Core (완료)

> 계획서 Phase 6 · 로그인/목록/파일정보/다운로드+Range/ZIP/일괄ZIP/미리보기/폴백검색 + B 잔여(미들웨어 연결)

## 1. Go 라우트 (모두 live contract 검증)

| 라우트 | Python 원본 | 비고 |
|---|---|---|
| `POST /` 로그인 | `main.index` | admin→guest 순서, legacy 재해시 config 저장, 302 `/browse/` |
| `GET /` | `main.index` | 로그인 시 302, 미로그인 401 JSON (HTML 페이지는 템플릿 단계로 연기) |
| `GET /logout` | `logout` | 세션 삭제 + 쿠키 만료 + 302 `/` |
| `POST /set_language`, `GET /set_language/<lang>` | 동일 | `Deprecation`/`Sunset: 2026-08-31` 포함, 세션 저장 |
| `GET /api/list/`, `/api/list/<sub>` | `api_list` | 페이지/정렬/검색/capability/directory_capabilities 동일 스키마 |
| `GET /file_info/<path>` | `get_file_info` | md5(<10MB), mime, dir 카운트, local ISO 시각 |
| `GET /download/<path>` | `download` | quota 예약, 단일 Range 206, suffix/open-range, 416 |
| `GET /zip/<path>` | `download_zip` | temp-ZIP 전략, 권한/403·404 분기 동일 |
| `POST /batch_download/<path>` | `batch_download` | 폼 JSON, safe_name arcname, 빈 subpath 404 |
| `GET /api/zip_preview/<path>` | `zip_preview` | 확장자 allowlist, 500 cap, 손상 400 |
| `GET /search` | `search_files` | fallback 전용 (`search_mode: fallback`) |

미들웨어: IP whitelist → IP 차단 → 세션 검증/타임아웃 → login_required(401 JSON vs `/` 리다이렉트, admin 403) → CSRF(POST exemption `/`만).

## 2. Contract 결과

- `tests/test_milestone_c_contract.py` **14/14 통과** (2회 연속): twin live 서버 쌍,
  상태·JSON·헤더·바이트 비교. ZIP은 namelist+CRC, 목록/검색은 순서+집합 비교.
- `go test ./...` 전 패키지 통과. Python 전체는 아래 최종 검증 참조.
- 이 과정에서 잡힌 실제 parity 버그: charset 부착 규칙(text/*,+xml),
  disposition 3형식(bare/quoted/fallback+star), ZIP 전용 disposition,
  `..` 세그먼트의 보호경로 403, 빈 subpath 404, fresh-login `last_active` 미존재.

## 3. 알려진 차이 (후속 마일스톤에서 해소)

- HTML 페이지(`/`, `/browse/`, 실패 로그인 화면): 템플릿 포트 단계.
- `search_mode`: Python `index`/`hybrid` vs Go `fallback` — 결과 집합은 동일 검증.
- CSRF 토큰 발급 시점: Python 렌더 지연 vs Go 로그인 즉시 (브라우저 관찰 동일).
- ETag 형식 상이 (조건부 처리는 Last-Modified/304만), multi-range multipart 미지원(200 폴백).
- `safe_filename` NFC 정규화 생략, audit/recent/통계 기록 생략 (Phase 12).
- quota/세션/IP차단 영속화 생략 (Phase 12, 현재 인메모리).

## 4. 환경 발견: Go loopback RST

- 최소 hello-world Go 서버도 이 머신 loopback에서 ~15% RST (Python Werkzeug 0%).
  서버 로그는 항상 완전 응답을 기록, 타 클라이언트(IWR)는 정상.
- contract harness는 `Connection: close` + transport 재시도(최대 6회)로 대응,
  실제 서버 결함은 매 시도 실패로 그대로 드러나도록 설계.
- `-race`는 windows/arm64 미지원으로 Linux CI에서 수행.

## 5. Gate

- Python: 아래 최종 (회귀 없음) · Go: fmt/vet/test 통과 · 보안회귀: traversal/
  symlink/권한필터/CSRF/IP/보호경로 live 검증 · 파일 integrity: 다운로드·ZIP
  바이트/CRC 동등 · 데이터 영향: config 재해시 저장 외 쓰기 없음.
