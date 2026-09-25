# Milestone D/E/F — Mutation · Upload · Share + 결함 수정 (완료)

> D: `internal/mutate` + mutation 라우트 · E: `internal/upload` + 업로드 라우트 ·
> F: `internal/share` + 공유 라우트 + ETag/Range/NFC/영속화 결함 수정

## 1. Go 라우트 (모두 live contract 검증)

| 라우트 | Python 원본 | 비고 |
|---|---|---|
| `POST /mkdir/`, `/mkdir/<p>` | `mutation_handlers.mkdir` | safe_name, 이중 write 체크, 중복 400 |
| `POST /delete/<p>` | `delete` | 휴지통 + 메타데이터, 미존재 404 |
| `POST /rename/<p>` | `rename` | `old_name` 변형, 충돌 400 |
| `POST /copy`, `/move` | `copy_item`/`move_item` | rename/fail/overwrite, 409 `DESTINATION_EXISTS`, staging 교체, overwrite 버전 백업 |
| `POST /batch_delete/<p>` | `batch_delete` | per-item 성공/실패, 빈 subpath 404 |
| `POST /unzip/<p>` | `unzip_file` | Zip Slip 400, Zip Bomb 400, BadZip 200+success:false |
| `POST /upload/`, `/upload/<p>` | `upload` | multipart 다중파일, `paths[]`, 중복 rename, 디스크 예약 |
| `POST /upload/chunk/init` | `chunk_init` | 세션/TTL 2h, owner 압력 429, 디스크 507 |
| `POST /upload/chunk/<id>` | `chunk_transfer` | owner 검증, index 범위, chunk/total 상한, 초과 시 세션 정리 |
| `POST /upload/chunk/<id>/complete` | `chunk_finalize` | 청크 집합 검증, 병합, 멱등 재완료, `upload_chunk_complete` 감사 |
| `POST /upload/chunk/<id>/cancel` | `cancel_chunk_upload` | 미존재도 success:true |
| `POST /share/create` (admin) | `create_share_link` | hours/max_downloads 범위, 보호경로 403 |
| `GET/POST /share/<token>` (공개) | `access_share_link` | 만료 410, 횟수초과 429, 비밀번호(폼/JSON), 파일/폴더ZIP, `?inline=1` |
| `GET /share/list`, `POST /share/delete/<t>` (admin) | 동일 | 만료 정리 후 반환 |

빈 subpath 404 매핑: Flask `<path:>` 컨버터 실측 결과(`delete`/`rename`/`unzip`/
`batch_delete`/`share/delete`에 적용, `mkdir`/`upload`는 양쪽 다 허용).

## 2. Contract 결과

- `tests/test_milestone_def_contract.py` **7/7 통과**: twin live 서버 쌍,
  per-backend 파일명으로 간섭 없이 상태·JSON·바이트 비교. RST 중복실행
  플레이크에는 효과-검증(`post_checked`)으로 대응.
- 기존 `test_milestone_b_parity.py` + `test_milestone_c_contract.py` **23/23**,
  Python 전체 **161 passed + 1 skipped** (회귀 없음), `go test ./...` 전 패키지 통과.
- 이 과정에서 잡힌 실제 parity 버그:
  - `CleanupOldVersions` 슬라이스 패닉 (Python은 범위 초과 슬라이스 허용).
  - 청크 index 범위 체크 누락 (초과분이 세션을 삭제하던 버그).
  - `resolveCopyMove` 반환 순서 역전, `fail` 정책 누락.
  - ETag 자릿수: Python `repr`는 정수 float에 `.0` 유지.

## 3. 결함 수정 (F)

- **ETag**: Werkzeug식 `"{mtime}-{size}-{adler32(path)}"`로 교체. mtime double은
  CPython `sec + rem/1e9`와 비트 동일 실측, adler 입력은 Python과 같은 경로 문자열
  (`send_file`은 validate 해소 경로, `send_from_directory`는 join 경로).
  Twin live 비교에서 ETag 바이트 일치 + `If-None-Match`(weak/`*`) 304 확인.
- **Range**: `If-Range` 지원 + **multi-range `multipart/byteranges` 206** 구현.
  의도적 차이: 동일 요청에 Python은 500 (Werkzeug가 multi에 416 → 핸들러 500),
  Go는 RFC 7233 정답 제공. 계약 테스트에 양쪽 기대값으로 고정.
- **NFC**: `golang.org/x/text/unicode/norm` 도입 (stdlib-only 예외 — 캐시 내
  `v0.42.0` 오프라인 해결, `go.mod` direct로 승격). 분해형 한글/결합문자 골든 테스트.
- **영속화**: 공유링크/공유-비밀번호시도(동기 저장), 감사(쓰로틀+종료 flush),
  다운로드쿼터·로그인차단(dirty+종료 flush). naive 로컬 시각으로 양 백엔드
  파일 호환. `app.FlushState()`를 serve 종료 시 호출.

## 4. 알려진 차이 (잔여)

- 공유 HTML 템플릿 미포트: 비밀번호 챌린지/실패 화면이 JSON
  (`need_password` 401 포함). `routes/templates.py`(216KB, importer 0)는
  `legacy/templates_v72.py`로 이동.
- 청크 세션·업로드 예약은 인메모리 (재시작 시 소멸 — Python도 동일).
- `search_mode: fallback` 유지, `track_download` 미사용 헬퍼는 미포트.
- 연령 초과 mtime(1e16년~)의 repr 지수 표기는 미대응 (현실 범위 외).

## 5. Gate

- Go: build/vet/test 통과 · Python: 전체/계약 통과 · 보안회귀: 기존 스위트 유지 ·
  데이터 영향: 공유 폴더 내 `.webshare_*.json` + 휴지통/버전/업로드temp만 기록.
