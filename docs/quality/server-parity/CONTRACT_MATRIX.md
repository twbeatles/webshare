# Contract Matrix (PAR / FT) -- expected vs actual live behavior

Oracle for every row: HTTP status + response meaning + file SHA-256 /
received bytes over real 127.0.0.1 servers. `N/A(계약상)` = documented
capability difference, asserted in tests (never a silent skip).

## PAR -- backend parity (tests/quality/test_live_backend_parity.py)

| ID | Flow | Python (live) | Go (live) | Verdict |
|---|---|---|---|---|
| PAR-01 | login→upload→download, 0B/1B/1KiB/1MiB + 한글/😀 이름 | bytes≡SHA | bytes≡SHA | PASS dual |
| PAR-02 | guest 업로드 403 / guest 읽기 200 / admin 허용 / 익명 거부 | 403/200/200/302 | 403/200/200/302 | PASS dual |
| PAR-03 | 공유 비번 폼→오답→정답 다운로드 + 횟수 정확 | 200 HTML/200/200+bytes, max 2→429 | same | PASS dual |
| PAR-04 | 만료/없음/한도소진 | 410/404/429, 0 bytes | 404/429 + 만료는 재시작 후 404 purge | PASS dual (표현은 문서화) |
| PAR-05 | Content-Disposition + UTF-8 + preview | disposition+preview 200 | disposition 동일, preview 404 | PASS + N/A(계약상) |
| PAR-06 | 중복 업로드 rename + rename 충돌 거부 | `_1` + 원본 불변, 400 | `_1` + 원본 불변 | PASS dual (+Python rename) |
| PAR-07 | 청크 역순/누락/중복/무효세션 | 동일 bytes / 400+무파일 / 성공 / 400 | 역순 동일 bytes | PASS dual+단일 |
| PAR-08 | traversal 8종 + 절댓경로 + symlink | 0 leak | 0 leak | PASS dual |
| PAR-09 | 휴지통 이동→목록→복원 | bytes≡ + original_path | bytes≡ + original_path | PASS dual |
| PAR-10 | 재시작 후 파일/공유/권한 | 유지 | Go 재시작은 FT-10에서 별도 검증 | PASS (Python) |
| PAR-11 | Go+HTTPS 거절, backend 선택, Go preview 부재 | 거절 PASS | N/A(계약상): preview/template/healthz 없음 | PASS (거절=기대값) |
| PAR-12 | Docker=Python 스택 명시 | 소스 계약 PASS | 해당 없음 | PASS |

GAP-1 해소: Go 만료도 live 검증됨
(`test_par04_go_share_expiry_via_persisted_store`). Go는 기동 시
`.webshare_share_links.json`을 읽으며 이미 만료된 링크를 purge하므로,
재시작 후 접근은 404 + 무바이트 + 목록에서 영구 제거된다. 실행 중 만료는
양 백엔드 모두 410 (Python live, Go는 `go-core` 단위 테스트가 `Access`
410 분기 보유). 주의: Go의 naive 시각 파싱은 UTC 기준이므로 테스트는
UTC로 이틀 전 시각을 주입해 타임존 skew를 제거했다.

## FT -- 장애/재시작/정합성 (test_live_fault_recovery.py)

| ID | Fault | 요구 결과 | 실제 |
|---|---|---|---|
| FT-01 | 청크 1개 후 cancel / 재시작 | 미완성·세션 무효, 파일 없음 | PASS |
| FT-02 | COMPLETING 중 cancel/complete + 재호출 | 409/409 후 정확히 1회 완성, 재호출 멱등·무중복 | PASS |
| FT-03 | os.replace 직전 실패 주입 | 원본 SHA 보존, merge temp 정리 | PASS |
| FT-04 | 커밋 후 재시작 | 완성 파일 유효·접근 가능 | PASS |
| FT-05 | 휴지통 메타 소실 | 목록/복원 self-heal, 무손실 | PASS |
| FT-06 | 복원 충돌 | 기존 대상 보존 + 별도 안전명, 바이트 미혼합 | PASS |
| FT-07 | max=2 공유 5-스레드 | 파일 바이트 정확히 2회, 우회 0 | PASS |
| FT-08 | 손상 JSON/무효 UTF-8 설정 | 타임스탬프 백업 + 폴백, 무음 초기화 없음 | PASS |
| FT-09 | Zip Slip / 정상 ZIP | 외부 추출 0 + 400 / 정상 추출 | PASS |
| FT-10 | Go 자식 kill → 재기동 | 고아 0, 동일 root 재서빙 | PASS |
| FT-11 | overwrite 스냅샷 → 버전 복원 | v1 바이트 정확 복원, bogus 거부·불변 | PASS |
| FT-12 | rename→delete→복원 순서 모델 | 404는 404(403 마스킹 없음), 최종 바이트 일치 | PASS |

## Security (test_live_security_boundary.py)

- 변이 8종 × 익명/게스트/관리자: 게스트 403, 익명은 302/401/403 중
  하나로 거부·무바이트, 관리자는 허용. PASS
- 이중 인코딩·백슬래시·절댓경로 (dual), ZIP 멤버명 3종: 0 escape. PASS
- 공유 비번 5회 오답 → 429 차단, 정답도 차단 기간 중 거부. PASS
- `.webshare*` 보호 경로 공유/휴지통 거부. PASS
- 공유 응답·목록·감사로그에 평문 비번/전체 토큰 미노출. PASS
