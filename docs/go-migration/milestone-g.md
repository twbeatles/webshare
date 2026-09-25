# Milestone G — Core APIs + Python-only 확정 (완료)

사용자 결정: 파일 핵심 API만 이식, 나머지는 Python-only로 문서화.

## 1. 이식된 Core API (live contract 검증)

| 라우트 | Python 원본 |
|---|---|
| `POST /trash`, `GET /trash/list`, `POST /trash/restore`, `POST /trash/empty`, `POST /api/trash/cleanup` | `trash_routes.py` (+`restore_from_trash`, `auto_cleanup_trash`) |
| `GET/POST/DELETE /api/tags`, `/api/favorites`, `/api/memo/<p>`, `/bookmarks` | `metadata_routes.py` (+`.webshare_meta.json`) |
| `GET /versions/<p>`, `POST /versions/restore` | `restore_version` (복원 전 현본 백업, 원자적 교체) |
| `GET /api/audit_log` (필터/페이징), `GET /api/audit_log/export` (BOM CSV) | `admin_routes/audit.py` |
| `GET /api/capabilities`, `/api/disk_info`, `/api/disk_status`, `/api/folder_size/<p>` | `api_routes.py` |

- `capabilities`는 전부 `false` (ffmpeg/WebDAV/UPnP/doc/psutil/qrcode 미탑재 — 정직한 보고).
- 버전 스탬프 결함 수정: Go가 `..._000000` 고정 접미사를 쓰던 버그 →
  Python과 동일한 `%Y%m%d_%H%M%S_%f` 실측 마이크로초로 교체 (동일 초 충돌 해소).
- 버전 복원은 `copy2` 대신 원자적 교체 (개선점, 문서화).
- Contract: `tests/test_milestone_def_contract.py`에 trash/metadata/versions/audit/system 3개 테스트 추가.

## 2. Python-only 확정 목록 (Go 미지원)

- **검색 인덱서**: `/api/indexer/status`, 전체 텍스트 인덱스/워처
  (Go `/search`는 파일명 폴백 유지).
- **중복 찾기**: `/api/duplicates*` 4종.
- **미디어**: `/stream/*`, HLS (`index.m3u8`/세그먼트), 트랜스코더/ffmpeg,
  썸네일/플레이리스트/갤러리/미리보기, 텍스트 편집(get/save_content).
- **WebDAV 서버**, **클라우드 동기화**(`/api/cloud/*` 8종, Google Drive),
  **UPnP**(`/api/network/upnp/*` 3종).
- **관리/대시보드**: `/api/metrics`, `/dashboard/summary`, `/active_sessions`,
  `/recent_files`, `/blocked_ips`, `/unblock/*`, `/security/status`,
  `/api/audit_log/clear`, permissions/users/system_stats/access_dashboard,
  trash_settings/cleanup_trash(admin), encrypt/decrypt, clipboard, PWA 3종,
  browse HTML 페이지.
- These routes return the Go normalized 404 (`NOT_FOUND`) when the Go backend
  is active; use `WEBSHARE_SERVER_BACKEND=python` for them (§57 fallback).

## 3. Gate

- Go: build/vet/test · Python: 전체 스위트 · 계약: DEF 확장 포함.
