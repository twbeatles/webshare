# Server-Parity Baseline (Phase 0)

> Recorded 2026-10-15. All commands below ran on this machine unless noted.

## Commit / versions

- HEAD: `ec9d922a2252b9e827634f4888c9a1a0de3d98ed` (2026-10-14,
  chore: sync README exe refs to 7.4.3)
- App version (`config.APP_VERSION`): 7.4.3
- Python 3.15.0 / Flask 3.1.3 / Werkzeug 3.1.9 / Flask-Compress 1.25
- Go go1.27.0 windows/amd64
- Go binary `go-core/webshare-core.exe` SHA-256:
  `3634e2de7d0f81cb6bc9992b31042599bcb7194e02232697e8f081753e974540`

## Supported capabilities (verified in code + live)

- Python backend: full routes (browse/upload/chunk/share/trash/versions/
  metadata/unzip/preview/stream/WebDAV-mount when wsgidav installed).
- Go backend (`webshare-core serve -host/-port/-config`): login, list,
  file_info, download, zip, upload + chunk init/transfer/complete/cancel,
  mkdir/delete/rename/copy/move, trash move/list/restore, versions
  list/restore, share create/list/delete/access (+HTML pages), tags/
  favorites/memo/bookmarks, audit, disk, WebDAV? no -- Go has NO
  `/preview/`, `/stream/`, browse HTML, `/healthz`, `/readyz`.
  Logged-out `GET /` is 401 JSON; anonymous browser downloads 302.
- Refusals (by design, tested): Go + HTTPS (`GO_HTTPS_BLOCKED`),
  `start_server(use_https=True)` with Go backend returns False.

## Existing coverage (not duplicated)

- `tests/test_backend_parity_contract.py`: hermetic (no live servers).
- `go-core/internal/handlers/*_test.go`: Go handler unit tests.
- Milestone B/C/DEF contract tests: excluded from CI fast subset,
  run in Release workflow.
- CI `ci.yml` (fast): Go build/vet/test, packaging check, pyright,
  pytest minus milestone B/C/DEF. Release: full pytest + Go + EXE
  smoke + signed manifest.
- Last known green (from plan): CI run 38557650270, Release
  run 38557659248 (2026-10-14).

## Gaps this hardening closes

1. No test ever drove two REAL servers (loopback HTTP) and compared
   bytes -- now `tests/quality/` (58 tests): PAR dual-backend parity,
   FT fault injection, security boundaries, M1..M10 detectors.
2. Chunk COMPLETING/cancel race, restart durability, corrupt-config
   behavior, quota exactness under concurrency -- now covered live.
3. Mutation killing power unproven -- now 10/10 KILLED with evidence.

## Environment findings (this machine, abilites/limits)

- Python-sourced HTTP responses without `Content-Encoding` fall back to
  length-less chunked (Flask-Compress 1.25 passthrough) and stall past
  ~64 KiB on loopback here (stock `http.server` too; Go unaffected).
  The harness therefore negotiates `Accept-Encoding: gzip` like a real
  browser and decodes. 1 MiB round-trips verified on both backends.
- Capped-share losers that pass the stale pre-check but lose the atomic
  reserve get the agreed `200 + share_expired.html` page on BOTH
  backends (Go `shareFail(..., StatusOK, ...)` mirrors it). File bytes
  never exceed `max_downloads` (FT-07/M5). Documented, not "fixed",
  to preserve parity and client behavior.
