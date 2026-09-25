# go-core

Go HTTP server core for WebShare Pro (MUSE migration, Milestones A–J).
Go is the default backend since Milestone J (`WEBSHARE_SERVER_BACKEND`
unset means `go`); `WEBSHARE_SERVER_BACKEND=python` keeps the legacy Python
backend. Go runs via `webshare_app/server/go_process.py` (subprocess +
per-run token) with automatic Python fallback when Go fails to start.

## Commands

```text
webshare-core serve [--config PATH] [--host H] [--port N] [--parent-pid PID]
webshare-core version
webshare-core check-config [--config PATH]
```

## Packages

| Package | Python origin |
|---|---|
| `internal/auth` | session codec, CSRF, passwords, IP blocks (+ `.webshare_login_attempts.json`) |
| `internal/config` | ConfigManager schema (read as-is, unknown keys preserved) |
| `internal/permission` | path validation, permissions, capabilities |
| `internal/files` | listing, download (Werkzeug ETag/Range/multipart), ZIP, search fallback, NFC `SafeFilename` |
| `internal/mutate` | mkdir/delete/rename/copy/move/batch/unzip ops, trash, versions, atomic IO |
| `internal/upload` | simple upload target/disk-reserve, chunk sessions |
| `internal/share` | share links (+ `.webshare_share_links.json`, password-attempt guard) |
| `internal/audit` | audit log (+ `.webshare_audit.json`) |
| `internal/quota` | download quota (+ `.webshare_download_tracker.json`) |
| `internal/handlers` | all user routes (login, list, files, mutation, upload, share) |
| `internal/server` | health/readiness/control endpoint, middleware |
| `cmd/testprobe` | TEST-ONLY helper for `tests/test_milestone_b_parity.py` |

Runtime state files live in the shared folder with naive local timestamps so
Python and Go read each other's files. `app.FlushState()` (called on
shutdown in `cmd/webshare-core`) flushes quota/blocks/share-attempts/audit.

## Dependencies

- Standard library only, except `golang.org/x/text` (NFC normalization in
  `SafeFilename`, parity with `unicodedata.normalize("NFC", ...)`).

## Verify

```bash
cd go-core
go test ./...
go vet ./...
go build -o webshare-core.exe ./cmd/webshare-core
./webshare-core check-config --config ../webshare_config.json
```

Live parity: `tests/test_milestone_{b,c,def}_contract.py` (twin Python/Go servers).
Known deliberate deviation: multi-range requests — Python 500s (Werkzeug
raises 416 for multi), Go serves RFC 7233 `multipart/byteranges` 206.
Share HTML templates have no port: access failures/password challenge are JSON.
