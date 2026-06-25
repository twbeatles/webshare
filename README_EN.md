# WebShare Pro v7.2.4

A Flask/PyQt file server for safely sharing and managing local files through a web browser.

[![Version](https://img.shields.io/badge/version-7.2.4-blue?style=flat-square)](https://github.com/twbeatles/webshare)

[한국어](README.md)

## Features

- File/folder browsing, upload, download, ZIP download, copy, move, delete
- Chunked uploads up to 10GB and atomic file replacement
- Admin/Guest roles, per-folder `read/write/delete` permissions, CSRF protection
- PBKDF2 password storage with automatic plaintext/SHA256 migration after successful legacy login
- Share links with expiration, optional password, download limits, and attachment-first file delivery
- Tags, memos, favorites, trash, version backups, duplicate scans
- Manual Google Drive upload/download sync with persisted job state
- Optional HLS streaming, WebDAV, UPnP, document previews, and system stats through runtime capability detection
- PWA manifest/service worker with an offline fallback

## v7.2.4 Security And Consistency Changes

- Replaced user-data inline JavaScript in file lists and key dynamic lists with `data-*` attributes and event delegation.
- Sanitized every Google Drive remote path segment and revalidated the final save path under the shared root.
- Kept only non-secret cloud state in `.webshare_cloud.json`; OAuth secrets and tokens are stored in an app config secret file.
- Persisted download quota, login failure, and share-link password failure state as JSON.
- Made regular uploads, chunk merge, and overwrite copy/move complete through temp files or staging paths before replacement.
- Added upload disk-space preflight checks that account for active upload reservations before accepting data.
- Version copy/move overwrite and version restore targets before replacement.
- Safely escaped OAuth popup result pages and encoded special-character path URLs.
- Applied `Cache-Control: no-store` to HTML/API responses and removed authenticated HTML from the service-worker install cache.
- Load Font Awesome, marked, DOMPurify, hls.js, and highlight.js from local vendor assets first, with CDN fallback only.
- Added metadata length/color validation and CSP/sandbox-style headers for SVG thumbnails.

## Post-Audit Remediations (2026-06-25)

Implemented phase 1–2 items from `PROJECT_AUDIT.md`:

- Serialized JSON persistence snapshots (`webshare_app/core/persistence.py`)
- Persistent Flask `secret_key` under the app config dir (`WEBSHARE_CONFIG_DIR/secret_key`)
- Default-password / public-bind warnings plus `GET /api/security/status` (admin)
- `validate_path` checks for drag-and-drop folder upload paths
- Idempotent chunk `complete`, 256KB clipboard cap, share ZIP disk preflight
- Regression tests in `tests/test_audit_remediations.py` (full suite: `113 passed, 1 skipped`)

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Install optional features with:

```bash
pip install -r requirements-optional.txt
```

On Python 3.14, `miniupnpc` is excluded from the default optional install. In that case only UPnP capability is disabled; the server, GUI, file sharing, and PyInstaller packaging continue to work.

For development and verification:

```bash
pip install -r requirements-dev.txt
pytest -q --basetemp .pytest_tmp
pyright
```

HLS transcoding requires the `ffmpeg` executable on PATH. The Docker image installs `ffmpeg`.

## Project Structure

Runtime implementation lives under the `webshare_app/` package.

- `webshare_app/app`, `webshare_app/server`: Flask app creation, WSGI composition, server thread lifecycle, runtime cleanup
- `webshare_app/routes`, `webshare_app/services`: Blueprint endpoints plus file, upload, share, media, and cloud service logic
- `webshare_app/core`, `webshare_app/features`, `webshare_app/security`, `webshare_app/gui`: config/state, feature modules, security, desktop GUI
- `templates/base.html`, `templates/partials/`, `static/css/app.css`, `static/js/`: Jinja layouts/partials and separated static UI assets
- Top-level `server.py`, `config.py`, `routes/`, `features/`, `utils/`, `security/`, and `gui/` are compatibility wrappers for existing imports.

## Run

```bash
python main.py
```

Default URL: `http://localhost:5000`

Default passwords:

| Role | Default |
|---|---|
| Admin | `1234` |
| Guest | `0000` |

The GUI password inputs never display existing hashes; they only save a new password when a new value is entered.

Google Drive Client Secret follows the same rule. Saving a blank secret preserves the existing value; selecting the clear checkbox explicitly removes it.

## Deployment And Security Notes

- Runtime state assumes a **single process** with Werkzeug's threaded server. Multi-worker deployments (e.g. gunicorn) are not supported.
- Behind a reverse proxy, configure `trusted_proxies` and `trusted_hops` correctly. Misconfiguration can weaken IP-based rate limits.
- Flask `secret_key` is auto-created and reused under the app config directory, not inside the shared folder.
- Dropbox sync (`/api/cloud/sync/dropbox`) returns `501 placeholder`; only Google Drive manual sync is implemented.
- Binding to `0.0.0.0` with default passwords is unsafe. Docker logs a warning; admins can inspect `GET /api/security/status`.

## Docker

```bash
docker compose up -d
```

The Dockerfile installs `ffmpeg` for HLS support.

Do not keep default passwords when binding Docker to a public interface.

```bash
$env:WEBSHARE_ADMIN_PASSWORD="change-me-admin"
$env:WEBSHARE_GUEST_PASSWORD="change-me-guest"
$env:WEBSHARE_SECRET_KEY="change-me-session-secret"
docker compose up -d
```

## Build

The PyInstaller specs read `APP_VERSION` from `webshare_app/core/config.py` and name outputs as `WebSharePro_v7.2.4.exe`. `WebSharePro.spec` and `webshare.spec` are kept in sync for runtime modules, templates, and static/vendor assets.

```bash
python -m PyInstaller --clean --noconfirm WebSharePro.spec
```

Before distribution, you can smoke-test the generated EXE without opening the GUI. The check uses a temporary shared folder, initializes runtime state, verifies `/healthz`, `/readyz`, and bundled static asset loading, and returns exit code `0` on success.

```powershell
.\dist\WebSharePro_v7.2.4.exe --smoke
```

The compatibility spec name uses the same build configuration:

```bash
python -m PyInstaller --clean --noconfirm webshare.spec
```

## API

Representative endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | liveness |
| `GET` | `/readyz` | readiness |
| `GET` | `/api/list/<path>` | file listing |
| `GET` | `/api/capabilities` | optional feature detection |
| `GET` | `/api/security/status` | deployment safety warnings (admin) |
| `POST` | `/api/cloud/sync/google_drive` | manual Google Drive sync |
| `GET/POST` | `/share/<token>` | share-link access |

`/api/capabilities` example:

```json
{
  "hls": true,
  "webdav": false,
  "upnp": false,
  "doc_preview": {
    "docx": true,
    "xlsx": true,
    "pptx": false
  },
  "system_stats": true,
  "qrcode": true
}
```

## Data And Secret Storage

`.webshare_*.json` files inside the shared folder store app state such as permissions, audit logs, share links, and runtime counters.

Google Drive secrets and tokens are stored outside the shared folder:

- Windows: `%APPDATA%/WebSharePro/secrets/cloud_secrets.json`
- Linux/macOS: `~/.config/websharepro/secrets/cloud_secrets.json`

Tests and automation can override the app config directory with `WEBSHARE_CONFIG_DIR`. The Flask `secret_key` is persisted as `secret_key` in that directory.

## Git Hygiene

`.gitignore` excludes:

- Shared folders and `.webshare_*.json/.tmp`, `.webshare_trash/`, `.webshare_versions/`, `.webshare_thumbs/` runtime state
- External secret filenames (`cloud_secrets.json`)
- PyInstaller outputs (`build/`, `dist/`, `*.toc`, `*.pkg`, `*.manifest`)
- Test/cache/virtual-environment artifacts

`static/vendor/` is intentionally tracked so packaged and offline runs can load bundled UI assets.

## Verification Baseline

- `pytest -q --basetemp .pytest_tmp` -> `113 passed, 1 skipped`
- `pyright` -> `0 errors, 0 warnings`

## License

MIT License
