# WebShare Pro v7.2.1

<div align="center">

![WebShare Pro Logo](https://img.shields.io/badge/WebShare-Pro-6366f1?style=for-the-badge&logo=server&logoColor=white)

**All-in-one file server for sharing local files via web browser**

[![Version](https://img.shields.io/badge/version-7.2.1-blue?style=flat-square)](https://github.com)
[![Python](https://img.shields.io/badge/python-3.8+-green?style=flat-square)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.0+-orange?style=flat-square)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)

[한국어](README.md) | **English**

</div>

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

### File Management
- Upload/Download with drag-and-drop support
- Automatic chunked upload for large files (up to 10GB)
- Folder create/rename/delete and ZIP download
- Real-time file name search with index + filesystem fallback
- Batch operations for multi-select actions

### Security
- Role-based access control (Admin/Guest)
- PBKDF2-SHA256 password hashing
- Global CSRF validation for state-changing requests
- IP blocking after repeated failed logins
- AES-GCM(v2) file encryption with legacy CBC decrypt compatibility
- XSS hardening for Markdown and file-info previews

### Sharing
- Share links with optional password, expiration, and download limit
- Persistent share link store (`.webshare_share_links.json`)
- QR code generation for mobile access

### Advanced Features
- Trash and restore workflow (with auto cleanup)
- File versioning and backup snapshots
- Tags/notes and favorites
- Session-scoped recent files tracking
- Duplicate scan by SHA256 hash
- Per-folder permissions (read/write/delete) plus guest mutation control via `allow_guest_upload`
- Audit log persistence
- Drag-and-drop move
- PDF/Markdown preview
- Multi-tab browsing
- Manual Google Drive upload/download sync
- Manual UPnP port mapping

### v7.2.3 Update
- Real-time transcoding and HLS streaming
- PWA support (`manifest.json`, installable shell)
- Network utilities (UPnP, WebDAV)
- Docker support (`Dockerfile`, `docker-compose.yml`)
- Additional security hardening (XSS/PKCS7/path protections)

> Note: `/api/users` management is currently decoupled from the active login model (`admin_pw` / `guest_pw`).

---

## Installation

### Requirements
- Python 3.8+
- pip

### 1. Clone
```bash
git clone https://github.com/your-repo/webshare.git
cd webshare
```

### 2. Install dependencies
```bash
# Required
pip install flask werkzeug pillow cryptography

# GUI (recommended)
pip install pyqt6

# Optional
pip install qrcode
pip install python-docx
pip install openpyxl
pip install python-pptx
pip install miniupnpc
pip install wsgidav cheroot
pip install flask-compress cachetools
pip install orjson

# FFmpeg must be installed on your system and available in PATH
```

### 3. Run
```bash
python main.py
```

### 4. Build EXE
```bash
pyinstaller webshare.spec
# Output: dist/WebSharePro_v7.2.1.exe
```

### 5. Docker
```bash
docker compose up -d
```

- Default port: `5000`
- Volume: `./shared_files -> /data`
- Entrypoint: `docker_entrypoint.py`

---

## Usage

### Quick Start
1. Run `python main.py`.
2. Configure shared folder, port, and passwords in GUI.
3. Start server.
4. Open `http://localhost:5000` (or displayed LAN IP) in browser.

### Default Credentials
| Account | Password | Permission |
|---|---|---|
| Admin | `1234` | Full |
| Guest | `0000` | Read-only |

---

## Keyboard Shortcuts

### Navigation
| Shortcut | Action |
|---|---|
| Arrow Up / Arrow Down | Move selection |
| Enter | Open file / enter folder |
| Backspace | Go to parent folder |
| Ctrl + A | Select all |
| Esc | Deselect / close modal |

### File Actions
| Shortcut | Action |
|---|---|
| Delete | Delete selected files |
| F2 | Rename |
| Ctrl + C | Copy |
| Ctrl + X | Cut |
| Ctrl + V | Paste |

### Other
| Shortcut | Action |
|---|---|
| Ctrl + N | New folder |
| Ctrl + U | Upload |
| Ctrl + F | Search |
| Ctrl + T | New tab |
| G | Toggle list/grid view |
| D | Toggle dark mode |
| ? | Shortcut help |

---

## Configuration

### `webshare_config.json`
```json
{
  "folder": "C:\\Users\\User\\shared_files",
  "port": 5000,
  "admin_pw": "1234",
  "guest_pw": "0000",
  "allow_guest_upload": false,
  "display_host": "0.0.0.0",
  "session_timeout": 60,
  "enable_versioning": true,
  "language": "en",
  "ip_whitelist": [],
  "daily_download_limit": 0,
  "daily_bandwidth_limit_mb": 0,
  "disk_warning_threshold": 90,
  "trusted_proxies": [],
  "trusted_hops": 1,
  "webdav_allow_insecure": false
}
```

### Key Options
| Key | Description | Default |
|---|---|---|
| `folder` | Shared folder path | `./shared_files` |
| `port` | Server port | `5000` |
| `admin_pw` | Admin password | `1234` |
| `guest_pw` | Guest password | `0000` |
| `allow_guest_upload` | Allow guest upload | `false` |
| `session_timeout` | Session timeout (minutes) | `60` |
| `language` | UI language (`ko`/`en`) | `ko` |
| `ip_whitelist` | Allowed IP list (empty = allow all) | `[]` |
| `daily_download_limit` | Daily download limit | `0` (unlimited) |
| `daily_bandwidth_limit_mb` | Daily bandwidth limit in MB | `0` (unlimited) |
| `trusted_proxies` | Trusted proxy IP list | `[]` |
| `trusted_hops` | Trusted proxy hop count | `1` |
| `webdav_allow_insecure` | Allow non-TLS WebDAV write methods | `false` |

---

## API Endpoints

### Authentication
| Method | Path | Description |
|---|---|---|
| `POST` | `/` | Login |
| `GET` | `/logout` | Logout |
| `POST` | `/set_language` | Standard language API (`{"lang":"ko|en","csrf_token":"..."}`) |
| `GET` | `/set_language/<lang>` | Legacy compatibility wrapper (Sunset: 2026-08-31) |

### File Management
| Method | Path | Description |
|---|---|---|
| `GET` | `/browse/<path>` | Browse folder |
| `GET` | `/download/<path>` | Download file |
| `POST` | `/upload/<path>` | Upload file |
| `POST` | `/mkdir/<path>` | Create folder |
| `POST` | `/rename/<path>` | Rename |
| `POST` | `/delete/<path>` | Delete |
| `POST` | `/copy` | Copy |
| `POST` | `/move` | Move |
| `GET` | `/zip/<path>` | Download folder as ZIP |

### v7.2 API
| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness check |
| `GET` | `/readyz` | Readiness check |
| `GET` | `/api/list/<path>` | Paginated directory listing |
| `GET` | `/api/dashboard/summary` | Dashboard summary |
| `GET` | `/api/indexer/status` | Search indexer status |
| `GET` | `/api/active_sessions` | Active sessions (admin only) |
| `GET` | `/api/audit_log` | Audit logs |
| `GET/POST` | `/api/permissions` | Folder permissions |
| `GET` | `/api/duplicates` | Duplicate files |
| `POST` | `/api/duplicates/scan` | Start duplicate scan |
| `GET` | `/api/cloud/config` | Read cloud sync config |
| `POST` | `/api/cloud/config` | Save cloud sync config |
| `GET` | `/api/cloud/status` | Cloud sync status and latest job |
| `GET` | `/api/cloud/google_drive/auth/start` | Start Google Drive OAuth |
| `GET` | `/api/cloud/google_drive/auth/callback` | Google Drive OAuth callback |
| `POST` | `/api/cloud/google_drive/disconnect` | Disconnect Google Drive |
| `POST` | `/api/cloud/sync/google_drive` | Start Google Drive sync job |
| `GET` | `/api/cloud/jobs/<job_id>` | Get cloud job status |
| `GET` | `/api/network/upnp/status` | Read UPnP status |
| `POST` | `/api/network/upnp/map` | Create manual UPnP mapping |
| `POST` | `/api/network/upnp/unmap` | Remove manual UPnP mapping |

### Chunk Upload API
| Method | Path | Description |
|---|---|---|
| `POST` | `/upload/chunk/init` | Create chunk session |
| `POST` | `/upload/chunk/<session_id>` | Upload single chunk |
| `POST` | `/upload/chunk/<session_id>/complete` | Validate and merge chunks |
| `POST` | `/upload/chunk/<session_id>/cancel` | Cancel upload session |

### Media/Network API
| Method | Path | Description |
|---|---|---|
| `GET` | `/stream/hls/<path>/index.m3u8` | HLS playlist |
| `GET` | `/webdav/` | WebDAV endpoint |
| `GET` | `/manifest.json` | PWA manifest |

### Security Notes
- CSRF is required for all logged-in state-changing requests.
- Hidden/system paths like `.webshare*` are blocked across download/stream/preview/WebDAV paths.
- Non-TLS WebDAV write methods are blocked by default.
- `/api/active_sessions` is admin-only.
- Share-link inputs such as `hours` and `max_downloads` are validated.
- Audit logs/share links are persisted in JSON files.
- `/stream/*` and HLS playback do not consume the `daily_download_limit` count quota; they still consume `daily_bandwidth_limit_mb`.
- Markdown preview is sanitized before rendering, so some raw HTML may no longer render verbatim.

---

## Project Structure

```text
(repo root)/
|-- main.py
|-- config.py
|-- i18n.py
|-- server.py
|-- utils/
|-- security/
|-- features/
|   |-- audit_log.py
|   |-- share_links_store.py
|   |-- network.py
|   |-- webdav_server.py
|   `-- transcoder.py
|-- routes/
|   |-- main_routes.py
|   |-- file_routes.py
|   |-- cloud_routes.py
|   |-- network_routes.py
|   `-- pwa_routes.py
|-- templates/
|   |-- index.html
|   |-- share_password.html
|   `-- share_expired.html
|-- static/
|   `-- js/
|       |-- app-core.js
|       |-- app-modals.js
|       `-- app-upload.js
|-- gui/
|-- legacy/
|   `-- 웹서버 프로그램v4.py
|-- scripts/
|   |-- generate_dataset.py
|   `-- perf_bench.py
|-- tests/
|-- webshare.spec
|-- WebSharePro.spec
|-- pyrightconfig.json
|-- typings/
|   `-- cachetools/
|       `-- __init__.pyi
|-- Dockerfile
|-- docker-compose.yml
`-- docker_entrypoint.py
```

---

## Troubleshooting

### Server does not start
```text
Error: Address already in use
```
Solution: Change the port in settings.

### `PyQt6` import error
```text
ModuleNotFoundError: No module named 'PyQt6'
```
Solution: `pip install pyqt6`

### Large upload fails
- Files larger than 100MB use chunked upload.
- Retry is supported for unstable networks.
- Maximum file size is 10GB.

### Cannot connect from external network
1. Open the server port in firewall.
2. Configure router port forwarding.
3. Set `display_host` to `0.0.0.0`.

---

## License

MIT License

Copyright (c) 2026 WebShare Pro

---

## Implementation Alignment (2026-02-28)
- Security/consistency plan items implemented:
  - Symlink-safe path validation in `validate_path`
  - Chunk upload ownership + size/concurrency limits
  - Atomic reserve/rollback for share-link `max_downloads`
  - Same composed WebDAV WSGI mount path in normal and Docker runtime
  - Startup cleanup for `.webshare_uploads` and recursive `.upload_temp`
- Cloud Sync now has a real Google Drive implementation only.
  - Upload/download are manual one-way jobs.
  - Dropbox remains a placeholder in the UI/API and does not perform real sync.
- Build spec consistency:
  - Both `webshare.spec` and `WebSharePro.spec` now align output naming to `WebSharePro_v{APP_VERSION}` from `config.py`.

## Implementation Notes (2026-03-05)

- JSON error responses are standardized to:
  `{ "success": false, "error": "...", "code": "ERROR_CODE", "message": "...", "request_id": "..." }`
- Backward compatibility is kept by preserving the `error` field while adding `code`, `message`, and `request_id`.
- Metadata list APIs now return only readable paths for the current requester:
  - `GET /api/tags` (all tags mode)
  - `GET /api/favorites`
  - `GET /bookmarks`
- Text editor APIs enforce a 10MB limit and return `413` when exceeded:
  - `GET /get_content/<path>`
  - `POST /save_content/<path>`
- Chunk upload hardening:
  - Actual chunk bytes must be `<= chunk_size`
  - Cumulative uploaded bytes must be `<= total_size`
  - Violations immediately clean up the upload session
- Batch ZIP download now performs a pre-check of download limits before ZIP creation, then re-checks after ZIP creation for race safety.
- PyInstaller specs include `utils.api_errors` in `hiddenimports` to keep the standardized API error utility bundled in frozen builds.
- `.gitignore` now excludes WebShare runtime temp artifacts (`.webshare_*.tmp`, `.webshare_*.json`) and transient upload/transcode directories.

## Implementation Notes (2026-03-09)

- Added `pyrightconfig.json` so static analysis is scoped to active app code and tests, while archived `legacy/` code is excluded.
- Added typed overloads to `ConfigManager.get()` in `config.py` so Pylance/Pyright can infer concrete types for the main configuration keys.
- Added a local stub at `typings/cachetools/__init__.pyi` and aligned `pyrightconfig.json` to silence external source-resolution noise, eliminating the remaining `cachetools` warnings without changing runtime behavior.
- Because `features.network` and `features.webdav_server` now load optional dependencies through `importlib`, both `webshare.spec` and `WebSharePro.spec` now explicitly include `miniupnpc` and `wsgidav.*` hidden imports for frozen builds.
- Verification baseline:
  - `pyright` -> `0 errors, 0 warnings`
  - `pytest -q` -> `44 passed, 1 skipped`

## Implementation Notes (2026-03-17)

- Frontend security alignment:
  - The editor Markdown preview and the standalone Markdown preview now share a sanitize-first rendering path.
  - File-info modal fields such as file name, path, MIME type, and MD5 are escaped before HTML rendering.
- Download/streaming policy alignment:
  - Only logical downloads (direct download, ZIP, batch ZIP, single-file share download) increment the download-count quota.
  - Range streaming and HLS playlist/segment requests accrue bytes without incrementing the count quota.
  - Recent files are now session-scoped and populated from download, text read, stream start, and HLS playlist start.
- Backend/runtime alignment:
  - `main.py` no longer performs Windows DPI initialization at import time on non-Windows platforms.
  - Non-Windows HLS transcoder processes now run in an isolated session and cleanup targets only that session.
  - ZIP extraction never merges into an existing directory; collisions extract into `name_1`, `name_2`, and so on.
  - Version backups now use a filename format that includes an encoded relative path, while legacy backup listing/restore compatibility remains intact.
  - Config, metadata, permissions, share-links, cloud config, and audit persistence paths now use `os.replace()` for atomic writes.
  - Config loading validates persisted values through `ConfigManager.set()` and falls back safely on invalid values.
- 2026-03-25 alignment:
  - Guest mutations are allowed only when `allow_guest_upload=true`, and then only where folder permissions permit them.
  - `/search` now falls back while indexing and returns `indexing` plus `search_mode`.
  - GUI/Tk start state switches to running only after actual bind/readiness succeeds.
  - Google Drive OAuth/job status and manual UPnP APIs are now available.
- Latest verification baseline:
  - `pytest -q --basetemp .pytest_tmp` -> `64 passed, 1 skipped`
