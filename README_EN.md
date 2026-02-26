# WebShare Pro v7.2

<div align="center">

![WebShare Pro Logo](https://img.shields.io/badge/WebShare-Pro-6366f1?style=for-the-badge&logo=server&logoColor=white)

**All-in-one file server for sharing local files via web browser**

[![Version](https://img.shields.io/badge/version-7.2.3-blue?style=flat-square)](https://github.com)
[![Python](https://img.shields.io/badge/python-3.8+-green?style=flat-square)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.0+-orange?style=flat-square)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)

[한국어](README.md) | **English**

</div>

---

## 📖 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Keyboard Shortcuts](#-keyboard-shortcuts)
- [Configuration](#-configuration)
- [API Endpoints](#-api-endpoints)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## ✨ Features

### 🗂️ File Management
- **Upload/Download** - Drag & drop support, chunked upload for large files (up to 10GB)
- **Folder Management** - Create, rename, delete, ZIP download
- **File Search** - Real-time filename search
- **Batch Operations** - Multi-select for batch download/delete

### 🔒 Security
- **Role-based Access Control** - Admin/Guest separation
- **PBKDF2-SHA256 Encryption** - Secure password storage
- **CSRF Token Protection** - All POST requests verified
- **IP Blocking** - 15-minute block after 5 failed login attempts
- **AES-256 File Encryption** - Individual file encryption/decryption

### 🔗 Sharing
- **Share Links** - Password protection, expiration time, download limits
- **QR Code** - QR code generation for mobile access

### 📁 Advanced Features
- **Trash** - Deleted file storage, restore, auto-empty (30 days)
- **Version Control** - Auto backup on file modification (up to 5 versions)
- **Tags/Notes** - Add tags and notes to files
- **Favorites** - Bookmark frequently accessed folders

### 🆕 v7.2 New Features
- **🔍 Duplicate Detection** - SHA256 hash-based duplicate file detection
- **🔐 Folder Permissions** - Per-folder read/write/delete permissions
- **📋 Audit Log** - Complete file operation history
- **🖱️ Drag & Drop Move** - Drag files to folders to move
- **📄 PDF/Markdown Preview** - pdf.js, marked.js integration
- **⌨️ Keyboard Shortcuts** - Quick file navigation and operations
- **📑 Multi-tab Support** - Open multiple folders simultaneously
- **☁️ Cloud Sync** - Google Drive/Dropbox integration ready

### 🆕 v7.2.3 Mega Update
- **🎬 Real-time Transcoding** - HLS streaming for MKV, AVI via FFmpeg
- **📱 PWA Support** - Installable app (Desktop/Mobile), offline shell
- **🔌 Network Utilities** - UPnP Port Forwarding, WebDAV Server (`/webdav`)
- **🐳 Docker Support** - `Dockerfile` & `docker-compose.yml` included
- **🔒 Security** - XSS prevention, PKCS7 validation, Path protection

### 🆕 v7.2.3 Security Enhancements
- **🔒 XSS Prevention** - HTML escape in document preview
- **🔐 PKCS7 Padding Validation** - Enhanced AES decryption error handling
- **📁 Copy/Move Protection** - Prevent copy/move to own subdirectory
- **🧵 Thread Safety** - Clipboard and user file I/O locks added

---

## 💾 Installation

### Requirements
- Python 3.8+
- pip (Python package manager)

### 1. Clone Repository
```bash
git clone https://github.com/your-repo/webshare.git
cd webshare
```

### 2. Install Dependencies
```bash
# Required packages
pip install flask werkzeug pillow cryptography

# GUI (recommended)
pip install pyqt6

# Optional packages (additional features)
pip install qrcode              # QR code generation
pip install python-docx         # Word document preview
pip install openpyxl            # Excel document preview
pip install python-pptx         # PowerPoint preview
pip install miniupnpc           # UPnP Port Forwarding
pip install wsgidav cheroot     # WebDAV Server
pip install flask-compress cachetools  # API compression / short TTL cache
pip install orjson             # Optional fast JSON serializer
# FFmpeg: Must be installed separately on system (Add to PATH)
```

### 3. Run
```bash
# Modular (recommended)
python main.py

# Legacy (single file)
python "legacy/웹서버 프로그램v4.py"
```

### 4. Docker
```bash
docker-compose up -d
```

---

## 🚀 Usage

### Quick Start

1. **Run the program**
   ```bash
   python main.py
   ```

2. **Configure in GUI**
   - Set shared folder path
   - Set port number (default: 5000)
   - Set admin/guest passwords

3. **Start Server**
   - Click "🚀 Start Server" button in GUI

4. **Access via Browser**
   - Navigate to `http://localhost:5000` or displayed IP address
   - Enter password to log in

### Default Passwords
| Account | Password | Permissions |
|---------|----------|-------------|
| Admin | `1234` | Full access |
| Guest | `0000` | Read only |

---

## ⌨️ Keyboard Shortcuts

### File Navigation
| Shortcut | Function |
|----------|----------|
| `↑` / `↓` | Move file selection |
| `Enter` | Open file / Enter folder |
| `Backspace` | Go to parent folder |
| `Ctrl + A` | Select all |
| `Esc` | Deselect / Close modal |

### File Operations
| Shortcut | Function |
|----------|----------|
| `Delete` | Delete selected files |
| `F2` | Rename |
| `Ctrl + C` | Copy |
| `Ctrl + X` | Cut |
| `Ctrl + V` | Paste |

### Others
| Shortcut | Function |
|----------|----------|
| `Ctrl + N` | New folder |
| `Ctrl + U` | Upload files |
| `Ctrl + F` | Search |
| `G` | Toggle view (list/grid) |
| `D` | Toggle dark mode |
| `?` | Shortcuts help |

---

## ⚙️ Configuration

### webshare_config.json
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
    "trusted_proxies": [],
    "trusted_hops": 1,
    "webdav_allow_insecure": false
}
```

### Configuration Options
| Key | Description | Default |
|-----|-------------|---------|
| `folder` | Shared folder path | `./shared_files` |
| `port` | Web server port | `5000` |
| `admin_pw` | Admin password | `1234` |
| `guest_pw` | Guest password | `0000` |
| `allow_guest_upload` | Allow guest uploads | `false` |
| `session_timeout` | Session timeout (minutes) | `60` |
| `language` | Language (`ko`/`en`) | `ko` |
| `ip_whitelist` | Allowed IP list (empty = allow all) | `[]` |
| `daily_download_limit` | Daily download count limit | `0` (unlimited) |
| `trusted_proxies` | Trusted proxy IP list for `X-Forwarded-For` | `[]` |
| `trusted_hops` | Trusted proxy hop count | `1` |
| `webdav_allow_insecure` | Allow non-TLS WebDAV write methods | `false` |

---

## 📡 API Endpoints

### Authentication
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/` | Login |
| `GET` | `/logout` | Logout |
| `POST` | `/set_language` | Standard language API (`{"lang":"ko|en","csrf_token":"..."}`) |
| `GET` | `/set_language/<lang>` | Legacy compatibility wrapper (Deprecation, Sunset: 2026-08-31) |

### File Management
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/browse/<path>` | Browse folder |
| `GET` | `/download/<path>` | Download file |
| `POST` | `/upload/<path>` | Upload file |
| `POST` | `/mkdir/<path>` | Create folder |
| `POST` | `/rename/<path>` | Rename |
| `POST` | `/delete/<path>` | Delete file |
| `POST` | `/copy` | Copy file |
| `POST` | `/move` | Move file |
| `GET` | `/zip/<path>` | Download folder as ZIP |

### v7.2 API
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Liveness check (no auth) |
| `GET` | `/readyz` | Readiness check (returns 503 when not ready) |
| `GET` | `/api/list/<path>` | Paginated directory listing (performance optimized) |
| `GET` | `/api/dashboard/summary` | Unified dashboard summary (metrics+disk) |
| `GET` | `/api/indexer/status` | Search indexer status |
| `GET` | `/api/audit_log` | Get audit logs (canonical in `admin_routes`, `limit` compatibility supported) |
| `GET/POST` | `/api/permissions` | Folder permissions |
| `GET` | `/api/duplicates` | Get duplicate files |
| `POST` | `/api/duplicates/scan` | Start duplicate scan |

### Media/Network (v7.2.3)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/stream/hls/<path>/index.m3u8` | HLS Playlist (Starts transcoding) |
| `GET` | `/webdav/` | WebDAV Endpoint |
| `GET` | `/manifest.json` | PWA Manifest |

### Security Policy Notes
- Logged-in state-changing requests (`POST/PUT/PATCH/DELETE`) require global CSRF validation.
- `.webshare*` and hidden paths are blocked (403) on `/download/*`, `/stream/*`, `/preview/*`, and WebDAV.
- WebDAV rejects non-TLS write/delete methods by default (`webdav_allow_insecure=false`).

---

## 📁 Project Structure

### v7.2.x Modular Structure (14 Blueprints)
```
(repo root)/
├── main.py                    # Entry point
├── config.py                  # Configuration/constants
├── i18n.py                    # Internationalization
├── server.py                  # Flask app factory, ServerThread
├── utils/                     # Utilities
├── security/                  # Security (auth, CSRF, IP blocking)
├── features/                  # Features (audit log, trash, crypto)
├── routes/                    # Flask Blueprints (14)
│   ├── main_routes.py
│   ├── pwa_routes.py          # NEW: PWA Manifest
│   └── ...
├── templates/                 # HTML Templates
│   ├── index.html
│   ├── share_password.html
│   └── share_expired.html
├── static/                    # Static resources
│   └── js/                    # Frontend split modules
│       ├── app-core.js
│       ├── app-modals.js
│       └── app-upload.js
├── gui/                       # PyQt6 GUI
├── legacy/                    # Legacy archive
│   └── 웹서버 프로그램v4.py
├── backup/                    # Backup files
├── scripts/                   # Performance tools
│   ├── generate_dataset.py
│   └── perf_bench.py
├── tests/                     # pytest suite
│   ├── test_security_policies.py
│   ├── test_permissions_enforcement.py
│   ├── test_api_compatibility.py
│   └── test_download_limits.py
├── webshare.spec              # PyInstaller spec
├── webshare_config.json       # Runtime config
├── Dockerfile                 # Docker image build
├── docker-compose.yml         # Docker runtime
└── shared_files/              # Shared folder
```

---

## ❓ Troubleshooting

### Server won't start
```
Error: Address already in use
```
**Solution**: Another program is using the port. Change the port number in settings.

### PyQt6 Error
```
ModuleNotFoundError: No module named 'PyQt6'
```
**Solution**: `pip install pyqt6`

### Large file upload fails
- Files over 100MB use automatic chunked upload
- Supports retry on network instability
- Maximum 10GB supported

### Cannot access from external network
1. Open port in firewall
2. Configure port forwarding on router
3. Set `display_host` to `0.0.0.0`

---

## 📄 License

MIT License

Copyright (c) 2026 WebShare Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files.
