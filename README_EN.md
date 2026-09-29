# WebShare Pro v7.4.0

<div align="center">

# 🚀 WebShare Pro
### High-Performance Go Engine Meets Flexible Python/PyQt6 — Next-Gen Hybrid Self-Hosted File Storage

[![Version](https://img.shields.io/badge/version-7.4.0-blue?style=for-the-badge&logo=semver)](https://github.com/twbeatles/webshare/releases)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/PyQt6-Dark_Theme-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://riverbankcomputing.com/software/pyqt/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)]()

<p align="center">
  <b>Turn any local folder into a private, secure, and blazing-fast cloud storage in seconds.</b><br/>
  No subscription fees, no cloud privacy leaks. 100% on-premises data ownership.<br/>
  Powered by a <b>native Go core HTTP engine</b> for high-throughput I/O and a <b>PyQt6 desktop manager</b> for intuitive control.
</p>

[✨ Highlights](#-highlights) •
[🚀 Quick Start](#-quick-start) •
[⚡ Go Core Engine](#-go-native-core-engine--hybrid-architecture) •
[🖥️ Desktop GUI](#-desktop-gui-guide) •
[🌐 Web File Manager](#-web-file-manager-web-ui-guide) •
[🛡️ Security & Admin](#-security--admin-features) •
[⚙️ Configuration](#-configuration--environment-variables) •
[한국어 문서 (Korean)](README.md)

</div>

---

## 📌 Keywords & GitHub Topics
`file-server` `self-hosted-storage` `go-server` `python-flask` `pyqt6` `private-cloud` `nas-alternative` `chunked-upload` `hls-streaming` `google-drive-sync` `pwa` `web-file-manager` `upnp` `cross-platform`

---

## 📑 Table of Contents

1. [Overview & Value Proposition](#-overview--value-proposition)
2. [System Architecture](#-system-architecture)
3. [Key Highlights](#-highlights)
4. [Quick Start](#-quick-start)
   - [Method 1: Windows Standalone Portable EXE](#1-windows-portable-exe-standalone---recommended)
   - [Method 2: Docker & Docker Compose](#2-docker--docker-compose-nas--linux-server)
   - [Method 3: Run from Source (Dev)](#3-run-from-source-development)
   - [Default Credentials](#default-credentials)
5. [Go Native Core Engine & Hybrid Architecture](#-go-native-core-engine--hybrid-architecture)
   - [Performance Benefits](#1-performance-benefits-of-go-core)
   - [Automatic Resilient Fallback](#2-automatic-resilient-fallback-to-python)
   - [Runtime Backend Selection](#3-backend-selection-via-environment-variables)
6. [Desktop GUI Guide](#-desktop-gui-guide)
7. [Web File Manager (Web UI) Guide](#-web-file-manager-web-ui-guide)
8. [Security & Admin Features](#-security--admin-features)
   - [Password-Protected & Expiring Share Links](#1-secure-share-links)
   - [Per-Folder Access Control (RBAC)](#2-per-folder-rbac-permissions)
   - [SHA-256 Duplicate File Finder](#3-sha-256-duplicate-file-scanner)
   - [Bidirectional Google Drive Sync](#4-google-drive-bidirectional-sync)
   - [Real-Time Audit Log & Active Sessions](#5-active-sessions--real-time-audit-log)
   - [UPnP Automatic Port Forwarding](#6-upnp-automatic-port-forwarding)
9. [Mobile & PWA Support](#-mobile--pwa-support)
10. [Configuration & Environment Variables](#-configuration--environment-variables)
11. [Developer, Testing & Build Guide](#-developer-testing--build-guide)
12. [Frequently Asked Questions (FAQ)](#-frequently-asked-questions-faq)
13. [License](#-license)

---

## 💡 Overview & Value Proposition

**WebShare Pro** transforms your local PC, server, or NAS drive into a feature-packed personal cloud without relying on third-party SaaS providers.

| Metric / Feature | Commercial Cloud (Google Drive / Dropbox) | Basic Python Server (`http.server`) | **WebShare Pro v7.4.0** |
|---|---|---|---|
| **Storage Cost** | Monthly subscription fees | Free | **100% Free, Unlimited (Uses your local drives)** |
| **Data Privacy** | Stored on third-party servers | Local | **Zero-Leak: 100% On-Premises Local Storage** |
| **I/O Engine** | Network dependent | Single-thread, slow on large files | **⚡ Native Go HTTP Core Engine with RFC 7233 byte ranges** |
| **GUI Experience** | Web only | Terminal CLI only | **🖥️ PyQt6 Dark Theme Desktop App + Tray Icon** |
| **File Transfers** | Web tab limits | Fails on disconnection | **📦 10GB+ Chunked Resumable Uploads & On-the-fly ZIP** |
| **Media & Office** | Basic viewers | Download required | **🎬 HLS Video Streaming, Audio, Image Gallery, PDF/Office & Code Editor** |
| **Access Control** | Simple sharing | None | **🛡️ Per-Folder RBAC (Read/Write/Delete), Expiring Pass-Protected Links** |

---

## 🏗️ System Architecture

WebShare Pro combines the raw speed and low memory footprint of **Go** with the rich desktop integration of **Python/PyQt6**.

```mermaid
flowchart TB
    subgraph Clients ["📱 Client Layer"]
        WebUI["💻 Web File Manager (Responsive)"]
        MobilePWA["📱 Mobile PWA & QR Connect"]
        ShareUser["🔗 Secure Share Link Visitor"]
    end

    subgraph DesktopControl ["🖥️ Desktop Supervisor Layer (Python / PyQt6)"]
        GUI["PyQt6 Dark Theme Manager"]
        Tray["System Tray & Windows Notifications"]
        Supervisor["Process Supervisor (go_process.py)"]
        GUI <--> Supervisor
    end

    subgraph EngineLayer ["⚡ Hybrid Server Core Layer"]
        GoCore["⚡ [Primary Backend] Go Core (webshare-core)<br/>- Goroutine-driven high concurrency<br/>- RFC 7233 multipart/byteranges (206)<br/>- Low-memory streaming & chunk merging<br/>- NFC Unicode filename normalization"]
        PyCore["🛡️ [Fallback Backend] Python Core (Flask / Werkzeug)<br/>- 1-second auto-fallback on Go failure<br/>- HLS video transcoding & UPnP & Cloud sync"]
        
        Supervisor -->|Primary Launch & Healthcheck| GoCore
        Supervisor -.->|Auto Fallback on Failure| PyCore
    end

    subgraph StorageLayer ["💾 Storage & Persistence Layer"]
        Disk["📂 Local Shared Folder"]
        Trash[".webshare_trash / .webshare_versions"]
        MetaJSON["State Files (.webshare_*.json)<br/>- Auth / Quota / Audit / Share links"]
        CloudSync["☁️ Google Drive Backup"]
    end

    Clients ===>|HTTP (HTTPS: Python backend only)| GoCore
    Clients -.->|Fallback Routing| PyCore

    GoCore --> Disk & Trash & MetaJSON
    PyCore --> Disk & Trash & MetaJSON
    PyCore <--> CloudSync
```

---

## ✨ Highlights

- ⚡ **Go Native Core HTTP Engine**: Ultra-fast I/O handling, RFC 7233 multipart byte ranges, and low-latency chunk processing.
- 🖥️ **PyQt6 Desktop Control & System Tray**: One-click start/stop, bandwidth/requests monitor, IP badge, and instant mobile QR code generator.
- 📦 **10GB+ Chunked Resumable Upload**: Splits large uploads into 10MB chunks, resumes upon connection drop, and verifies disk space in advance.
- 🎬 **HLS Video Streaming & Document Previews**: Real-time HLS video transcoding for MKV/AVI/MP4, audio player, image gallery, PDF/Office document viewer, and inline code editor for 30+ programming languages.
- 🔗 **Secure Expiring Share Links**: Custom link expiration (1h, 6h, 24h, 7d, unlimited), download counter limits, password protection, and brute-force defenses.
- 🛡️ **Fine-Grained RBAC Permissions**: Admin vs Guest roles, with per-folder Read, Write, and Delete rules.
- 🔍 **SHA-256 Duplicate File Finder**: Fast whole-tree disk scanning to detect byte-identical duplicate files and reclaim disk storage.
- ☁️ **Bidirectional Google Drive Sync**: Manual backup and restore between local storage and Google Drive with collision policies.
- 🗑️ **Trash Bin & Version Rollback**: 1-click restore of deleted files, and automatic version history on file overwrite.
- 🔄 **Safe Auto-Update**: Ed25519 digital signature validation with atomic binary swap and automatic rollback.

---

## 🚀 Quick Start

### 1. Windows Portable EXE (Standalone - Recommended)

No Python or Go installation required. The executable bundles both engines ready to run.

1. Download `WebSharePro_v7.4.0.exe` from **[GitHub Releases](https://github.com/twbeatles/webshare/releases)**.
2. Launch the application and click **[▶ Start Server]**.
3. Open `http://127.0.0.1:5000` in your web browser.

---

### 2. Docker & Docker Compose (NAS / Linux Server)

Includes `ffmpeg` out of the box for video transcoding.

```bash
git clone https://github.com/twbeatles/webshare.git
cd webshare

# Configure secure passwords and launch
export WEBSHARE_ADMIN_PASSWORD="MySecureAdminPassword!"
export WEBSHARE_GUEST_PASSWORD="MyGuestPassword123"
docker compose up -d
```

---

### 3. Run from Source (Development)

```bash
# 1. Clone repository & setup virtual environment
git clone https://github.com/twbeatles/webshare.git
cd webshare
python -m venv .venv

# Activate venv
# Windows: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-optional.txt

# 2. Build Go Core Engine
cd go-core
go test ./...
go build -o webshare-core.exe ./cmd/webshare-core   # Windows
# go build -o webshare-core ./cmd/webshare-core     # Linux/macOS
cd ..

# 3. Start Server
python main.py
```

---

### Default Credentials

- **Default URL**: `http://localhost:5000`
- **Default Accounts**:
  | Role | Default Password | Permissions |
  |---|---|---|
  | **Admin** | `1234` | Full access, settings, user permissions, audit logs, duplicate scan, cloud sync |
  | **Guest** | `0000` | Browse & download (upload optional, subject to folder RBAC) |

> ⚠️ **Security Warning**: Change the default passwords immediately before exposing the server to external networks.

---

## ⚡ Go Native Core Engine & Hybrid Architecture

### 1. Performance Benefits of Go Core

- **Goroutine-based High Concurrency**: Serves hundreds of concurrent downloads with negligible memory overhead compared to traditional WSGI workers.
- **RFC 7233 Multipart Range Streaming (`206 Partial Content`)**: Smooth multi-threaded downloads and instant video seek without buffering delays.
- **NFC Unicode Normalization**: Employs `golang.org/x/text` to prevent filename encoding issues across macOS, Windows, and Linux.

### 2. Automatic Resilient Fallback to Python

The process supervisor ([`GoServerProcess`](file:///c:/twbeatles-repos/webshare/webshare_app/server/go_process.py#L72-L130)) handles startup and healthchecks:
- If the Go binary is missing, fails to start, or crashes, it switches seamlessly to the Python backend in less than 1 second. No fallback occurs while the Go process stays alive but ignores configuration (bind address/HTTPS).
- State files (`.webshare_*.json`) share a common format between Go and Python to avoid data loss during transitions. Behavior is not identical in every detail (session cookie Secure flag, share-link page shape, state flush timing).

### 3. Backend Selection via Environment Variables

```bash
# Default: Use native Go engine
WEBSHARE_SERVER_BACKEND=go

# Force legacy Python backend
WEBSHARE_SERVER_BACKEND=python

# Custom Go core binary path
WEBSHARE_CORE_BIN=/path/to/webshare-core.exe
```

---

## 🖥️ Desktop GUI Guide

Built with PyQt6, featuring a responsive dark theme:

```text
┌─────────────────────────────────────────────────────────────┐
│ 🚀 WebShare Pro                     [🔄 Check Update] v7.4.0  │
├─────────────────────────────────────────────────────────────┤
│  [ 🏠 Home ]    [ ⚙️ Settings ]    [ 📝 Logs ]                │
│                                                             │
│                      🟢 Server Running                      │
│                    [ ⏹ Stop Server ]                        │
│                                                             │
│  ┌─ 📡 Access Information ────────────────────────────────┐  │
│  │   http://192.168.0.15:5000  (Engine: ⚡ Go Core)        │  │
│  │   [🌐 Open Browser]  [📱 QR Code]  [📂 Open Folder]     │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌─ 📊 Realtime Stats ────────────────────────────────────┐  │
│  │     Requests: 1,420    Clients: 12    Traffic: 1.84 GB   │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

- **Home**: One-click start/stop, LAN IP display, Mobile QR code generator, and real-time request/bandwidth meters.
- **Settings**: Choose shared folder, port, interface (`127.0.0.1` vs `0.0.0.0`), HTTPS toggle (Python backend only — the default Go backend refuses to start with HTTPS enabled), and passwords.
- **Logs**: Filter logs by `INFO`, `WARN`, `ERROR` and export to file.
- **One-Click Update**: Ed25519 signature verification against GitHub Releases with zero-downtime atomic swap.

---

## 🌐 Web File Manager (Web UI) Guide

- **10GB+ Chunked Upload**: Multi-part upload with automated retry and preflight disk space checks.
- **Integrated Media Player**: Direct video playback + HLS on-the-fly transcoding for non-web video containers.
- **Document & Code Editor**: In-browser viewing for PDF, Word, Excel, and an inline editor with syntax highlighting for 30+ languages.
- **Metadata**: Add color tags, memos, favorites, and inspect revision history with instant rollback.
- **Trash Bin**: Safely store deleted files in `.webshare_trash` with one-click restore.

---

## 🛡️ Security & Admin Features

### 1. Secure Share Links
Create time-limited, password-protected links with download counters (e.g. valid for 1 download or expires in 24h). Both backends serve browser-friendly pages for these flows (Python renders the full templates; the default Go backend renders minimal equivalent HTML pages), while API callers receive JSON.

### 2. Per-Folder RBAC Permissions
Assign granular `read`, `write`, and `delete` permissions to guest users per directory.

### 3. SHA-256 Duplicate File Scanner
Identify duplicate files via cryptographic hashes and reclaim storage space with batch cleanup.

### 4. Google Drive Bidirectional Sync
Sync local files to Google Drive with automated collision handling policies (overwrite/skip/rename).

### 5. Active Sessions & Real-Time Audit Log
Track logged-in users, client IPs, timestamps, and log security-sensitive operations.

### 6. UPnP Automatic Port Forwarding
Automatically open the server port on UPnP-compatible home routers with zero manual configuration.

---

## 📱 Mobile & PWA Support

1. **Instant QR Connect**: Scan the QR code on the desktop app with your smartphone camera to connect immediately. (LAN access requires the host to be set to `0.0.0.0` in Settings.)
2. **PWA Home Screen App**: Add WebShare to your mobile home screen to run in full-screen standalone app mode.

---

## ⚙️ Configuration & Environment Variables

| Variable | Description | Default |
|---|---|---|
| `WEBSHARE_SERVER_BACKEND` | Core server backend (`go` or `python`) | `go` |
| `WEBSHARE_CORE_BIN` | Path to `webshare-core` binary | Auto-detected |
| `WEBSHARE_FOLDER` | Path to shared storage directory | `./shared_files` (Docker: `/data`) |
| `WEBSHARE_HOST` | Bound network interface | `127.0.0.1` (Docker: `0.0.0.0`) |
| `WEBSHARE_PORT` | HTTP port | `5000` |
| `WEBSHARE_ADMIN_PASSWORD` | Admin account password | `1234` |
| `WEBSHARE_GUEST_PASSWORD` | Guest account password | `0000` |
| `WEBSHARE_SECRET_KEY` | Flask session secret key | Auto-generated |
| `WEBSHARE_CONFIG_DIR` | App config and secrets directory | OS AppData path |

---

## 🛠️ Developer, Testing & Build Guide

```bash
# 1. Run tests
cd go-core && go test ./... && cd ..
pytest -q --basetemp .pytest_tmp
pyright

# 2. Build Go Core & Windows Standalone EXE
cd go-core
go build -o webshare-core.exe ./cmd/webshare-core
cd ..
python -m PyInstaller --clean --noconfirm WebSharePro.spec

# 3. Smoke Test (Headless)
.\dist\WebSharePro_v7.4.0.exe --smoke
```

---

## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><b>Q1. What happens if the Go binary fails or is missing?</b></summary>
WebShare Pro has built-in auto-fallback. If the Go backend fails to launch, the system automatically falls back to the embedded Python engine in under a second. No fallback occurs while the Go process stays alive but ignores its configuration.
</details>

<details>
<summary><b>Q2. Can I use a reverse proxy (Nginx, Caddy, Cloudflare)?</b></summary>
Yes. Configure <code>trusted_proxies</code> and <code>trusted_hops</code> in <code>webshare_config.json</code> to ensure accurate client IP logging and rate limiting.
</details>

---

## 📜 License

Distributed under the [MIT License](LICENSE). Free for personal and commercial use.

<div align="center">
  <sub>Built with ❤️ by twbeatles and contributors. Powered by Go & Python.</sub>
</div>
