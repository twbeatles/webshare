# WebShare Pro v7.4.0

<div align="center">

# 🚀 WebShare Pro
### 고성능 Go 엔진과 유연한 Python/PyQt6의 결합 — 차세대 하이브리드 로컬 웹 스토리지

[![Version](https://img.shields.io/badge/version-7.4.0-blue?style=for-the-badge&logo=semver)](https://github.com/twbeatles/webshare/releases)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/PyQt6-Dark_Theme-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://riverbankcomputing.com/software/pyqt/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)]()

<p align="center">
  <b>로컬 PC의 폴더를 단 1초 만에 안전하고 강력한 개인 클라우드 스토리지로 변환하세요.</b><br/>
  외부 클라우드 구독료 없이, 데이터 유출 걱정 없는 온프레미스 고성능 파일 서버 솔루션입니다.<br/>
  <b>Go 언어 기반 네이티브 코어 엔진</b>의 압도적인 전송 속도와 <b>PyQt6 데스크톱 관리자</b>의 직관적인 편의성을 동시에 제공합니다.
</p>

[✨ 핵심 기능](#-핵심-기능-highlights) •
[🚀 빠른 시작](#-빠른-시작-quick-start) •
[⚡ Go 코어 엔진](#-go-네이티브-코어-엔진--하이브리드-아키텍처) •
[🖥️ 데스크톱 GUI](#-데스크톱-프로그램-gui-가이드) •
[🌐 웹 파일 매니저](#-웹-파일-관리자-web-ui-가이드) •
[🛡️ 보안 & 관리자](#-보안--엔터프라이즈-관리자-기능) •
[⚙️ 설정 레퍼런스](#-설정-및-환경-변수-레퍼런스) •
[English Docs](README_EN.md)

</div>

---

## 📌 주요 검색 태그 (Keywords)
`file-server` `self-hosted-storage` `go-server` `python-flask` `pyqt6` `private-cloud` `nas-alternative` `chunked-upload` `hls-streaming` `google-drive-sync` `pwa` `web-file-manager` `upnp` `cross-platform` `개인클라우드` `파일공유서버` `대용량파일전송`

---

## 📑 목차 (Table of Contents)

1. [프로젝트 개요 및 차별점](#-프로젝트-개요--차별점)
2. [시스템 아키텍처](#-시스템-아키텍처-system-architecture)
3. [핵심 기능 (Highlights)](#-핵심-기능-highlights)
4. [빠른 시작 (Quick Start)](#-빠른-시작-quick-start)
   - [방법 1: Windows 무설치 단일 실행 파일 (EXE)](#1-windows-무설치-단일-실행-파일-exe로-시작-가장-추천)
   - [방법 2: Docker / Docker Compose 배포](#2-docker--docker-compose로-시작-nas서버-권장)
   - [방법 3: 소스코드 개발 환경 구동](#3-소스코드-개발-환경에서-시작)
   - [기본 계정 및 접속 정보](#기본-접속-및-계정-정보)
5. [Go 네이티브 코어 엔진 & 하이브리드 아키텍처](#-go-네이티브-코어-엔진--하이브리드-아키텍처)
   - [Go 백엔드 특징 및 성능상 이점](#1-go-코어-엔진의-성능상-이점)
   - [하이브리드 자동 장애 복구 (Auto Fallback)](#2-하이브리드-자동-장애-복구-auto-fallback)
   - [백엔드 전환 제어](#3-백엔드-전환-제어-런타임-플래그)
6. [데스크톱 프로그램 (GUI) 가이드](#-데스크톱-프로그램-gui-가이드)
   - [홈 탭 (원클릭 제어 & 모바일 QR)](#1-홈-탭-home)
   - [설정 탭 (스토리지 & 네트워크 & 보안)](#2-설정-탭-settings)
   - [로그 탭 & 원클릭 자동 업데이트](#3-로그-탭--원클릭-안전-자동-업데이트)
7. [웹 파일 관리자 (Web UI) 가이드](#-웹-파일-관리자-web-ui-가이드)
   - [대용량 파일 청크 업로드 (최대 10GB)](#1-대용량-파일-청크-업로드-최대-10gb)
   - [미디어 스트리밍 & 문서 뷰어 & 인라인 코드 에디터](#2-미디어-스트리밍--문서-뷰어--인라인-코드-에디터)
   - [태그, 메모, 북마크 & 파일 버전 관리 (롤백)](#3-태그-메모-북마크--파일-버전-관리-롤백)
   - [안전 휴지통 시스템](#4-안전-휴지통-시스템)
8. [보안 & 엔터프라이즈 관리자 기능](#-보안--엔터프라이즈-관리자-기능)
   - [보안 공유 링크 발급 (암호/만료/다운로드 제한)](#1-보안-공유-링크-share-link-발급)
   - [폴더별 세분화된 접근 권한 제어 (RBAC)](#2-폴더별-세분화된-접근-권한-제어-rbac)
   - [SHA-256 기반 중복 파일 검사 및 정리](#3-sha-256-기반-중복-파일-검사-및-디스크-용량-확보)
   - [Google Drive 클라우드 양방향 동기화](#4-google-drive-클라우드-양방향-동기화)
   - [접속 세션 및 감사 로그 (Audit Log)](#5-접속-세션-및-실시간-감사-로그-audit-log)
   - [UPnP 자동 포트포워딩](#6-upnp-공유기-자동-포트포워딩)
9. [모바일 & PWA 지원](#-모바일--pwa-지원)
10. [설정 및 환경 변수 레퍼런스](#-설정-및-환경-변수-레퍼런스)
11. [개발, 테스트 및 빌드 가이드](#-개발-테스트-및-빌드-가이드)
12. [자주 묻는 질문 (FAQ) & 트러블슈팅](#-자주-묻는-질문-faq--트러블슈팅)
13. [라이선스](#-라이선스-license)

---

## 💡 프로젝트 개요 & 차별점

**WebShare Pro**는 복잡한 NAS 설정이나 비싼 상용 클라우드 구독 없이, 컴퓨터에 보관된 대용량 파일과 미디어를 안전하게 공유하고 제어할 수 있는 **차세대 개인 파일 스토리지 솔루션**입니다.

### 🌟 왜 WebShare Pro를 선택해야 할까요?

| 구분 | 일반 클라우드 서비스 (Google Drive 등) | 기존 단순 웹 서버 (SimpleHTTPServer 등) | **WebShare Pro v7.4.0** |
|---|---|---|---|
| **저장 용량** | 매월 구독료 발생, 용량 제한 | 로컬 디스크 한도 | **내 하드디스크 용량 전체 무료 사용** |
| **데이터 프라이버시** | 외부 기업 서버에 파일 보관 | 로컬 보관 | **100% 로컬 및 온프레미스 보관 (Zero-Leak)** |
| **I/O 처리 성능** | 인터넷 업로드/다운로드 속도 의존 | 단일 스레드, 대용량 버벅임 | **⚡ Go 네이티브 엔진 탑재로 초고속 I/O 및 멀티파트 스트리밍** |
| **GUI 편의성** | 웹 전용 | CLI 전용 (까다로운 터미널 조작) | **🖥️ PyQt6 다크 테마 데스크톱 관리자 & 트레이 제공** |
| **대용량 파일 전송** | 브라우저 탭 종료 시 실패 | 네트워크 끊김 시 처음부터 재전송 | **📦 10GB+ 청크 분할 전송 & 중단 시 자동 재개** |
| **미디어 & 오피스** | 제한적인 변환 | 다운로드 후 확인 필요 | **🎬 HLS 동영상 실시간 변환 스트리밍, 오피스/PDF/코드 뷰어 내장** |
| **보안 & 제어** | 단순 링크 공유 | 권한 관리 불가 | **🛡️ 비밀번호/만료일/다운로드 횟수 제한 링크, 폴더별 세부 RBAC** |

---

## 🏗️ 시스템 아키텍처 (System Architecture)

WebShare Pro는 **성능(Performance)**과 **사용자 편의성(Usability)**을 극대화하기 위해 **Go + Python 하이브리드 아키텍처**를 채택하고 있습니다.

```mermaid
flowchart TB
    subgraph Clients ["📱 사용자 인터페이스 (Clients)"]
        WebUI["💻 웹 파일 관리자 (반응형 브라우저)"]
        MobilePWA["📱 모바일 PWA & QR 접속"]
        ShareUser["🔗 보안 공유 링크 사용자"]
    end

    subgraph DesktopControl ["🖥️ 데스크톱 컨트롤 계층 (Python / PyQt6)"]
        GUI["PyQt6 다크 테마 관리창"]
        Tray["시스템 트레이 & 윈도우 알림"]
        Supervisor["프로세스 수퍼바이저 (go_process.py)"]
        GUI <--> Supervisor
    end

    subgraph EngineLayer ["⚡ 하이브리드 서버 엔진 (Core Layer)"]
        GoCore["⚡ [기본 백엔드] Go 네이티브 코어 (webshare-core)<br/>- Goroutine 기반 고동시성 I/O 처리<br/>- RFC 7233 멀티파트 바이트 레인지 지원<br/>- 저메모리 고속 청크 스트리밍<br/>- NFC 유니코드 파일명 정규화"]
        PyCore["🛡️ [폴백 백엔드] Python Core (Flask / Werkzeug)<br/>- Go 코어 이상 발생 시 1초 만에 무중단 자동 전환<br/>- HLS 트랜스코딩 & UPnP & 구글 드라이브 동기화"]
        
        Supervisor -->|기본 실행 & 헬스체크| GoCore
        Supervisor -.->|장애 감지 시 자동 폴백| PyCore
    end

    subgraph StorageLayer ["💾 스토리지 및 영속화 계층"]
        Disk["📂 로컬 공유 폴더 (Shared Files)"]
        Trash[".webshare_trash / .webshare_versions"]
        MetaJSON["상태 데이터 (.webshare_*.json)<br/>- 계정/세션/감사로그/다운로드쿼터"]
        CloudSync["☁️ Google Drive 클라우드 백업"]
    end

    Clients ===>|HTTP (HTTPS는 Python 백엔드 전용)| GoCore
    Clients -.->|폴백 시 라우팅| PyCore

    GoCore --> Disk & Trash & MetaJSON
    PyCore --> Disk & Trash & MetaJSON
    PyCore <--> CloudSync
```

---

## ✨ 핵심 기능 (Highlights)

- ⚡ **Go 고성능 네이티브 코어**: Go 언어로 재작성된 파일 I/O 코어 탑재로 높은 동시 접속 환경과 대용량 파일 전송에서 최소한의 CPU/메모리 자원만 소비
- 🖥️ **원클릭 데스크톱 GUI & 트레이**: PyQt6 기반 다크 테마 GUI 프로그램으로 터미널 조작 없이 원클릭 시작/중지 및 모바일용 QR 코드 제공
- 📦 **10GB+ 대용량 청크 업로드**: 대용량 파일을 10MB 조각 단위로 분할 전송하며, 네트워크가 끊겨도 중단 지점부터 즉시 재개
- 🎬 **HLS 비디오 스트리밍 & 문서 뷰어**: MKV/AVI/MP4 실시간 HLS 트랜스코딩 스트리밍, 오디오 플레이어, PDF/Word/Excel 뷰어, 30개 이상의 언어를 지원하는 웹 인라인 코드 에디터
- 🔗 **만료/암호 보안 공유 링크**: 접근 비밀번호, 다운로드 횟수 제한(예: 3회 후 링크 자동 파기), 유효 기간(1시간~무제한)을 지정할 수 있는 1회성/보안 공유 링크 발급
- 🛡️ **엔터프라이즈급 권한 제어 (RBAC)**: 관리자(`Admin`)와 게스트(`Guest`) 구분, 특정 폴더별 세분화된 읽기(Read)/쓰기(Write)/삭제(Delete) 제어
- 🔍 **SHA-256 중복 파일 탐색기**: 공유 폴더 전체를 고속 스캔하여 정확한 바이트 해시 비교로 중복 파일을 감지하고 원클릭 용량 확보
- ☁️ **Google Drive 양방향 동기화**: 로컬 폴더와 구글 드라이브 간 실시간 업로드/다운로드 백업 및 충돌 방지 정책
- 🗑️ **안전 휴지통 및 파일 버전 관리**: 실수로 삭제한 파일 1초 복원, 파일 수정/덮어쓰기 시 이전 버전 자동 보관 및 롤백
- 🔄 **원클릭 무중단 자동 업데이트**: Ed25519 디지털 서명 검증을 통한 무결성 확인 및 업데이트 실패 시 원자적(Atomic) 자동 롤백

---

## 🚀 빠른 시작 (Quick Start)

### 1. Windows 무설치 단일 실행 파일 (EXE)로 시작 (가장 추천)

Windows 환경에서는 Python이나 Go를 설치할 필요 없이, 단일 실행 파일 하나로 모든 기능(Go 코어 포함)을 즉시 사용할 수 있습니다.

1. **[GitHub Releases](https://github.com/twbeatles/webshare/releases)** 페이지에서 최신 버전의 `WebSharePro_v7.4.0.exe` 다운로드
2. 다운로드한 파일을 실행하고 화면 중앙의 **[▶ 서버 시작]** 클릭
3. 브라우저에서 `http://127.0.0.1:5000` 접속하거나 GUI의 **[🌐 브라우저 열기]** 클릭

---

### 2. Docker / Docker Compose로 시작 (NAS/서버 권장)

리눅스 서버, 시놀로지(Synology)/QNAP NAS 환경에서는 Docker Compose를 통해 간편하게 배포할 수 있습니다. (`ffmpeg` 기본 내장)

```bash
# 1. 저장소 복제
git clone https://github.com/twbeatles/webshare.git
cd webshare

# 2. 보안 비밀번호 설정 후 컨테이너 실행
export WEBSHARE_ADMIN_PASSWORD="MySecureAdminPassword!"
export WEBSHARE_GUEST_PASSWORD="MyGuestPassword123"
docker compose up -d
```

> **Windows PowerShell 환경:**
> ```powershell
> $env:WEBSHARE_ADMIN_PASSWORD="MySecureAdminPassword!"
> $env:WEBSHARE_GUEST_PASSWORD="MyGuestPassword123"
> docker compose up -d
> ```

---

### 3. 소스코드 개발 환경에서 시작

개발자 환경 또는 직접 빌드하여 구동할 경우 다음 단계를 진행합니다.

#### (1) Python 가상환경 및 패키지 설치
```bash
git clone https://github.com/twbeatles/webshare.git
cd webshare

# 가상환경 생성 및 활성화
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

# 의존 패키지 설치
pip install -r requirements.txt
pip install -r requirements-optional.txt
```

#### (2) Go 네이티브 코어 엔진 빌드
```bash
cd go-core
go test ./...
go build -o webshare-core.exe ./cmd/webshare-core   # Windows
# go build -o webshare-core ./cmd/webshare-core     # Linux/macOS
cd ..
```

#### (3) 서버 실행
```bash
python main.py
```
PyQt6가 지원되는 데스크톱 환경에서는 다크 테마 GUI가 실행되며, 리눅스 터미널이나 SSH 환경에서는 헤드리스 콘솔 모드로 자동 구동됩니다.

---

### 기본 접속 및 계정 정보

- **기본 접속 주소**: `http://localhost:5000` (또는 로컬 네트워크 IP)
- **기본 계정 정보**:
  | 역할 (Role) | 기본 비밀번호 | 권한 범위 |
  |---|---|---|
  | **Admin (관리자)** | `1234` | 모든 파일 관리, 시스템 설정, 권한 제어, 클라우드 동기화, 감사 로그 |
  | **Guest (게스트)** | `0000` | 공유 파일 조회/다운로드 (설정에 따라 업로드 가능, 폴더 권한 적용) |

> ⚠️ **보안 주의**: 외부망에 공개하거나 공유기에 포트포워딩하기 전에 반드시 관리자 및 게스트 비밀번호를 변경하세요.

---

## ⚡ Go 네이티브 코어 엔진 & 하이브리드 아키텍처

WebShare Pro v7.4.0의 핵심 혁신은 **Go 기반 고성능 파일 엔진 (`go-core`)**의 도입입니다.

### 1. Go 코어 엔진의 성능상 이점

- **Goroutine 기반 대규모 동시성**:
  - Python WSGI의 스레드 한계를 뛰어넘어, 수백 명의 동시 다운로드 및 스트리밍 요청을 매우 가벼운 Goroutine으로 효율적으로 처리합니다.
- **RFC 7233 멀티파트 바이트 레인지 (206 Partial Content)**:
  - 브라우저나 다운로드 가속기가 요청하는 분할 다운로드 및 동영상 시크(Seek)를 고속 처리합니다.
- **Zero-Allocation 지향 초고속 파일 I/O**:
  - 기가바이트(GB) 단위 대용량 파일 전송 시에도 메모리 누수 없이 시스템 캐시를 효율적으로 사용하는 파이프라인 스트리밍을 제공합니다.
- **NFC 유니코드 파일명 완벽 정규화**:
  - `golang.org/x/text`를 적용하여 macOS(NFD)와 Windows/Linux(NFC) 간 한글 파일명 깨짐(자모 분리 현상)을 원천 차단합니다.

### 2. 하이브리드 자동 장애 복구 (Auto Fallback)

데스크톱 프로세스 관리자([`GoServerProcess`](file:///c:/twbeatles-repos/webshare/webshare_app/server/go_process.py#L72-L130))는 Go 엔진의 상태를 상시 모니터링합니다.
- 만약 Go 바이너리가 누락되었거나 비정상 종료되는 경우, **사용자 개입 없이 1초 이내에 레거시 Python 백엔드로 무중단 자동 폴백(Fallback)**합니다. 단, Go 프로세스는 살아 있으나 설정(바인딩 주소·HTTPS)을 무시하는 상태에서는 장애로 감지되지 않아 폴백이 발생하지 않습니다.
- 모든 상태 데이터(`.webshare_*.json`)는 Go와 Python 간 상호 호환되는 형식으로 설계되어 전환 시 데이터 손실이 발생하지 않도록 합니다. 단, 세션 쿠키 속성(HTTPS Secure)·공유 링크 페이지 형태·상태 flush 시점이 백엔드마다 다를 수 있어 동작이 완전히 동일하지는 않습니다.

### 3. 백엔드 전환 제어 (런타임 플래그)

환경 변수를 통해 원하는 백엔드를 명시적으로 지정할 수 있습니다:
```bash
# 기본값 (Go 고성능 백엔드 사용)
WEBSHARE_SERVER_BACKEND=go

# 레거시 Python 백엔드로 강제 전환
WEBSHARE_SERVER_BACKEND=python

# Go 바이너리 위치 직접 지정
WEBSHARE_CORE_BIN=/path/to/webshare-core.exe
```

---

## 🖥️ 데스크톱 프로그램 (GUI) 가이드

PyQt6로 제작된 프리미엄 다크 테마 GUI 프로그램으로 모든 기능을 제어할 수 있습니다.

```text
┌─────────────────────────────────────────────────────────────┐
│ 🚀 WebShare Pro                     [🔄 업데이트 확인] v7.4.0 │
├─────────────────────────────────────────────────────────────┤
│  [ 🏠 홈 ]    [ ⚙️ 설정 ]    [ 📝 로그 ]                     │
│                                                             │
│                      🟢 서버 실행 중                         │
│                    [ ⏹ 서버 중지 ]                          │
│                                                             │
│  ┌─ 📡 접속 정보 ────────────────────────────────────────┐  │
│  │   http://192.168.0.15:5000  (엔진: ⚡ Go Core)        │  │
│  │   [🌐 브라우저 열기]  [📱 QR 코드]  [📂 폴더 열기]     │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌─ 📊 실시간 통계 ──────────────────────────────────────┐  │
│  │     요청: 1,420     접속: 12       트래픽: 1.84 GB     │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 1. 홈 탭 (Home)
- **원클릭 서버 구동**: 버튼 하나로 공유 폴더와 포트에 맞춰 웹 서버를 즉시 시작/중지합니다.
- **접속 주소 및 클릭 복사**: 로컬 주소 및 Wi-Fi/LAN IP를 한눈에 확인하고 클릭 한 번으로 복사합니다.
- **📱 모바일 QR 코드**: 스마트폰 카메라로 비추면 같은 네트워크 내에서 바로 접속할 수 있는 전용 QR 창을 생성합니다. (같은 네트워크 접속에는 설정에서 호스트를 `0.0.0.0`으로 지정해야 합니다.)
- **📂 폴더 열기**: 현재 공유 중인 로컬 폴더를 윈도우 파일 탐색기/파인더로 즉시 엽니다.
- **📊 실시간 모니터링**: 누적 요청 수, 현재 활성 세션, 실시간 네트워크 트래픽을 5초마다 자동 집계합니다.

### 2. 설정 탭 (Settings)
- **공유 폴더 선택**: 원하는 드라이브나 폴더를 자유롭게 탐색기로 지정
- **네트워크 바인딩**: 로컬 전용(`127.0.0.1`), LAN 전체(`0.0.0.0`), 포트 번호(기본 `5000`) 변경
- **보안 비밀번호**: 관리자/게스트 비밀번호를 안전하게 단방향 해시로 저장
- **HTTPS 보안 통신**: Ad-hoc 자체 서명 인증서 기반 SSL 암호화 통신 활성화 (Python 백엔드 전용 — Go 기본 백엔드에서는 HTTPS 설정 시 서버가 시작되지 않고 안내 오류가 표시됩니다)
- **트레이 & 자동 실행**: 최소화(`_`) 또는 닫기(`X`) 시 트레이 최소화, 윈도우 부팅 시 자동 시작 설정

### 3. 로그 탭 & 원클릭 안전 자동 업데이트
- **실시간 로그 뷰어**: `INFO`, `WARN`, `ERROR` 등 등급별 실시간 필터링 및 텍스트 파일 내보내기 지원
- **🔄 Ed25519 서명 검증 업데이트**:
  - 최상단의 **[🔄 업데이트 확인]** 클릭 시 GitHub Release 매니페스트를 조회합니다.
  - 새 버전이 있을 경우 릴리스 노트를 확인하고 원클릭으로 다운로드 및 무중단 바이너리 교체를 수행합니다. (검증 실패 시 자동 롤백)

---

## 🌐 웹 파일 관리자 (Web UI) 가이드

모던 웹 기술로 제작된 반응형 파일 탐색기로 브라우저 어디서나 쾌적하게 파일을 관리합니다.

### 1. 대용량 파일 청크 업로드 (최대 10GB)
- **드래그 앤 드롭**: 파일이나 폴더를 브라우저 영역에 끌어다 놓기만 하면 즉시 업로드됩니다.
- **10MB 청크 분할 전송**: 대용량 파일을 분할 업로드하여 네트워크 오류 발생 시 실패한 조각부터 재전송합니다.
- **디스크 공간 사전 체크**: 업로드 시작 전 서버 디스크의 남은 용량을 사전에 검증하여 디스크 가득 참 현상을 방지합니다.

### 2. 미디어 스트리밍 & 문서 뷰어 & 인라인 코드 에디터
- **🎬 동영상 플레이어**: MP4, WebM 브라우저 직접 재생 및 고화질 비표준 포맷(MKV, AVI 등) HLS 실시간 스트리밍 지원
- **🎵 오디오 플레이어**: MP3, FLAC, WAV, AAC 백그라운드 연속 재생
- **🖼️ 이미지 갤러리**: 썸네일 미리보기, 슬라이드쇼, 원본 확대/축소
- **📄 오피스 & PDF 뷰어**: 브라우저 다운로드 없이 PDF, Word(`.docx`), Excel(`.xlsx`) 문서 즉시 미리보기
- **💻 소스코드 & 텍스트 인라인 편집기**:
  - Python, JavaScript, HTML, CSS, Markdown, JSON, YAML 등 30개 이상의 프로그래밍 언어 구문 강조(Syntax Highlighting) 지원
  - 웹상에서 코드를 수정하고 저장하면 즉시 서버 파일에 반영 (수정 시 이전 버전 자동 백업)

### 3. 태그, 메모, 북마크 & 파일 버전 관리 (롤백)
- **🏷️ 태그 & 메모**: 파일별 중요도 색상 라벨 지정 및 상세 메모 기록, 실시간 통합 검색 지원
- **⭐ 북마크**: 자주 사용하는 주요 폴더 및 파일을 즐겨찾기로 상단에 고정
- **🕒 파일 버전 롤백 (Versioning)**:
  - 파일 수정이나 덮어쓰기 발생 시 최대 5개까지 이전 버전을 자동 보관합니다.
  - 버전 히스토리 모달에서 변경 시점과 크기를 확인하고 클릭 한 번으로 **과거 시점 복원**이 가능합니다.

### 4. 안전 휴지통 시스템
- 파일을 삭제하면 즉시 영구 삭제되지 않고 `.webshare_trash` 보관소로 안전하게 이동합니다.
- 삭제된 파일의 원래 경로와 삭제 일시를 확인하고 **원클릭 복원**할 수 있습니다.
- 30일(설정 가능) 이상 경과한 파일은 자동으로 디스크에서 정리됩니다.

---

## 🛡️ 보안 & 엔터프라이즈 관리자 기능

관리자(`Admin`) 권한으로 로그인하면 상단 네비게이션을 통해 엔터프라이즈급 관리 도구를 사용할 수 있습니다.

### 1. 보안 공유 링크 (Share Link) 발급
특정 파일이나 폴더에 대해 계정 로그인 없이 외부인에게 안전하게 전달할 수 있는 전용 링크를 발급합니다.
- **유효 기간 설정**: `1시간`, `6시간`, `24시간`, `7일`, `무제한`
- **다운로드 횟수 제한**: 최대 횟수 초과 시 링크 자동 만료 (예: 1회용 다운로드 링크)
- **접근 비밀번호 보호**: 비밀번호 입력 후 접근 허용 (연속 5회 오입력 시 IP 임시 차단)
- **백엔드 동일 동작**: 기본 Go 백엔드에서도 브라우저에는 비밀번호 폼·만료 안내 HTML 페이지를, API 호출에는 JSON을 반환합니다 (Python 백엔드와 동일한 contract).
- **링크 즉시 회수**: 활성화된 링크 목록을 확인하고 언제든지 즉시 삭제/파기 가능

### 2. 폴더별 세분화된 접근 권한 제어 (RBAC)
게스트(`Guest`) 사용자나 부서별 폴더에 대해 읽기/쓰기/삭제 권한을 독립적으로 지정할 수 있습니다.
- **Read (읽기)**: 파일 조회 및 다운로드 권한
- **Write (쓰기)**: 신규 파일 업로드 및 폴더 생성 권한
- **Delete (삭제)**: 기존 파일 수정 및 삭제 권한

### 3. SHA-256 기반 중복 파일 검사 및 디스크 용량 확보
- 공유 폴더 전체를 백그라운드에서 스캔하여 바이트 단위 SHA-256 해시를 계산합니다.
- 동일한 내용의 중복 파일을 그룹별로 분류하여 보여주며, 불필요한 사본들을 선택하여 일괄 삭제함으로써 수 기가바이트의 디스크 용량을 즉시 확보합니다.

### 4. Google Drive 클라우드 양방향 동기화
- Google Cloud OAuth 자격증명을 연결하여 로컬 폴더와 Google Drive 간 양방향 동기화를 지원합니다.
- **로컬 ➔ Google Drive (클라우드 백업)** / **Google Drive ➔ 로컬 (다운로드 동기화)**
- 덮어쓰기, 건너뛰기, 이름 변경 등의 충돌 방지 정책과 실시간 백그라운드 진행 상태 모니터링을 제공합니다.
- 민감한 인증 정보는 공유 폴더와 분리된 OS 시스템 보안 스토리지에 안전하게 보관됩니다.

### 5. 접속 세션 및 실시간 감사 로그 (Audit Log)
- **활성 세션 뷰어**: 현재 접속 중인 클라이언트의 IP, 역할, 로그인 시각, 마지막 활동 시각 실시간 추적
- **감사 로그 (Audit Log)**: 파일 다운로드, 업로드, 삭제, 권한 변경, 로그인 시도 등 모든 보안 이벤트를 타임스탬프와 IP로 기록하고 검색/내보내기를 지원합니다.

### 6. UPnP 공유기 자동 포트포워딩
- 홈 네트워크나 공유기 환경에서 라우터 관리 페이지에 들어갈 필요 없이, WebShare 포트를 외부 인터넷으로 원클릭 자동 개방합니다. (UPnP 지원 공유기 필요)

---

## 📱 모바일 & PWA 지원

스마트폰, 태블릿 등 모바일 기기에서도 별도의 네이티브 앱 설치 없이 완벽한 사용자 경험을 제공합니다.

1. **간편한 모바일 연결**:
   - PC 화면의 **[📱 QR 코드]**를 모바일 카메라로 스캔하면 즉시 모바일 웹 매니저가 열립니다.
2. **PWA (Progressive Web App) 앱 설치**:
   - 모바일 브라우저(Safari, Chrome 등) 메뉴에서 **"홈 화면에 추가"**를 터치합니다.
   - 브라우저 상단 주소창이 사라지고, 스마트폰 바탕화면의 전용 독립 앱처럼 전체 화면으로 구동됩니다.
   - 스마트폰 사진/동영상 직접 업로드 및 백그라운드 음악 재생이 가능합니다.

---

## ⚙️ 설정 및 환경 변수 레퍼런스

환경 변수를 통해 컨테이너, CI/CD, 헤드리스 서버 등에서 설정을 손쉽게 오버라이드할 수 있습니다.

### 핵심 환경 변수 목록

| 환경 변수 | 설명 | 기본값 |
|---|---|---|
| `WEBSHARE_SERVER_BACKEND` | 서버 백엔드 코어 선택 (`go` 또는 `python`) | `go` |
| `WEBSHARE_CORE_BIN` | Go 코어 바이너리(`webshare-core.exe`)의 절대/상대 경로 | 자동 탐색 |
| `WEBSHARE_FOLDER` | 웹으로 공유할 기본 로컬 폴더 경로 | `./shared_files` (Docker: `/data`) |
| `WEBSHARE_HOST` | 바인딩 호스트 IP | `127.0.0.1` (Docker: `0.0.0.0`) |
| `WEBSHARE_PORT` | 서비스 HTTP 포트 | `5000` |
| `WEBSHARE_ADMIN_PASSWORD` | 관리자(`admin`) 로그인 비밀번호 | `1234` |
| `WEBSHARE_GUEST_PASSWORD` | 게스트(`guest`) 로그인 비밀번호 | `0000` |
| `WEBSHARE_SECRET_KEY` | 세션 보안 서명 키 | 자동 영속 생성 |
| `WEBSHARE_CONFIG_DIR` | 애플리케이션 및 비밀 정보 저장 디렉터리 | OS 기본 AppData 경로 |

### 데이터 및 메타데이터 저장 구조

```text
shared_files/                       # 공유 대상 폴더
├── .webshare_trash/                # 휴지통 임시 보관 폴더
├── .webshare_versions/             # 이전 파일 버전 히스토리
├── .webshare_login_attempts.json   # 무차별 대입 공격 차단 기록
├── .webshare_share_links.json      # 보안 공유 링크 메타데이터
├── .webshare_download_tracker.json # 다운로드 쿼터 및 트래커 상태
└── .webshare_audit.json            # 시스템 감사 로그 파일
```

---

## 🛠️ 개발, 테스트 및 빌드 가이드

### 1. 개발 및 테스트

```bash
# 가상환경 활성화 후 개발 의존성 설치
pip install -r requirements-dev.txt

# Go 코어 테스트
cd go-core
go test ./...
go vet ./...
cd ..

# Python 테스트 스위트 실행
pytest -q --basetemp .pytest_tmp

# 정적 타입 분석
pyright
```

### 2. Go 코어 빌드 및 PyInstaller 패키징

```bash
# 1. Go 네이티브 바이너리 빌드 (spec 파일에 번들링됨)
cd go-core
go build -o webshare-core.exe ./cmd/webshare-core
cd ..

# 2. PyInstaller로 단일 실행 파일(EXE) 생성
python -m PyInstaller --clean --noconfirm WebSharePro.spec
```
빌드가 완료되면 `dist/WebSharePro_v7.4.0.exe`가 생성됩니다.

### 3. 무결성 스모크 테스트 (Smoke Test)

GUI를 실행하지 않고 백엔드 엔진이 정상 구동되고 API가 응답하는지 검증합니다:
```bash
# 소스코드 기반 스모크 테스트
python main.py --smoke

# 빌드된 EXE 바이너리 스모크 테스트
.\dist\WebSharePro_v7.4.0.exe --smoke
```
검증 성공 시 `SMOKE_OK WebShare Pro` 메시지와 함께 정상 종료(`exit 0`)됩니다.

---

## ❓ 자주 묻는 질문 (FAQ) & 트러블슈팅

<details>
<summary><b>Q1. Go 백엔드 실행 파일이 없거나 오류가 발생하면 어떻게 되나요?</b></summary>
WebShare Pro는 다중 방어 메커니즘을 내장하고 있습니다. Go 바이너리(`webshare-core`)를 찾을 수 없거나 실행 실패가 감지되면, 즉시 내장된 Python 백엔드로 1초 만에 자동 전환되어 서버가 중단 없이 계속 작동합니다. 단, Go 프로세스가 살아 있는 상태에서는 설정 무시 시에도 전환되지 않습니다.
</details>

<details>
<summary><b>Q1-2. HTTPS를 켰는데 Go 백엔드에서 서버가 시작되지 않아요.</b></summary>
Go 코어에는 TLS 리스너가 없어 HTTPS 조합이 차단됩니다. 그대로 실행하면 평문 HTTP에 Secure 쿠키가 붙어 로그인이 깨지기 때문입니다. HTTPS가 필요하면 `WEBSHARE_SERVER_BACKEND=python`으로 실행하거나 설정에서 HTTPS를 꺼세요.
</details>

<details>
<summary><b>Q2. 외부 인터넷에서 접속하려면 어떻게 해야 하나요?</b></summary>
1. 데스크톱 GUI의 설정에서 호스트를 `0.0.0.0`으로 설정합니다.<br/>
2. 공유기를 사용하는 경우 관리자 메뉴의 [UPnP 포트포워딩]을 켜거나, 공유기 관리자 페이지에서 5000번 포트를 포트포워딩합니다.<br/>
3. DDNS 또는 공인 IP를 통해 외부 브라우저에서 접속할 수 있습니다. (외부 공개 시 반드시 기본 비밀번호를 변경하세요)
</details>

<details>
<summary><b>Q3. 리버스 프록시(Nginx, Caddy, Cloudflare)를 연동할 수 있나요?</b></summary>
네, 지원합니다. 설정 파일(`webshare_config.json`)의 `trusted_proxies`에 프록시 서버의 IP를 등록하고 `trusted_hops`를 지정하면 클라이언트의 실제 IP가 정상적으로 식별되어 브루트포스 차단 및 감사 로그에 정확히 기록됩니다.
</details>

<details>
<summary><b>Q4. 동영상 재생 시 HLS 고화질 변환이 동작하지 않아요.</b></summary>
시스템에 <code>ffmpeg</code>가 설치되어 있고 시스템 PATH에 등록되어 있어야 합니다. (Docker 배포판의 경우 기본 내장되어 있습니다)
</details>

---

## 📜 라이선스 (License)

이 프로젝트는 [MIT License](LICENSE)에 따라 자유롭게 사용, 수정, 배포할 수 있습니다.
상업적 용도를 포함한 개인 및 기업 환경에서 제한 없이 사용 가능합니다.

<div align="center">
  <sub>Built with ❤️ by twbeatles and contributors. Powered by Go & Python.</sub>
</div>
