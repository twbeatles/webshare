# WebShare Pro v7.2.4

브라우저로 로컬 파일을 안전하게 공유하고 관리하는 Flask/PyQt 기반 파일 서버입니다.

[![Version](https://img.shields.io/badge/version-7.2.4-blue?style=flat-square)](https://github.com/twbeatles/webshare)

[English](README_EN.md)

## 주요 기능

- 파일/폴더 탐색, 업로드, 다운로드, ZIP 다운로드, 복사/이동/삭제
- 10GB까지의 청크 업로드와 원자적 파일 교체
- Admin/Guest 역할, 폴더별 `read/write/delete` 권한, CSRF 보호
- PBKDF2 비밀번호 저장, legacy 평문/SHA256 로그인 성공 시 자동 마이그레이션
- 공유 링크 만료, 비밀번호, 다운로드 제한, 기본 attachment 다운로드
- 태그, 메모, 즐겨찾기, 휴지통, 버전 백업, 중복 파일 검사
- Google Drive 수동 업로드/다운로드 동기화와 작업 상태 저장
- HLS 스트리밍, WebDAV, UPnP, 문서 미리보기, 시스템 통계는 capability 감지 기반 선택 기능
- PWA manifest/service worker와 오프라인 fallback

## v7.2.4 보안/정합성 변경

- 파일 목록과 주요 동적 목록의 사용자 데이터 기반 inline JS를 `data-*`와 event delegation으로 전환했습니다.
- Google Drive 원격 파일명은 segment 단위로 안전하게 정규화하고, 최종 저장 경로를 공유 루트 내부인지 재검증합니다.
- `.webshare_cloud.json`에는 non-secret 상태만 저장하고, OAuth secret/token은 앱 설정 디렉터리의 `secrets/cloud_secrets.json`에 저장합니다.
- 다운로드 quota, 로그인 실패, 공유 링크 비밀번호 실패 상태를 JSON으로 영속화합니다.
- 일반 업로드, 청크 병합, overwrite copy/move는 임시 파일 또는 staging 경로 완료 후 교체합니다.
- 업로드 시작 전 디스크 여유 공간을 확인하고 진행 중인 업로드 예약량을 반영해 저장 공간 고갈을 사전에 차단합니다.
- overwrite copy/move와 버전 복원은 기존 파일을 먼저 버전 백업한 뒤 교체합니다.
- OAuth 팝업 결과와 특수문자 경로 URL을 안전하게 escaping/encoding합니다.
- HTML/API 응답은 `Cache-Control: no-store`를 적용하고, service worker는 인증 HTML을 install cache에 넣지 않습니다.
- Font Awesome, marked, DOMPurify, hls.js, highlight.js는 로컬 vendor asset을 우선 사용하고 CDN은 fallback으로만 사용합니다.
- metadata 입력 길이와 tag color 형식을 검증하고, SVG thumbnail에는 CSP/sandbox 성격 header를 추가합니다.

## 감사 후속 조치 (2026-06-25)

기능 감사(`PROJECT_AUDIT.md`) 권장 1·2단계 항목을 반영했습니다.

- JSON 상태 저장 시 snapshot+write 직렬화 (`webshare_app/core/persistence.py`)
- `secret_key` 앱 설정 디렉터리 자동 생성·재사용 (`WEBSHARE_CONFIG_DIR/secret_key`)
- 기본 비밀번호·공개 바인딩 경고 및 `GET /api/security/status` (admin)
- 드래그&드롭 폴더 업로드 경로 `validate_path` 검증
- 청크 업로드 `complete` 멱등 응답, 클립보드 256KB 제한, 공유 ZIP 디스크 사전 검사
- 회귀 테스트: `tests/test_audit_remediations.py` (전체 `113 passed, 1 skipped`)

## 설치

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

선택 기능까지 확인하려면 다음도 설치합니다.

```bash
pip install -r requirements-optional.txt
```

Python 3.14 환경에서는 `miniupnpc`를 기본 선택 설치에서 제외합니다. 이 경우 UPnP capability만 비활성화되며, 서버/GUI/파일 공유와 PyInstaller 패키징은 그대로 동작합니다.

개발/검증 환경은 다음을 사용합니다.

```bash
pip install -r requirements-dev.txt
pytest -q --basetemp .pytest_tmp
pyright
```

HLS 변환에는 Python 패키지가 아니라 `ffmpeg` 실행 파일이 필요합니다. Docker 이미지는 `ffmpeg`를 포함합니다.

## 프로젝트 구조

런타임 구현은 `webshare_app/` 패키지 아래에 정리되어 있습니다.

- `webshare_app/app`, `webshare_app/server`: Flask 앱 생성, WSGI 조립, 서버 스레드와 런타임 정리
- `webshare_app/routes`, `webshare_app/services`: Blueprint 엔드포인트와 파일/업로드/공유/미디어/클라우드 서비스 로직
- `webshare_app/core`, `webshare_app/features`, `webshare_app/security`, `webshare_app/gui`: 설정/상태, 기능 모듈, 보안, 데스크톱 GUI
- `templates/base.html`, `templates/partials/`, `static/css/app.css`, `static/js/`: Jinja layout/partial과 분리된 정적 UI asset
- 최상위 `server.py`, `config.py`, `routes/`, `features/`, `utils/`, `security/`, `gui/`는 기존 import 호환 wrapper입니다.

## 실행

```bash
python main.py
```

기본 접속 주소는 `http://localhost:5000`입니다.

기본 비밀번호:

| 역할 | 기본값 |
|---|---|
| Admin | `1234` |
| Guest | `0000` |

GUI에서 비밀번호 입력란은 기존 hash를 표시하지 않으며, 새 값을 입력한 경우에만 변경 저장합니다.

Google Drive Client Secret도 같은 방식으로 동작합니다. 빈 값으로 저장하면 기존 secret을 유지하고, 삭제 체크박스를 선택한 경우에만 저장된 secret을 지웁니다.

## 배포 및 보안 참고

- 런타임 상태(업로드 세션, 공유 링크 메모리, IP 차단 등)는 **단일 프로세스·단일 Werkzeug 스레드 풀** 전제입니다. gunicorn multi-worker 배포는 지원하지 않습니다.
- reverse proxy 뒤에서 실행할 때는 신뢰할 프록시 IP만 `trusted_proxies`에 설정하고 `trusted_hops`를 맞춰 주세요. 잘못 설정하면 `X-Forwarded-For` 기반 다운로드/로그인 제한이 우회될 수 있습니다.
- `secret_key`는 공유 폴더가 아닌 앱 설정 디렉터리(`WEBSHARE_CONFIG_DIR` 또는 OS 기본 config 경로)에 자동 생성·재사용됩니다.
- Dropbox 동기화 API(`/api/cloud/sync/dropbox`)는 현재 `501 placeholder`이며, Google Drive만 수동 동기화를 지원합니다.
- 공개 바인딩(`0.0.0.0`)과 기본 비밀번호 조합은 위험합니다. Docker는 경고 로그를 남기며, Admin UI는 `GET /api/security/status`로 경고 목록을 확인할 수 있습니다.

## Docker

```bash
docker compose up -d
```

Dockerfile은 HLS 지원을 위해 `ffmpeg`를 설치합니다.

공개 바인딩 환경에서는 기본 비밀번호를 그대로 두지 않는 것이 좋습니다.

```bash
$env:WEBSHARE_ADMIN_PASSWORD="change-me-admin"
$env:WEBSHARE_GUEST_PASSWORD="change-me-guest"
$env:WEBSHARE_SECRET_KEY="change-me-session-secret"
docker compose up -d
```

## 빌드

PyInstaller spec은 `webshare_app/core/config.py`의 `APP_VERSION`을 읽어 `WebSharePro_v7.2.4.exe` 형식으로 산출물 이름을 맞춥니다. `WebSharePro.spec`과 `webshare.spec`은 같은 런타임 모듈, templates, static/vendor asset 구성을 포함하도록 동기화되어 있습니다.

```bash
python -m PyInstaller --clean --noconfirm WebSharePro.spec
```

배포 전에는 생성된 EXE 자체를 GUI 없이 smoke 검증할 수 있습니다. 이 검증은 임시 공유 폴더에서 런타임 초기화, `/healthz`, `/readyz`, 정적 asset 로딩을 확인하고 성공 시 종료 코드 `0`을 반환합니다.

```powershell
.\dist\WebSharePro_v7.2.4.exe --smoke
```

호환 이름으로도 같은 빌드 구성을 사용할 수 있습니다.

```bash
python -m PyInstaller --clean --noconfirm webshare.spec
```

## API

대표 API:

| Method | Endpoint | 설명 |
|---|---|---|
| `GET` | `/healthz` | liveness |
| `GET` | `/readyz` | readiness |
| `GET` | `/api/list/<path>` | 파일 목록 |
| `GET` | `/api/capabilities` | 선택 기능 감지 결과 |
| `GET` | `/api/security/status` | 배포 안전 경고 (admin) |
| `POST` | `/api/cloud/sync/google_drive` | Google Drive 수동 동기화 |
| `GET/POST` | `/share/<token>` | 공유 링크 접근 |

`/api/capabilities` 예시:

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

## 데이터와 secret 저장 위치

공유 폴더 안의 `.webshare_*.json` 파일은 권한, 감사 로그, 공유 링크, 런타임 상태 같은 앱 상태 저장에 사용됩니다.

Google Drive secret/token은 공유 폴더 밖에 저장됩니다.

- Windows: `%APPDATA%/WebSharePro/secrets/cloud_secrets.json`
- Linux/macOS: `~/.config/websharepro/secrets/cloud_secrets.json`

테스트나 자동화에서는 `WEBSHARE_CONFIG_DIR` 환경 변수로 앱 설정 디렉터리를 오버라이드할 수 있습니다. Flask `secret_key`는 같은 디렉터리의 `secret_key` 파일에 영속화됩니다.

## Git 관리 참고

`.gitignore`는 다음을 제외합니다.

- 공유 폴더와 `.webshare_*.json/.tmp`, `.webshare_trash/`, `.webshare_versions/`, `.webshare_thumbs/` 런타임 상태
- 외부 secret 파일명 (`cloud_secrets.json`)
- PyInstaller 산출물 (`build/`, `dist/`, `*.toc`, `*.pkg`, `*.manifest`)
- 테스트/캐시/가상환경 산출물

`static/vendor/`는 폐쇄망/패키지 실행을 위한 동봉 정적 asset이므로 추적 대상입니다.

## 검증 기준

현재 기준선:

- `pytest -q --basetemp .pytest_tmp` -> `113 passed, 1 skipped`
- `pyright` -> `0 errors, 0 warnings`

## 라이선스

MIT License
