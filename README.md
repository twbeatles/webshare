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
- HTML/API 응답은 `Cache-Control: no-store`를 적용하고, service worker는 인증 HTML을 install cache에 넣지 않습니다.
- metadata 입력 길이와 tag color 형식을 검증하고, SVG thumbnail에는 CSP/sandbox 성격 header를 추가합니다.

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

개발/검증 환경은 다음을 사용합니다.

```bash
pip install -r requirements-dev.txt
pytest -q --basetemp .pytest_tmp
pyright
```

HLS 변환에는 Python 패키지가 아니라 `ffmpeg` 실행 파일이 필요합니다. Docker 이미지는 `ffmpeg`를 포함합니다.

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

## Docker

```bash
docker compose up -d
```

Dockerfile은 HLS 지원을 위해 `ffmpeg`를 설치합니다.

## 빌드

PyInstaller spec은 `config.py`의 `APP_VERSION`을 읽어 `WebSharePro_v7.2.4.exe` 형식으로 산출물 이름을 맞춥니다.

```bash
pyinstaller WebSharePro.spec
```

또는 간소화 spec을 사용할 수 있습니다.

```bash
pyinstaller webshare.spec
```

## API

대표 API:

| Method | Endpoint | 설명 |
|---|---|---|
| `GET` | `/healthz` | liveness |
| `GET` | `/readyz` | readiness |
| `GET` | `/api/list/<path>` | 파일 목록 |
| `GET` | `/api/capabilities` | 선택 기능 감지 결과 |
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

테스트나 자동화에서는 `WEBSHARE_CONFIG_DIR` 환경 변수로 앱 설정 디렉터리를 오버라이드할 수 있습니다.

## Git 관리 참고

`.gitignore`는 다음을 제외합니다.

- 공유 폴더와 `.webshare_*.json/.tmp` 런타임 상태
- 외부 secret 파일명 (`cloud_secrets.json`)
- PyInstaller 산출물 (`build/`, `dist/`, `*.toc`, `*.pkg`, `*.manifest`)
- 테스트/캐시/가상환경 산출물

## 검증 기준

현재 기준선:

- `pytest -q --basetemp .pytest_tmp` -> `92 passed, 1 skipped`
- `pyright` -> `0 errors, 0 warnings`

## 라이선스

MIT License
