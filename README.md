# WebShare Pro v7.2.1

<div align="center">

![WebShare Pro Logo](https://img.shields.io/badge/WebShare-Pro-6366f1?style=for-the-badge&logo=server&logoColor=white)

**브라우저에서 로컬 파일을 공유하는 올인원 파일 서버**

[![Version](https://img.shields.io/badge/version-7.2.1-blue?style=flat-square)](https://github.com)
[![Python](https://img.shields.io/badge/python-3.8+-green?style=flat-square)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.0+-orange?style=flat-square)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)

**한국어** | [English](README_EN.md)

</div>

---

## 목차

- [주요 기능](#주요-기능)
- [설치](#설치)
- [사용 방법](#사용-방법)
- [단축키](#단축키)
- [설정](#설정)
- [API 엔드포인트](#api-엔드포인트)
- [프로젝트 구조](#프로젝트-구조)
- [문제 해결](#문제-해결)
- [라이선스](#라이선스)

---

## 주요 기능

### 파일 관리
- 드래그 앤 드롭 업로드/다운로드
- 대용량 파일 자동 청크 업로드(최대 10GB)
- 폴더 생성/이름 변경/삭제, ZIP 다운로드
- 실시간 파일명 검색
- 다중 선택 일괄 작업

### 보안
- 역할 기반 접근 제어(Admin/Guest)
- PBKDF2-SHA256 비밀번호 해시
- 상태 변경 요청에 대한 전역 CSRF 검증
- 로그인 실패 누적 시 IP 차단
- AES-GCM(v2) 파일 암호화 + 구버전 CBC 복호화 호환

### 공유
- 비밀번호/만료시간/다운로드 제한을 가진 공유 링크
- 공유 링크 JSON 영속화(`.webshare_share_links.json`)
- 모바일 접속용 QR 코드 생성

### 고급 기능
- 휴지통/복원/자동 정리
- 파일 버전 관리 및 백업 스냅샷
- 태그/메모, 즐겨찾기
- SHA256 기반 중복 파일 스캔
- 폴더별 읽기/쓰기/삭제 권한
- 감사 로그 저장
- 드래그 앤 드롭 이동
- PDF/Markdown 미리보기
- 멀티 탭 탐색

### v7.2.3 업데이트
- 실시간 트랜스코딩 + HLS 스트리밍
- PWA 지원(`manifest.json`, 설치형 셸)
- 네트워크 유틸리티(UPnP, WebDAV)
- Docker 지원(`Dockerfile`, `docker-compose.yml`)
- 보안 강화(XSS/PKCS7/경로 보호)

> 참고: `/api/users` 관리 기능은 현재 활성 로그인 모델(`admin_pw` / `guest_pw`)과 직접 연동되지 않습니다.

---

## 설치

### 요구 사항
- Python 3.8+
- pip

### 1. 저장소 복제
```bash
git clone https://github.com/your-repo/webshare.git
cd webshare
```

### 2. 의존성 설치
```bash
# 필수
pip install flask werkzeug pillow cryptography

# GUI (권장)
pip install pyqt6

# 선택
pip install qrcode
pip install python-docx
pip install openpyxl
pip install python-pptx
pip install miniupnpc
pip install wsgidav cheroot
pip install flask-compress cachetools
pip install orjson

# FFmpeg는 시스템에 별도 설치 후 PATH 등록 필요
```

### 3. 실행
```bash
python main.py
```

### 4. EXE 빌드
```bash
pyinstaller webshare.spec
# 결과: dist/WebSharePro_v7.2.1.exe
```

### 5. Docker 실행
```bash
docker compose up -d
```

- 기본 포트: `5000`
- 볼륨: `./shared_files -> /data`
- 엔트리포인트: `docker_entrypoint.py`

---

## 사용 방법

### 빠른 시작
1. `python main.py` 실행
2. GUI에서 공유 폴더/포트/비밀번호 설정
3. 서버 시작
4. 브라우저에서 `http://localhost:5000` 또는 표시된 LAN IP 접속

### 기본 계정
| 계정 | 비밀번호 | 권한 |
|---|---|---|
| 관리자 | `1234` | 전체 |
| 게스트 | `0000` | 읽기 전용 |

---

## 단축키

### 탐색
| 단축키 | 기능 |
|---|---|
| ↑ / ↓ | 선택 이동 |
| Enter | 파일 열기 / 폴더 진입 |
| Backspace | 상위 폴더 이동 |
| Ctrl + A | 전체 선택 |
| Esc | 선택 해제 / 모달 닫기 |

### 파일 작업
| 단축키 | 기능 |
|---|---|
| Delete | 선택 파일 삭제 |
| F2 | 이름 변경 |
| Ctrl + C | 복사 |
| Ctrl + X | 잘라내기 |
| Ctrl + V | 붙여넣기 |

### 기타
| 단축키 | 기능 |
|---|---|
| Ctrl + N | 새 폴더 |
| Ctrl + U | 업로드 |
| Ctrl + F | 검색 |
| Ctrl + T | 새 탭 |
| G | 목록/그리드 전환 |
| D | 다크 모드 전환 |
| ? | 단축키 도움말 |

---

## 설정

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
  "language": "ko",
  "ip_whitelist": [],
  "daily_download_limit": 0,
  "disk_warning_threshold": 90,
  "trusted_proxies": [],
  "trusted_hops": 1,
  "webdav_allow_insecure": false
}
```

### 주요 옵션
| 키 | 설명 | 기본값 |
|---|---|---|
| `folder` | 공유 폴더 경로 | `./shared_files` |
| `port` | 서버 포트 | `5000` |
| `admin_pw` | 관리자 비밀번호 | `1234` |
| `guest_pw` | 게스트 비밀번호 | `0000` |
| `allow_guest_upload` | 게스트 업로드 허용 | `false` |
| `session_timeout` | 세션 만료 시간(분) | `60` |
| `language` | 언어(`ko`/`en`) | `ko` |
| `ip_whitelist` | 허용 IP 목록(비어 있으면 전체 허용) | `[]` |
| `daily_download_limit` | 일일 다운로드 제한 | `0`(무제한) |
| `trusted_proxies` | 신뢰 프록시 IP 목록 | `[]` |
| `trusted_hops` | 신뢰 프록시 홉 수 | `1` |
| `webdav_allow_insecure` | 비TLS WebDAV 쓰기 메서드 허용 | `false` |

---

## API 엔드포인트

### 인증
| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/` | 로그인 |
| `GET` | `/logout` | 로그아웃 |
| `POST` | `/set_language` | 표준 언어 API (`{"lang":"ko|en","csrf_token":"..."}`) |
| `GET` | `/set_language/<lang>` | 레거시 호환 래퍼 (종료 예정: 2026-08-31) |

### 파일 관리
| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/browse/<path>` | 폴더 탐색 |
| `GET` | `/download/<path>` | 파일 다운로드 |
| `POST` | `/upload/<path>` | 파일 업로드 |
| `POST` | `/mkdir/<path>` | 폴더 생성 |
| `POST` | `/rename/<path>` | 이름 변경 |
| `POST` | `/delete/<path>` | 삭제 |
| `POST` | `/copy` | 복사 |
| `POST` | `/move` | 이동 |
| `GET` | `/zip/<path>` | 폴더 ZIP 다운로드 |

### v7.2 API
| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/healthz` | Liveness 체크 |
| `GET` | `/readyz` | Readiness 체크 |
| `GET` | `/api/list/<path>` | 페이지네이션 디렉터리 목록 |
| `GET` | `/api/dashboard/summary` | 대시보드 요약 |
| `GET` | `/api/indexer/status` | 인덱서 상태 |
| `GET` | `/api/active_sessions` | 활성 세션(관리자 전용) |
| `GET` | `/api/audit_log` | 감사 로그 조회 |
| `GET/POST` | `/api/permissions` | 폴더 권한 |
| `GET` | `/api/duplicates` | 중복 파일 조회 |
| `POST` | `/api/duplicates/scan` | 중복 스캔 시작 |
| `GET` | `/api/cloud/config` | 클라우드 동기화 설정(`mode: mock`) |
| `GET` | `/api/cloud/status` | 클라우드 동기화 상태(`mode: mock`) |
| `POST` | `/api/cloud/sync/<provider>` | Mock 동기화 작업 등록(`202 Accepted`) |

### 청크 업로드 API
| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/upload/chunk/init` | 청크 세션 생성 |
| `POST` | `/upload/chunk/<session_id>` | 단일 청크 업로드 |
| `POST` | `/upload/chunk/<session_id>/complete` | 무결성 검증 후 병합 |
| `POST` | `/upload/chunk/<session_id>/cancel` | 업로드 세션 취소 |

### 미디어/네트워크 API
| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/stream/hls/<path>/index.m3u8` | HLS 재생목록 |
| `GET` | `/webdav/` | WebDAV 엔드포인트 |
| `GET` | `/manifest.json` | PWA 매니페스트 |

### 보안 메모
- 로그인된 상태 변경 요청(`POST/PUT/PATCH/DELETE`)은 CSRF 검증이 필요합니다.
- `.webshare*` 등 숨김/시스템 경로는 다운로드/스트리밍/미리보기/WebDAV에서 차단됩니다.
- 비TLS WebDAV 쓰기 메서드는 기본적으로 차단됩니다.
- `/api/active_sessions`는 관리자 전용입니다.
- 공유 링크의 `hours`, `max_downloads`는 범위 검증됩니다.
- 감사 로그/공유 링크는 JSON 파일로 주기 저장됩니다.

---

## 프로젝트 구조

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

## 문제 해결

### 서버가 시작되지 않음
```text
Error: Address already in use
```
해결: 설정에서 포트를 변경하세요.

### `PyQt6` 오류
```text
ModuleNotFoundError: No module named 'PyQt6'
```
해결: `pip install pyqt6`

### 대용량 업로드 실패
- 100MB 이상 파일은 자동 청크 업로드를 사용합니다.
- 네트워크 불안정 시 재시도를 지원합니다.
- 최대 10GB를 지원합니다.

### 외부 네트워크 접속 불가
1. 방화벽에서 포트를 개방합니다.
2. 공유기 포트포워딩을 설정합니다.
3. `display_host`를 `0.0.0.0`으로 설정합니다.

---

## 라이선스

MIT License

Copyright (c) 2026 WebShare Pro

---

## 구현 정합성 업데이트 (2026-02-28)
- 보안/정합성 실행 계획 반영 완료:
  - 경로 검증(`validate_path`) 심볼릭 링크 우회 차단
  - 청크 업로드 소유권 검증 + 총량/동시성 제한
  - 공유 링크 `max_downloads` 원자적 reserve/rollback
  - 일반 실행/Docker 모두 동일 WebDAV WSGI 마운트 경로 사용
  - 시작 시 임시 업로드 폴더(`.webshare_uploads`, `.upload_temp`) 정리 복구
- Cloud Sync는 현재 **Mock/Beta scaffold**이며 `POST /api/cloud/sync/<provider>`는 `202 Accepted`를 반환합니다.
- 빌드 스펙 정합성:
  - `webshare.spec`, `WebSharePro.spec` 모두 `config.py`의 `APP_VERSION`을 기준으로 산출물명을 `WebSharePro_v{APP_VERSION}`로 맞췄습니다.

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
- PyInstaller 스펙에 `utils.api_errors`를 `hiddenimports`로 추가해, 동결 빌드에서도 표준 에러 유틸이 누락되지 않도록 맞췄습니다.
- `.gitignore`에 WebShare 런타임 임시 산출물(`.webshare_*.tmp`, `.webshare_*.json`)과 업로드/트랜스코드 임시 디렉터리 제외 규칙을 보강했습니다.

## Implementation Notes (2026-03-09)

- `pyrightconfig.json`을 추가해 실사용 코드와 테스트를 정적분석 범위로 고정하고, 보관용 `legacy/`는 제외했습니다.
- `config.py`의 `ConfigManager.get()`에 타입 오버로드를 추가해 Pylance/Pyright가 주요 설정 키를 구체 타입으로 추론하도록 정리했습니다.
- `typings/cachetools/__init__.pyi` 로컬 스텁과 `pyrightconfig.json`의 외부 source-warning 정리를 함께 적용해 `cachetools` 관련 Pylance 경고를 제거했습니다.
- `features.network`, `features.webdav_server`가 `importlib` 기반 선택 의존성 로딩으로 바뀌었기 때문에, `webshare.spec`와 `WebSharePro.spec` 모두 `miniupnpc`, `wsgidav.*` hidden import를 명시적으로 포함하도록 동기화했습니다.
- 개발 검증 기준선:
  - `pyright` -> `0 errors, 0 warnings`
  - `pytest -q` -> `44 passed, 1 skipped`
