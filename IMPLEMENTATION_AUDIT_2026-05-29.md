# WebShare Pro 구현/문서 정합성 감사 (2026-05-29)

## 점검 범위

- 기준 문서: `README.md`, `README_EN.md`
- 스펙 파일: `WebSharePro.spec`, `webshare.spec`
- ignore 정책: `.gitignore`
- 구현 표면: `webshare_app/`, `templates/partials/`, `static/js/`, `static/vendor/`, `docker_entrypoint.py`, `docker-compose.yml`
- 참고: `CLAUDE.md`/`claude.md`는 현재 프로젝트 트리에서 발견되지 않음

## 반영 완료 항목

- Google Drive OAuth popup 결과 페이지의 HTML/JS escaping을 적용했다.
- Google Drive Client Secret은 빈 값 저장 시 기존 값을 유지하고, UI의 명시 삭제 체크박스를 통해서만 제거되도록 수정했다.
- copy/move 자기 하위 경로 검사는 Windows 대소문자 비민감 파일 시스템을 고려해 `normcase` + `commonpath` 기반으로 보강했다.
- overwrite copy/move와 version restore는 대상 교체 전 기존 파일을 버전 백업한다. 폴더 overwrite는 기존 폴더 안의 일반 파일도 버전 백업한다.
- 청크 업로드 commit 이후 index/audit 후처리 실패가 완료 파일을 삭제하지 않도록 transaction 경계를 분리했다.
- 특수문자 경로의 browse redirect, breadcrumb, 주요 프론트엔드 URL 조립을 segment-safe encoding으로 통일했다.
- 공유 링크 최대 다운로드 횟수 초과 응답은 HTTP 429를 반환한다.
- 일반 업로드와 청크 업로드 init에 disk free-space preflight와 process-local reservation을 적용했다.
- Font Awesome, marked, DOMPurify, hls.js, highlight.js는 `static/vendor/` 로컬 asset을 우선 사용하고 CDN은 fallback으로만 사용한다.
- Docker entrypoint는 `WEBSHARE_ADMIN_PASSWORD`, `WEBSHARE_GUEST_PASSWORD`, `WEBSHARE_SECRET_KEY`를 지원하고, 공개 바인딩에서 기본 비밀번호 사용 시 warning을 남긴다.

## 2026-06-08 배포 실행 추가 점검

- `console=False` PyInstaller EXE에서 `sys.stdout`/`sys.stderr`가 없는 windowed 실행을 고려해 시작 배너와 로그 출력이 콘솔 스트림 부재로 크래시하지 않도록 보강했다.
- `main.py --smoke` 경로를 추가해 GUI를 띄우지 않고 임시 공유 폴더에서 런타임 초기화, `/healthz`, `/readyz`, bundled static asset 로딩을 검증할 수 있게 했다.
- `requirements-optional.txt`는 Python 3.14 환경에서 wheel 빌드가 실패하는 `miniupnpc`를 기본 선택 설치에서 제외한다. 이 경우 UPnP capability만 비활성화되고, 서버/GUI/파일 공유/패키징은 계속 동작한다.

## 문서/스펙 정합성

- `README.md`와 `README_EN.md`는 업로드 disk guard, secret 유지/삭제 정책, local vendor asset, Docker env, PyInstaller 명령, 최신 검증 기준을 설명하도록 갱신했다.
- `WebSharePro.spec`와 `webshare.spec`는 동일한 PyInstaller 수집 정책을 갖도록 동기화했다.
- 두 spec 모두 `APP_VERSION`을 `webshare_app/core/config.py`에서 읽고, `templates/`, `static/`, `collect_submodules("webshare_app")`, API error/helper/runtime route hiddenimports를 포함한다.
- `static/vendor/`는 패키지/폐쇄망 실행을 위한 동봉 asset이므로 `.gitignore` 대상이 아니라 추적 대상이다.

## .gitignore 검증

실제 파일명 기준으로 다음 ignore 커버리지를 확인했다.

- `webshare_config.json`
- `shared_files/foo.txt`
- `build/WebSharePro/x.toc`
- `dist/WebSharePro_v7.2.4.exe`
- `.pytest_tmp/x`, `.pytest_cache/x`
- `__pycache__/x.pyc`
- `.webshare_merge_test.tmp`
- `shared_files/.webshare_merge_test.tmp`
- `shared_files/.upload_temp/session/chunk_00000`
- `cloud_secrets.json`

`static/vendor/marked/marked.min.js`는 `NOT_IGNORED`로 확인했다. 따라서 이번 정합성 패스에서는 `.gitignore` 수정이 필요하지 않다.

## 검증 결과

- `python -m pip install -r requirements.txt` -> 필수 런타임 의존성 설치 성공
- `python -m pip install -r requirements-optional.txt` -> Python 3.14에서 `miniupnpc` skip, 나머지 선택 의존성 설치 성공
- `pytest -q --basetemp .pytest_tmp` -> `103 passed, 1 skipped`
- `pyright` -> `0 errors, 0 warnings, 0 informations`
- `git diff --check` -> whitespace 오류 없음
- `python main.py --smoke` -> `SMOKE_OK WebShare Pro v7.2.4`
- `python -m PyInstaller --clean --noconfirm WebSharePro.spec` -> `dist/WebSharePro_v7.2.4.exe` 생성 성공
- `dist/WebSharePro_v7.2.4.exe --smoke` -> `EXIT_CODE=0`
- GUI EXE 시작 smoke -> 5초 후 프로세스 실행 상태 확인 후 종료

## 푸쉬/빌드 기준

- 사용자 요청에 따라 삭제와 untracked 파일을 포함하는 `git add -A` 범위로 푸쉬한다.
- 푸쉬 후 `python -m PyInstaller --clean --noconfirm WebSharePro.spec`로 실제 빌드를 다시 수행하고, `dist/WebSharePro_v7.2.4.exe --smoke` 종료 코드 `0`을 확인한다.
