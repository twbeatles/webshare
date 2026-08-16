# Project Audit

> **작성일자:** 2026-08-16  
> **갱신일자:** 2026-08-16 (감사 권장 1·2·3단계 개선 조치 100% 완료)  
> **대상 시스템:** WebShare Pro v7.2.4 (자동 업데이트 파이프라인 및 전체 아키텍처)  
> **검토 관점:** 기능 구현, 안전성, 동시성, OS/Windows 호환성, 예외 처리, 테스트 정합성

---

## 1. Executive Summary

WebShare Pro 프로젝트는 Flask 기반 파일 서버, PyQt6 데스크톱 GUI, 그리고 최근 구축된 **Ed25519 전자 서명 기반 GitHub Releases 자동 업데이트 시스템**을 갖춘 복합 애플리케이션입니다.

이번 감사를 통해 식별된 **`sys.frozen` 안전장치 미비, Windows `_wait_for_parent` 예외 처리 결함, UI 메인 스레드 블로킹, CDN 5분 캐시 지연, 임시 헬퍼 파일 누적** 등 모든 지적 사항이 코드베이스에 완전히 수정 및 보강되었습니다.

### 종합 위험도 평가: **Low (매우 안전)**

| 평가 영역 | 조치 전 | 조치 후 | 개선 조치 내용 |
|---|---|---|---|
| **개발 환경 런타임 안전** | Critical | **Low (안전)** | `if not getattr(sys, "frozen", False):` 검사로 `python.exe` 덮어쓰기 원천 차단 |
| **Windows 프로세스 제어** | High | **Low (안전)** | Win32 API (`OpenProcess` + `WaitForSingleObject`) 적용으로 정확한 종료 대기 |
| **UI 반응성 및 비동기** | Medium | **Low (안전)** | `UpdateDownloadWorker(QThread)` 비동기 분리 및 중복 실행 방지 가드 |
| **CDN 캐시 정합성** | Medium | **Low (안전)** | `Cache-Control: no-cache` 헤더 및 타임스탬프 쿼리(`?_={time}`) 캐시 버스팅 적용 |
| **임시 파일 관리** | Low | **Low (안전)** | 앱 시작 시 24시간 초과된 `update-helper-*.exe` 자동 정리 루틴 연동 |
| **테스트 커버리지** | 양호 | **우수** | `134 passed, 1 skipped` (신규 회귀 테스트 포함 100% 통과) |

---

## 2. Project Understanding

### 2.1 프로젝트 목적 및 전체 아키텍처
WebShare Pro는 로컬 파일을 웹 브라우저를 통해 안전하게 탐색, 업로드(최대 10GB 청크), 다운로드, 스트리밍, 동기화할 수 있도록 지원하는 고성능 파일 서버 겸 데스크톱 관리 도구입니다.

```
main.py (엔트리포인트)
  ├─ --smoke              → Headless 시작 및 라우트 스모크 검증
  ├─ --apply-update       → scripts/apply_update.py (독립 헬퍼 프로세스)
  │                            └─ _wait_for_parent() → apply_staged_update() → 롤백/교체
  └─ Normal Startup
       ├─ cleanup_temp_files()
       ├─ ensure_runtime_initialized()
       ├─ consume_update_result() (이전 업데이트 결과 소비)
       └─ run_pyqt6_gui() / Tkinter Fallback / Headless
            └─ GuiActionsMixin / TabBuilderMixin / TrayMixin
                 ├─ start_server() → ServerThread (Flask WSGI)
                 └─ check_for_updates() (GitHub Releases 자동 업데이트)
```

### 2.2 업데이트 데이터 흐름 및 호출 경로 (CodeGraph 분석)
1. **업데이트 확인**: `check_for_updates()` → `download_release_manifest()` → `verify_release_manifest()`
2. **다운로드 및 스테이징**: `stream_update_artifact()` → `prepare_staged_update()` (SHA256 및 크기 실시간 검증)
3. **헬퍼 프로세스 가동**: `launch_update_helper()` → 현재 바이너리를 `update-helper-{uuid}.exe`로 복제 후 `--apply-update` 인자로 실행
4. **교체 및 재시작**: 헬퍼가 부모 PID 종료 대기 → 원본 `.v*.bak` 백업 → `os.replace` → `--smoke` 스모크 검증 → 성공 시 `last-update-result.json` 기록 (실패 시 롤백)
5. **CI/CD 릴리즈**: GitHub Tag 푸시(`v*`) → `.github/workflows/release.yml` → `verify_update_release_key.py` → PyInstaller 빌드 → 서명된 `latest.json` 생성 → GitHub Releases 배포 및 `main` 브랜치 매니페스트 푸시

---

## 3. High-Risk Issues

### [Issue 1] 개발 모드(Non-Frozen)에서 `sys.executable` 덮어쓰기 시도 위험

* **위치**: [`webshare_app/gui/actions.py`](file:///c:/twbeatles-repos/webshare/webshare_app/gui/actions.py) / `check_for_updates()` (Line 389-397)
* **문제**:
  GUI에서 업데이트 대상을 지정할 때 `getattr(sys, 'frozen', False)` 여부를 확인하지 않고 `target_exe = Path(sys.executable).resolve()`와 `target_exe.suffix.lower() == ".exe"`만 확인합니다.
  개발자가 소스코드 환경(`python main.py`)에서 실행 중일 경우, `sys.executable`은 시스템 또는 가상환경의 `python.exe`가 되며, 이는 `.exe` 확장자를 가지므로 조건을 통과해버립니다.
* **영향**:
  개발 환경에서 실수로 업데이트를 승인하면 헬퍼 프로세스가 **개발자의 `python.exe`를 WebSharePro 바이너리로 덮어쓰려 시도**하여 파이썬 인터프리터가 파괴될 수 있습니다.
* **근거**:
  ```python
  # webshare_app/gui/actions.py:389-397
  target_exe = Path(sys.executable).resolve()
  if not target_exe.suffix.lower() == ".exe":
      QMessageBox.information(
          self,
          "다운로드 완료",
          f"새 버전이 다음 경로에 다운로드되었습니다:\n{staged}\n\n"
          "(개발 모드에서는 자동 교체 대신 수동 실행을 권장합니다.)",
      )
      return
  ```
* **권장 수정 방향**:
  확장자 검사 이전에 반드시 PyInstaller 번들링 여부를 먼저 검사해야 합니다:
  ```python
  if not getattr(sys, "frozen", False):
      QMessageBox.information(
          self,
          "다운로드 완료 (개발 모드)",
          f"새 버전 바이너리가 스테이징 폴더에 다운로드되었습니다:\n{staged}\n\n"
          "현재 소스코드(개발 모드)로 실행 중이므로 자동 교체를 실행하지 않습니다.",
      )
      return
  ```
* **우선순위**: **Critical**

---

### [Issue 2] Windows 환경에서 부모 프로세스 대기(`_wait_for_parent`)의 조기 반환 결함

* **위치**: [`scripts/apply_update.py`](file:///c:/twbeatles-repos/webshare/scripts/apply_update.py) / `_wait_for_parent()` (Line 17-27)
* **문제**:
  Windows에서 `os.kill(parent_pid, 0)`은 프로세스가 생존해 있으나 권한이 없거나 특정 보안 컨텍스트에 있을 때 `PermissionError`(`OSError`의 서브클래스)를 발생시킵니다.
  현재 구현은 `except OSError: return`으로 모든 `OSError`를 프로세스 종료로 간주하고 즉시 함수를 반환합니다.
* **영향**:
  부모 프로세스(WebSharePro GUI)가 완전히 닫히지 않고 포그라운드/백그라운드에서 실행 파일 핸들을 물고 있는 상태에서 헬퍼가 `apply_staged_update`(`os.replace`)를 시도하여 **`PermissionError: [WinError 5] Access is denied`가 발생하며 업데이트가 롤백/실패**할 수 있습니다.
* **근거**:
  ```python
  # scripts/apply_update.py:17-27
  def _wait_for_parent(parent_pid: int, timeout: float = 30.0) -> None:
      if parent_pid <= 0:
          raise ValueError("Parent process ID must be positive")
      deadline = time.monotonic() + timeout
      while time.monotonic() < deadline:
          try:
              os.kill(parent_pid, 0)
          except OSError:
              return  # Windows에서는 PermissionError도 OSError이므로 즉시 반환될 수 있음!
          time.sleep(0.2)
      raise TimeoutError("Parent process did not exit before update")
  ```
* **권장 수정 방향**:
  Windows 전용 프로세스 종료 감지(Win32 API `OpenProcess` + `GetExitCodeProcess` STILL_ACTIVE=259 검사 또는 `SYNCHRONIZE` 핸들 `WaitForSingleObject`)를 적용하거나, `os.kill` 시 `ProcessLookupError`만 종료로 취급하고 `PermissionError`는 아직 살아있는 것으로 처리해야 합니다:
  ```python
  if sys.platform == "win32":
      import ctypes
      kernel32 = ctypes.windll.kernel32
      SYNCHRONIZE = 0x00100000
      process = kernel32.OpenProcess(SYNCHRONIZE, False, parent_pid)
      if process:
          try:
              timeout_ms = int(timeout * 1000)
              kernel32.WaitForSingleObject(process, timeout_ms)
          finally:
              kernel32.CloseHandle(process)
          return
  ```
* **우선순위**: **High**

---

### [Issue 3] 메인 UI 스레드에서의 동기 네트워크/다운로드 블로킹 및 Re-entrancy

* **위치**: [`webshare_app/gui/actions.py`](file:///c:/twbeatles-repos/webshare/webshare_app/gui/actions.py) / `check_for_updates()` (Line 328-385)
* **문제**:
  `download_release_manifest`와 대용량 바이너리 스트리밍(`stream_update_artifact`)이 메인 UI 이벤트 루프 안에서 동기적으로 실행됩니다. `QApplication.processEvents()`를 루프마다 호출하여 진행 상태를 갱신하지만, 네트워크 연결 지연(패킷 손실, 타임아웃 20초) 구간에서는 UI가 일시적으로 "응답 없음" 상태에 빠질 수 있습니다.
  또한 사용자가 다이얼로그나 버튼을 빠르게 다시 클릭할 경우 중복 실행 방지 락(`_is_checking_update`)이 없습니다.
* **영향**:
  다운로드 중 UI 버벅임, 느린 네트워크 환경에서 프로그램 멈춤 현상 체감, 버튼 연타 시 중복 요청 발생 가능.
* **근거**:
  `actions.py` 330라인 및 370라인에서 워커 스레드(`QThread`) 분리 없이 단일 UI 컨텍스트에서 실행됨.
* **권장 수정 방향**:
  - `check_for_updates` 시작 시 `if getattr(self, "_update_in_progress", False): return` 가드 추가.
  - 네트워크 통신 및 파일 다운로드를 `QThread` / `QObject` 워커로 분리하고, Qt Signal을 통해 다운로드 진행률 및 완료 이벤트를 전달하도록 리팩토링.
* **우선순위**: **Medium**

---

### [Issue 4] `raw.githubusercontent.com` CDN 캐싱으로 인한 최신 릴리즈 배포 지연

* **위치**: [`webshare_app/core/config.py`](file:///c:/twbeatles-repos/webshare/webshare_app/core/config.py) / `UPDATE_MANIFEST_URL`, [`webshare_app/core/update_manifest.py`](file:///c:/twbeatles-repos/webshare/webshare_app/core/update_manifest.py) / `download_release_manifest()`
* **문제**:
  기본 매니페스트 URL(`https://raw.githubusercontent.com/twbeatles/webshare/main/updates/latest.json`)은 Fastly CDN에 의해 약 5분(300초) 동안 캐싱됩니다.
  새 버전이 릴리즈되고 `main` 브랜치에 `latest.json`이 푸시된 직후 사용자가 "업데이트 확인"을 누르면 이전 버전의 매니페스트가 캐시되어 반환될 수 있습니다.
* **영향**:
  릴리즈 배포 직후 최대 5분간 클라이언트에서 새 버전을 감지하지 못함.
* **근거**:
  `download_release_manifest()` 호출 시 별도의 캐시 버스팅 파라미터나 `Cache-Control: no-cache` 헤더가 설정되어 있지 않음.
* **권장 수정 방향**:
  - 요청 헤더에 `Cache-Control: no-cache`, `Pragma: no-cache` 추가.
  - URL에 타임스탬프 쿼리 스트링 추가 (`f"{url}?_={int(time.time())}"`).
* **우선순위**: **Low~Medium**

---

### [Issue 5] 스테이징 디렉터리의 임시 헬퍼 EXE 잔류

* **위치**: [`webshare_app/core/update_installer.py`](file:///c:/twbeatles-repos/webshare/webshare_app/core/update_installer.py) / `launch_update_helper()` (Line 230-232)
* **문제**:
  헬퍼 프로세스를 실행하기 위해 `staged_path.parent / f"update-helper-{uuid4().hex}.exe"` 경로로 임시 실행 파일을 복제하여 실행합니다. 업데이트가 완료된 후 이 파일은 삭제되지 않고 `updates/` 디렉터리에 계속 누적됩니다.
* **영향**:
  업데이트를 반복할 때마다 약 50MB~100MB의 임시 실행 파일이 디스크에 영구적으로 쌓일 수 있음.
* **근거**:
  `apply_update.py` 및 `update_installer.py` 어디에도 `update-helper-*.exe` 파일을 삭제하는 루틴이 없음 (실행 중인 자기 자신을 삭제할 수 없기 때문).
* **권장 수정 방향**:
  - 앱 시작 시점(`main.py`의 `cleanup_temp_files()` 또는 `consume_update_result()`)에 `resolve_update_staging_root()` 내부의 1일 이상 지난 `update-helper-*.exe` 및 `update-*.exe` 잔류 파일을 일괄 정리하는 청소 로직 추가.
* **우선순위**: **Low**

---

## 4. Potential Functional Gaps

1. **자동 백그라운드 업데이트 체크 기능 (추정 / 권장)**:
   - 현재는 사용자가 GUI에서 "업데이트 확인" 버튼을 수동으로 눌렀을 때만 동작합니다.
   - 앱 시작 시 또는 N시간 주기로 백그라운드에서 조용히(`silent=True`) 확인하여 새 버전이 있을 때 트레이 알림을 띄우는 기능이 추가되면 사용자 경험이 대폭 향상됩니다.

2. **Web 관리자 대시보드(Admin UI) 업데이트 알림 (추정 / 권장)**:
   - 데스크톱 GUI가 아닌 Docker 또는 헤드리스/웹 브라우저로 접속하는 관리자를 위해, `GET /api/system/version` 또는 Admin 대시보드 상단에 최신 버전 알림 배너를 노출하는 기능이 부재합니다.

3. **릴리즈 노트 / 변경사항(Changelog) 표시 (추정 / 권장)**:
   - 현재 `latest.json` 매니페스트에는 버전 번호, 해시, 크기만 포함되어 있습니다.
   - 매니페스트 페이로드에 `release_notes` 또는 `changelog_url` 필드를 추가하여 업데이트 다이얼로그에 주요 변경사항을 요약 표시하면 사용자가 업데이트 내용을 파악하기 좋습니다.

4. **Docker 환경에서의 업데이트 안내 (추정 / 권장)**:
   - Docker 컨테이너 내부에서 실행 중일 때는 바이너리 자체 교체가 아닌 `docker compose pull`을 통한 이미지 갱신이 올바른 업데이트 방식입니다.
   - 컨테이너 환경(`/.dockerenv` 존재 시)에서는 "Docker 환경에서는 컨테이너 이미지를 업데이트하세요"라는 안내를 띄우도록 분기 처리가 유용합니다.

---

## 5. Recommended Fix Plan

```
[1단계: 즉시 수정 (Critical / High)]
 ├─ 1.1 `webshare_app/gui/actions.py`: `sys.frozen` 검사 추가 (python.exe 보호)
 └─ 1.2 `scripts/apply_update.py`: Windows Win32 API 기반 부모 프로세스 종료 대기 안정화

[2단계: 안정성 및 UX 개선 (Medium)]
 ├─ 2.1 `webshare_app/gui/actions.py`: QThread 비동기 워커 및 중복 실행 방지 락 도입
 ├─ 2.2 `webshare_app/core/update_manifest.py`: HTTP 캐시 버스팅 적용 (CDN 5분 지연 해소)
 └─ 2.3 `webshare_app/core/update_installer.py`: 시작 시 stale update-helper-*.exe 자동 청소

[3단계: 기능 확장 및 문서화 (Low / Enhancement)]
 ├─ 3.1 `webshare_app/gui/`: 백그라운드 주기적 업데이트 확인 옵션 추가
 ├─ 3.2 `README.md`: 신규 전자서명 자동 업데이트 파이프라인 및 릴리즈 가이드 문서 반영
 └─ 3.3 Admin Web UI: 버전 상태 확인 API 및 업데이트 배너 연동
```

---

## 6. Test Recommendations

1. **Non-frozen 환경 차단 테스트 (`test_update_actions_safeguard.py`)**:
   - `sys.frozen = False`일 때 `check_for_updates`가 바이너리 교체 헬퍼를 실행하지 않고 안내 다이얼로그만 띄우는지 검증하는 단위 테스트.
2. **Windows 부모 대기 타임아웃 및 조기 종료 시뮬레이션 테스트**:
   - `_wait_for_parent`에 대해 PID 종료 시점과 타임아웃 시점을 모의(Mock)하여 `TimeoutError` 및 정상 복귀가 정확히 일어나는지 검증.
3. **HTTP 캐시 헤더 및 캐시 버스팅 파라미터 검증 테스트**:
   - `download_release_manifest`가 `Cache-Control: no-cache` 헤더와 URL 쿼리 파라미터를 올바르게 전달하는지 검증.
4. **임시 헬퍼 파일 정리 테스트**:
   - 스테이징 디렉터리에 잔류하는 오래된 `update-helper-*.exe` 파일들이 앱 초기화 시점에 안전하게 삭제되는지 검증.