"""Go backend subprocess launcher (migration plan Phase 2).

Responsibilities:
- locate the ``webshare-core`` binary (dev tree / PyInstaller bundle / PATH)
- spawn ``webshare-core serve`` with a per-run random control token
- poll health/readiness, capture logs, graceful shutdown, crash detection

The control token is passed via ``WEBSHARE_CONTROL_TOKEN`` env only:
never written to config, never logged, never returned by any API.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

CONTROL_TOKEN_ENV = "WEBSHARE_CONTROL_TOKEN"
BACKEND_ENV = "WEBSHARE_SERVER_BACKEND"
BINARY_ENV = "WEBSHARE_CORE_BIN"

_BINARY_NAMES = ("webshare-core.exe", "webshare-core")


def backend_name() -> str:
    """Active backend: ``go`` (default since Milestone J) or ``python``."""
    return os.environ.get(BACKEND_ENV, "go").strip().lower() or "go"


def generate_control_token() -> str:
    """Fresh 256-bit random control token for one Go process run."""
    return secrets.token_hex(32)


def find_binary() -> Optional[str]:
    """Locate the Go core binary; ``None`` when not installed yet."""
    override = os.environ.get(BINARY_ENV)
    if override:
        p = Path(override)
        if p.is_file():
            return str(p)
        return None

    candidates: list[Path] = []
    # PyInstaller bundle layout (webshare-core.exe shipped next to the app).
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        for name in _BINARY_NAMES:
            candidates.append(Path(meipass) / name)
    # Portable / installed layout: next to the running executable or repo root.
    here = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
    for base in (here, here.parent, Path.cwd(), Path.cwd() / "go-core"):
        for name in _BINARY_NAMES:
            candidates.append(base / name)
    for c in candidates:
        if c.is_file():
            return str(c)
    for name in _BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


class GoServerProcess:
    """Manages one ``webshare-core serve`` child process."""

    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.startup_error = ""
        self.control_token = ""
        self.base_url = ""
        self._log_lock = threading.Lock()
        self._log_tail: list[str] = []

    # -- lifecycle -----------------------------------------------------

    def start(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        config_path: Optional[str] = None,
        timeout: float = 15.0,
    ) -> bool:
        if self.is_alive():
            self.startup_error = "Go 서버가 이미 실행 중입니다."
            return False
        binary = find_binary()
        if not binary:
            self.startup_error = (
                "webshare-core 바이너리를 찾을 수 없습니다. "
                f"{BINARY_ENV} 경로를 지정하거나 go-core를 빌드하세요."
            )
            return False
        self.control_token = generate_control_token()
        env = dict(os.environ)
        env[CONTROL_TOKEN_ENV] = self.control_token
        cmd = [binary, "serve", "--host", host, "--port", str(port),
               "--parent-pid", str(os.getpid())]
        if config_path:
            cmd += ["--config", config_path]
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
        except OSError as exc:
            self.startup_error = f"Go 서버 시작 실패: {exc}"
            self.proc = None
            return False
        threading.Thread(target=self._drain_output, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{port}"
        if not self._wait_ready(timeout=timeout):
            self.startup_error = self.startup_error or (
                f"Go 서버 준비 대기 시간이 초과되었습니다. ({timeout}초)"
            )
            self._terminate()
            return False
        self.startup_error = ""
        return True

    def shutdown(self, timeout: float = 10.0) -> bool:
        proc = self.proc
        if proc is None or proc.poll() is not None:
            self.proc = None
            return False
        # Graceful path: loopback-only control endpoint with the run token.
        try:
            req = urllib.request.Request(
                self.base_url + "/_control/shutdown",
                data=b"",
                method="POST",
                headers={"X-Control-Token": self.control_token},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    raise OSError(f"shutdown status {resp.status}")
            proc.wait(timeout=timeout)
        except Exception:
            self._terminate()
        finally:
            self.proc = None
            self.control_token = ""
        return True

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def crashed(self) -> bool:
        """True when the child exited on its own (startup error holds the code)."""
        proc = self.proc
        if proc is None:
            return False
        code = proc.poll()
        if code is None:
            return False
        if not self.startup_error:
            self.startup_error = f"Go 서버가 비정상 종료되었습니다. (exit={code})"
        return True

    # -- diagnostics ---------------------------------------------------

    def recent_logs(self, limit: int = 50) -> list[str]:
        with self._log_lock:
            return list(self._log_tail[-limit:])

    # -- internals -----------------------------------------------------

    def _drain_output(self) -> None:
        proc = self.proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                with self._log_lock:
                    self._log_tail.append(line.rstrip("\n"))
                    del self._log_tail[:-200]
        except Exception:
            pass

    def _wait_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.1, timeout)
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                code = self.proc.poll()
                self.startup_error = f"Go 서버가 시작 중 종료되었습니다. (exit={code})"
                return False
            try:
                with urllib.request.urlopen(self.base_url + "/readyz", timeout=2) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass
            time.sleep(0.2)
        return False

    def _terminate(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        finally:
            self.control_token = ""
