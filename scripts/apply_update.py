from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from webshare_app.core.update_installer import apply_staged_update, write_update_result


def _wait_for_parent(parent_pid: int, timeout: float = 30.0) -> None:
    if parent_pid <= 0:
        raise ValueError("Parent process ID must be positive")

    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            SYNCHRONIZE = 0x00100000
            WAIT_TIMEOUT = 0x00000102
            WAIT_FAILED = 0xFFFFFFFF
            process = kernel32.OpenProcess(SYNCHRONIZE, False, int(parent_pid))
            if process:
                try:
                    timeout_ms = int(max(0.0, timeout) * 1000)
                    res = kernel32.WaitForSingleObject(process, timeout_ms)
                    if res == WAIT_TIMEOUT:
                        raise TimeoutError("Parent process did not exit before update timeout")
                    return
                finally:
                    kernel32.CloseHandle(process)
            else:
                # OpenProcess failed - process does not exist or already exited
                return
        except TimeoutError:
            raise
        except Exception:
            # Fallback to polling loop if ctypes fails
            pass

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(parent_pid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            # Process is still running but caller lacks permission to signal it
            pass
        except OSError:
            # Other OS errors (e.g. invalid param / process gone)
            return
        time.sleep(0.2)
    raise TimeoutError("Parent process did not exit before update")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply staged WebShare Pro update")
    parser.add_argument("--target", required=True)
    parser.add_argument("--staged", required=True)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--expected-size", required=True, type=int)
    parser.add_argument("--result-file", required=True)
    args = parser.parse_args(argv)
    base_result = {
        "target": str(Path(args.target).resolve()),
        "backup": str(Path(args.backup).resolve()),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        _wait_for_parent(args.parent_pid)
        apply_staged_update(
            target=Path(args.target),
            staged=Path(args.staged),
            backup=Path(args.backup),
            expected_sha256=args.expected_sha256,
            expected_size=args.expected_size,
        )
    except Exception as exc:
        status = "rolled_back" if "rolled back" in str(exc).lower() else "failed"
        write_update_result(
            args.result_file,
            {**base_result, "status": status, "error": str(exc)},
        )
        return 1
    write_update_result(args.result_file, {**base_result, "status": "applied"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
