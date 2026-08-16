#!/usr/bin/env python3
"""
WebShare Pro v7.2.5 - Main Entry Point
웹 기반 파일 공유 서버

Usage:
    python main.py
    python main.py --smoke
"""

import os
import shutil
import sys
import tempfile
import time
from typing import cast

# 패키지 경로 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webshare_app.core.config import ConfigData, conf, APP_TITLE
from webshare_app.utils.helpers import cleanup_upload_temp_dirs
from webshare_app.core.log_manager import logger
from webshare_app.server import ensure_runtime_initialized


def safe_print(message: str = ""):
    """Write to console when one exists; windowed PyInstaller builds may not have stdout."""
    stream = getattr(sys, "stdout", None) or getattr(sys, "__stdout__", None)
    if stream is None:
        return
    try:
        stream.write(str(message) + "\n")
        stream.flush()
    except Exception:
        pass


def configure_windows_dpi():
    """Enable high-DPI awareness on Windows only."""
    if sys.platform != 'win32':
        return

    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def cleanup_temp_files():
    """Delete stale upload temp directories and updater helpers at startup."""
    try:
        cleanup_upload_temp_dirs(conf.get('folder'))
    except Exception as e:
        logger.add(f"시작 시 임시 파일 정리 실패: {e}", "WARN")

    try:
        from webshare_app.core.update_installer import (
            cleanup_stale_update_helpers,
            resolve_update_staging_root,
        )

        staging_root = resolve_update_staging_root()
        cleanup_stale_update_helpers(staging_root, max_age_hours=24.0)
    except Exception:
        pass


def _prepare_smoke_runtime() -> tuple[str, bool]:
    smoke_root = os.environ.get("WEBSHARE_SMOKE_DIR")
    cleanup_after = False
    if not smoke_root:
        smoke_root = tempfile.mkdtemp(prefix="webshare_smoke_")
        cleanup_after = True

    config_dir = os.path.join(smoke_root, "config")
    shared_dir = os.path.join(smoke_root, "shared")
    os.makedirs(config_dir, exist_ok=True)
    os.makedirs(shared_dir, exist_ok=True)
    os.environ.setdefault("WEBSHARE_CONFIG_DIR", config_dir)
    conf.set("folder", shared_dir)
    conf.set("display_host", "127.0.0.1")
    return smoke_root, cleanup_after


def run_smoke_check() -> int:
    """Headless startup check for source and frozen PyInstaller builds."""
    smoke_root = ""
    cleanup_after = False
    original_config = dict(conf.config)
    original_config_dir = os.environ.get("WEBSHARE_CONFIG_DIR")
    from webshare_app.server import bootstrap as _server_bootstrap

    original_runtime_initialized = _server_bootstrap._runtime_initialized
    try:
        smoke_root, cleanup_after = _prepare_smoke_runtime()
        cleanup_temp_files()
        ensure_runtime_initialized()

        from webshare_app.app.factory import create_app

        app = create_app()
        with app.test_client() as client:
            required_checks = [
                ("/healthz", 200),
                ("/readyz", 200),
                ("/static/logo.png", 200),
            ]
            for path, expected_status in required_checks:
                response = client.get(path)
                if response.status_code != expected_status:
                    safe_print(f"SMOKE_FAIL {path}: {response.status_code} != {expected_status}")
                    return 1

        safe_print(f"SMOKE_OK {APP_TITLE}")
        return 0
    except Exception as exc:
        safe_print(f"SMOKE_FAIL {exc}")
        return 1
    finally:
        conf.config = cast(ConfigData, original_config)
        _server_bootstrap._runtime_initialized = original_runtime_initialized
        if original_config_dir is None:
            os.environ.pop("WEBSHARE_CONFIG_DIR", None)
        else:
            os.environ["WEBSHARE_CONFIG_DIR"] = original_config_dir
        if cleanup_after and smoke_root:
            shutil.rmtree(smoke_root, ignore_errors=True)


def main(argv: list[str] | None = None):
    """Main entry point."""
    import argparse
    parser = argparse.ArgumentParser(description=APP_TITLE, add_help=False)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--apply-update", action="store_true")
    parser.add_argument("--update-target", default="")
    parser.add_argument("--update-staged", default="")
    parser.add_argument("--update-backup", default="")
    parser.add_argument("--update-parent-pid", default=0, type=int)
    parser.add_argument("--update-expected-sha256", default="")
    parser.add_argument("--update-expected-size", default=0, type=int)
    parser.add_argument("--update-result-file", default="")

    parsed_args, _ = parser.parse_known_args(sys.argv[1:] if argv is None else argv)

    if parsed_args.smoke:
        sys.exit(run_smoke_check())

    if parsed_args.apply_update:
        from scripts.apply_update import main as apply_update_main

        sys.exit(
            apply_update_main(
                [
                    "--target",
                    parsed_args.update_target,
                    "--staged",
                    parsed_args.update_staged,
                    "--backup",
                    parsed_args.update_backup,
                    "--parent-pid",
                    str(parsed_args.update_parent_pid),
                    "--expected-sha256",
                    parsed_args.update_expected_sha256,
                    "--expected-size",
                    str(parsed_args.update_expected_size),
                    "--result-file",
                    parsed_args.update_result_file,
                ]
            )
        )

    configure_windows_dpi()

    try:
        from webshare_app.security.deployment_guard import log_deployment_warnings

        for warning in log_deployment_warnings():
            safe_print(f"[SECURITY] {warning}")
    except Exception:
        pass

    safe_print(f"\n{'='*50}")
    safe_print(f"  {APP_TITLE}")
    safe_print("  웹 기반 파일 공유 서버")
    safe_print(f"{'='*50}\n")

    # startup cleanup + runtime initialization
    cleanup_temp_files()
    ensure_runtime_initialized()

    # consume previous update result if any
    try:
        from webshare_app.core.update_installer import (
            consume_update_result,
            resolve_update_staging_root,
            update_result_path,
        )

        staging_root = resolve_update_staging_root()
        update_res = consume_update_result(update_result_path(staging_root))
        if update_res:
            res_status = update_res.get("status")
            if res_status == "applied":
                logger.add("이전 업데이트가 성공적으로 적용되었습니다.", "INFO")
            else:
                logger.add(
                    f"이전 업데이트 실패 (상태: {res_status}, 에러: {update_res.get('error', 'unknown')})",
                    "WARN",
                )
    except Exception as exc:
        logger.add(f"업데이트 결과 확인 중 오류: {exc}", "WARN")

    # GUI 시작
    try:
        # PyQt6 시도
        from webshare_app.gui.pyqt_gui import run_pyqt6_gui

        os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '1'
        os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'

        safe_print("[INFO] PyQt6 GUI 시작")
        sys.exit(run_pyqt6_gui())

    except ImportError as e:
        safe_print(f"[WARN] PyQt6 로드 실패: {e}")
        safe_print("[INFO] Tkinter fallback 사용")

        # Tkinter fallback
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox

            root = tk.Tk()
            root.title(APP_TITLE)
            root.geometry("500x400")

            frame = ttk.Frame(root, padding=20)
            frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(frame, text=APP_TITLE, font=('', 16, 'bold')).pack(pady=10)
            ttk.Label(frame, text="PyQt6가 설치되지 않아 기본 Tkinter GUI를 사용합니다.").pack(pady=5)
            ttk.Label(frame, text=f"공유 폴더: {conf.get('folder')}").pack(pady=5)
            ttk.Label(frame, text=f"포트: {conf.get('port')}").pack(pady=5)

            def start_server_tk():
                from webshare_app.server import get_server_startup_error, start_server
                if start_server(wait_ready=True, timeout=5.0):
                    messagebox.showinfo("성공", f"서버가 시작되었습니다.\nhttp://127.0.0.1:{conf.get('port')}")
                else:
                    messagebox.showerror("오류", get_server_startup_error() or "서버 시작에 실패했습니다.")

            ttk.Button(frame, text="서버 시작", command=start_server_tk).pack(pady=20)

            root.mainloop()

        except ImportError:
            safe_print("[ERROR] GUI를 사용할 수 없습니다. Flask 서버만 시작합니다.")
            from webshare_app.server import start_server
            start_server()

            # 서버가 종료될 때까지 대기
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                safe_print("\n[INFO] 서버를 종료합니다.")


if __name__ == '__main__':
    main()
