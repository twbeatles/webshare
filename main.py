#!/usr/bin/env python3
"""
WebShare Pro v7.2 - Main Entry Point
웹 기반 파일 공유 서버

Usage:
    python main.py
"""

import os
import sys
import time

# DPI 설정 (Windows)
try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

# 패키지 경로 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import conf, APP_TITLE
from utils.log_manager import logger
from server import ensure_runtime_initialized


def cleanup_temp_files():
    """시작 시 임시 업로드 폴더 정리"""
    import shutil
    try:
        temp_dir = os.path.join(conf.get('folder'), '.webshare_uploads')
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.add("임시 업로드 파일 정리 완료")
    except Exception as e:
        logger.add(f"임시 파일 정리 실패: {e}", "WARN")


def main():
    """메인 진입점"""
    print(f"\n{'='*50}")
    print(f"  {APP_TITLE}")
    print(f"  웹 기반 파일 공유 서버")
    print(f"{'='*50}\n")
    
    # 초기화
    cleanup_temp_files()
    ensure_runtime_initialized()
    
    # GUI 시작
    try:
        # PyQt6 시도
        from gui.pyqt_gui import run_pyqt6_gui
        
        os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '1'
        os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'
        
        print("[INFO] PyQt6 GUI 시작")
        sys.exit(run_pyqt6_gui())
        
    except ImportError as e:
        print(f"[WARN] PyQt6 로드 실패: {e}")
        print("[INFO] Tkinter fallback 사용")
        
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
                from server import start_server
                if start_server():
                    messagebox.showinfo("성공", f"서버가 시작되었습니다.\nhttp://127.0.0.1:{conf.get('port')}")
            
            ttk.Button(frame, text="서버 시작", command=start_server_tk).pack(pady=20)
            
            root.mainloop()
            
        except ImportError:
            print("[ERROR] GUI를 사용할 수 없습니다. Flask 서버만 시작합니다.")
            from server import start_server
            start_server()
            
            # 서버가 종료될 때까지 대기
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[INFO] 서버를 종료합니다.")


if __name__ == '__main__':
    main()
