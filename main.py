#!/usr/bin/env python3
"""
WebShare Pro v7.2 - Main Entry Point
??湲곕컲 ?뚯씪 怨듭쑀 ?쒕쾭

Usage:
    python main.py
"""

import os
import sys
import time

# DPI ?ㅼ젙 (Windows)
try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

# ?⑦궎吏 寃쎈줈 異붽?
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import conf, APP_TITLE
from utils.helpers import cleanup_upload_temp_dirs
from utils.log_manager import logger
from server import ensure_runtime_initialized


def cleanup_temp_files():
    """Delete stale upload temp directories at startup."""
    try:
        cleanup_upload_temp_dirs(conf.get('folder'))
    except Exception as e:
        logger.add(f"시작 시 임시 파일 정리 실패: {e}", "WARN")


def main():
    """Main entry point."""
    print(f"\n{'='*50}")
    print(f"  {APP_TITLE}")
    print(f"  ??湲곕컲 ?뚯씪 怨듭쑀 ?쒕쾭")
    print(f"{'='*50}\n")
    
    # startup cleanup + runtime initialization
    cleanup_temp_files()
    ensure_runtime_initialized()
    
    # GUI ?쒖옉
    try:
        # PyQt6 ?쒕룄
        from gui.pyqt_gui import run_pyqt6_gui
        
        os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '1'
        os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'
        
        print("[INFO] PyQt6 GUI ?쒖옉")
        sys.exit(run_pyqt6_gui())
        
    except ImportError as e:
        print(f"[WARN] PyQt6 濡쒕뱶 ?ㅽ뙣: {e}")
        print("[INFO] Tkinter fallback ?ъ슜")
        
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
            ttk.Label(frame, text="PyQt6媛 ?ㅼ튂?섏? ?딆븘 湲곕낯 Tkinter GUI瑜??ъ슜?⑸땲??").pack(pady=5)
            ttk.Label(frame, text=f"怨듭쑀 ?대뜑: {conf.get('folder')}").pack(pady=5)
            ttk.Label(frame, text=f"?ы듃: {conf.get('port')}").pack(pady=5)
            
            def start_server_tk():
                from server import start_server
                if start_server():
                    messagebox.showinfo("?깃났", f"?쒕쾭媛 ?쒖옉?섏뿀?듬땲??\nhttp://127.0.0.1:{conf.get('port')}")
            
            ttk.Button(frame, text="?쒕쾭 ?쒖옉", command=start_server_tk).pack(pady=20)
            
            root.mainloop()
            
        except ImportError:
            print("[ERROR] GUI瑜??ъ슜?????놁뒿?덈떎. Flask ?쒕쾭留??쒖옉?⑸땲??")
            from server import start_server
            start_server()
            
            # ?쒕쾭媛 醫낅즺???뚭퉴吏 ?湲?
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[INFO] ?쒕쾭瑜?醫낅즺?⑸땲??")


if __name__ == '__main__':
    main()

