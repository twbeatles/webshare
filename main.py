#!/usr/bin/env python3
"""
WebShare Pro v7.2 - Main Entry Point
웹 기반 파일 공유 서버

Usage:
    python main.py
"""

import os
import sys
import threading
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

from webshare.config import conf, APP_TITLE
from webshare.utils.log_manager import logger
from webshare.features.metadata import load_metadata
from webshare.features.audit_log import load_audit_log, save_audit_log
from webshare.features.cloud_sync import load_cloud_config
from webshare.features.trash import auto_cleanup_trash
from webshare.security.permissions import load_permissions


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


def periodic_cleanup():
    """주기적 정리 스레드 (5분 간격)"""
    from webshare.utils.helpers import cleanup_expired_sessions, cleanup_expired_share_links
    from webshare.security.ip_blocker import cleanup_expired_login_attempts
    
    while True:
        time.sleep(300)
        try:
            # 휴지통 자동 정리
            auto_cleanup_trash()
            # 감사 로그 저장
            save_audit_log()
            # 만료된 세션 정리
            cleanup_expired_sessions()
            # 만료된 공유 링크 정리
            cleanup_expired_share_links()
            # 오래된 로그인 시도 기록 정리
            cleanup_expired_login_attempts()
        except Exception as e:
            logger.add(f"주기적 정리 오류: {e}", "ERROR")


def main():
    """메인 진입점"""
    print(f"\n{'='*50}")
    print(f"  {APP_TITLE}")
    print(f"  웹 기반 파일 공유 서버")
    print(f"{'='*50}\n")
    
    # 초기화
    cleanup_temp_files()
    load_metadata()
    load_audit_log()
    load_permissions()
    load_cloud_config()
    
    # 주기적 정리 스레드 시작
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()
    
    # GUI 시작
    try:
        # PyQt6 시도
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        
        os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '1'
        os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'
        
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        
        # PyQt6 GUI (기존 GUI 클래스 사용)
        # from webshare.gui.pyqt_gui import WebShareGUI
        # window = WebShareGUI()
        # window.show()
        
        # 임시: 기존 단일 파일에서 GUI 로드
        print("[INFO] PyQt6 GUI 사용 가능")
        print("[INFO] 기존 '웹서버 프로그램v4.py'를 실행하거나, GUI 모듈을 완성 후 사용하세요.")
        
        # sys.exit(app.exec())
        
    except ImportError:
        print("[INFO] PyQt6가 설치되지 않음. Tkinter fallback 사용")
    
    print("\n[안내] 현재는 모듈 구조만 생성되었습니다.")
    print("[안내] 완전한 실행을 위해서는 routes/ 및 GUI 모듈 완성이 필요합니다.")
    print("[안내] 기존 파일은 'backup/' 폴더에 백업되어 있습니다.")


if __name__ == '__main__':
    main()
