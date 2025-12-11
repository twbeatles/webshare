import os
import sys
import socket
import threading
import webbrowser
import mimetypes
import json
import shutil
import zipfile
import io
import time
import logging
import queue
import re
from datetime import datetime, timedelta
from functools import wraps

# GUI Imports - PyQt6
try:
    from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                                  QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QTabWidget,
                                  QTextEdit, QFileDialog, QMessageBox, QGroupBox, QFrame, QSizePolicy,
                                  QSpacerItem, QDialog, QDialogButtonBox, QScrollArea, QSystemTrayIcon, QMenu)
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
    from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QImage, QAction
    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    # Fallback to Tkinter if PyQt6 not installed
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext, filedialog

from PIL import Image, ImageTk  # Requires: pip install pillow

# Server Imports
from flask import Flask, request, send_from_directory, render_template_string, redirect, url_for, session, abort, send_file, jsonify, g
from werkzeug.serving import make_server
# secure_filename은 한글을 지원하지 않으므로 직접 구현한 함수를 사용합니다.

# ==========================================
# 1. 설정 및 상수 (Constants)
# ==========================================
APP_TITLE = "WebShare Pro v4.0"
CONFIG_FILE = "webshare_config.json"
DEFAULT_PORT = 5000
TEXT_EXTENSIONS = {'.txt', '.py', '.html', '.css', '.js', '.json', '.md', '.log', '.xml', '.ini', '.conf', '.sh', '.bat', '.c', '.cpp', '.h', '.java', '.sql', '.yaml', '.yml'}
MAX_LOG_LINES = 1000
SESSION_TIMEOUT_MINUTES = 30  # 세션 만료 시간 (분)
VERSION_FOLDER_NAME = ".webshare_versions"  # 파일 버전 저장 폴더
MAX_FILE_VERSIONS = 5  # 최대 버전 수

# 서버 통계 전역 변수
SERVER_START_TIME = datetime.now()
STATS = {
    'requests': 0,
    'bytes_sent': 0,
    'bytes_received': 0,
    'errors': 0,
    'active_connections': 0  # 현재 접속자 수
}

# 공유 링크 저장소 (메모리 저장, 서버 재시작 시 초기화)
# 형식: {token: {'path': 경로, 'expires': 만료시간, 'created_by': 생성자}}
SHARE_LINKS = {}

# 북마크 저장소
BOOKMARKS = []

# 접속 기록 (최대 100개)
ACCESS_LOG = []
MAX_ACCESS_LOG = 100

# 썸네일 캐시 (메모리)
THUMBNAIL_CACHE = {}

# 휴지통 폴더명
TRASH_FOLDER_NAME = ".webshare_trash"

# ==========================================
# 2. 유틸리티 함수 (Utility Functions)
# ==========================================

def safe_filename(filename):
    """
    Werkzeug의 secure_filename은 한글을 모두 삭제하므로,
    한글을 지원하는 안전한 파일명 변환 함수를 구현합니다.
    """
    # 1. 경로 구분자 제거 (보안)
    filename = filename.replace('/', '').replace('\\', '')
    
    # 2. 상위 디렉토리 탐색(..) 방지
    filename = re.sub(r'\.\.+', '.', filename)
    
    # 3. 윈도우/리눅스 예약 문자 제거 또는 치환
    # < > : " / \ | ? *
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # 4. 공백 및 제어 문자 처리
    filename = filename.strip()
    
    # 5. 빈 파일명 방지
    if not filename:
        filename = "unnamed_file"
        
    return filename

def validate_path(base_dir: str, path: str) -> tuple:
    """
    경로 탐색 공격을 방지하기 위한 경로 검증 함수.
    
    Args:
        base_dir: 기본 허용 디렉토리
        path: 검증할 상대 경로
        
    Returns:
        tuple: (is_valid: bool, full_path: str, error_msg: str)
    """
    try:
        full_path = os.path.normpath(os.path.join(base_dir, path))
        base_dir_normalized = os.path.normpath(os.path.abspath(base_dir))
        
        # 경로가 기본 디렉토리 내에 있는지 확인
        if not os.path.abspath(full_path).startswith(base_dir_normalized):
            return (False, None, "잘못된 경로입니다.")
        
        return (True, full_path, None)
    except Exception as e:
        return (False, None, f"경로 검증 오류: {str(e)}")

class LogManager:
    def __init__(self):
        self.queue = queue.Queue()

    def add(self, msg, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] [{level}] {msg}"
        self.queue.put(formatted_msg)
        print(formatted_msg) 

logger = LogManager()

# ==========================================
# 2.1 보안 헬퍼 함수 (v4 추가)
# ==========================================
import hashlib

def hash_password(password: str) -> str:
    """별도 라이브러리 없이 SHA256으로 비밀번호 해싱"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_password: str, provided_password: str) -> bool:
    """비밀번호 검증 (해시되었는지 평문인지 확인 후 비교)"""
    # 해시된 비밀번호인지 확인 (SHA256은 64자)
    if len(stored_password) == 64:
        return hash_password(provided_password) == stored_password
    # 평문 비밀번호 (마이그레이션 호환성)
    return stored_password == provided_password

def log_access(ip: str, action: str, details: str = ""):
    """접속 기록 저장"""
    global ACCESS_LOG
    entry = {
        'time': datetime.now().isoformat(),
        'ip': ip,
        'action': action,
        'details': details
    }
    ACCESS_LOG.insert(0, entry)
    # 최대 개수 제한
    if len(ACCESS_LOG) > MAX_ACCESS_LOG:
        ACCESS_LOG = ACCESS_LOG[:MAX_ACCESS_LOG]

def create_file_version(file_path: str):
    """파일 수정 전 버전 자동 백업"""
    if not os.path.exists(file_path):
        return
    
    base_dir = conf.get('folder')
    version_dir = os.path.join(base_dir, VERSION_FOLDER_NAME)
    os.makedirs(version_dir, exist_ok=True)
    
    filename = os.path.basename(file_path)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    version_name = f"{timestamp}_{filename}"
    version_path = os.path.join(version_dir, version_name)
    
    try:
        shutil.copy2(file_path, version_path)
        
        # 최대 버전 수 유지 (오래된 것 삭제)
        versions = sorted([
            f for f in os.listdir(version_dir) 
            if f.endswith(f'_{filename}')
        ], reverse=True)
        
        for old_version in versions[MAX_FILE_VERSIONS:]:
            os.remove(os.path.join(version_dir, old_version))
            
    except Exception as e:
        logger.add(f"버전 생성 실패: {e}", "ERROR")

class ConfigManager:
    def __init__(self):
        self.config = {
            'folder': os.path.abspath(os.path.join(os.getcwd(), 'shared_files')),
            'port': DEFAULT_PORT,
            'admin_pw': "1234",
            'guest_pw': "0000",
            'allow_guest_upload': False,
            'display_host': '0.0.0.0',
            'use_https': False,
            # v4 신규 설정
            'session_timeout': SESSION_TIMEOUT_MINUTES,
            'enable_notifications': True,  # 시스템 알림
            'enable_versioning': True,  # 파일 버전 관리
            'minimize_to_tray': True  # 트레이로 최소화
        }
        self.load()

    def load(self):
        if not os.path.exists(self.config['folder']):
            try: 
                os.makedirs(self.config['folder'])
            except Exception as e:
                print(f"폴더 생성 실패: {e}")
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    self.config.update(json.load(f))
            except Exception as e:
                logger.add(f"설정 로드 실패: {e}", "ERROR")

    def save(self):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.add(f"설정 저장 실패: {e}", "ERROR")
            
    def get(self, key): return self.config.get(key)
    def set(self, key, value): self.config[key] = value

conf = ConfigManager()

# ==========================================
# 3. HTML 템플릿 (변경 없음)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="description" content="WebShare Pro - 파일 공유 및 관리 시스템">
    <title>WebShare Pro</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/github-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>

    <style>
        :root {
            --primary: #6366f1; --primary-dark: #4f46e5; --bg: #f8fafc; --card: #ffffff; --text: #1e293b; 
            --text-secondary: #64748b; --border: #e2e8f0; --danger: #ef4444; --folder: #f59e0b; --hover: #f1f5f9;
            --success: #10b981; --focus-ring: #818cf8; --gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        [data-theme="dark"] {
            --primary: #818cf8; --primary-dark: #6366f1; --bg: #0f172a; --card: #1e293b; --text: #f1f5f9;
            --text-secondary: #94a3b8; --border: #334155; --folder: #fbbf24; --hover: #334155;
            --gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        * { box-sizing: border-box; }
        
        body { 
            font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: var(--bg); 
            color: var(--text); 
            margin: 0; 
            transition: background 0.3s, color 0.3s; 
            padding-bottom: 80px; 
            -webkit-tap-highlight-color: transparent;
            line-height: 1.5;
        }
        
        *:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; border-radius: 4px; }

        .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
        
        header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 24px; 
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }
        
        .card { 
            background: var(--card); 
            border-radius: 16px; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.05); 
            border: 1px solid var(--border); 
            overflow: hidden;
            transition: box-shadow 0.2s;
        }
        
        .toolbar { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
        .search-box { flex: 1; position: relative; min-width: 200px; }
        .search-box input { 
            width: 100%; 
            padding: 12px 12px 12px 42px; 
            border-radius: 12px; 
            border: 1px solid var(--border); 
            background: var(--card); 
            color: var(--text); 
            box-sizing: border-box; 
            height: 44px;
            font-size: 0.95rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .search-box input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1); }
        .search-box i { position: absolute; left: 14px; top: 50%; transform: translateY(-50%); color: var(--text-secondary); }
        
        .sort-select { 
            padding: 0 14px; 
            height: 44px; 
            border-radius: 12px; 
            border: 1px solid var(--border); 
            background: var(--card); 
            color: var(--text); 
            cursor: pointer;
            font-size: 0.9rem;
        }

        .btn { 
            background: var(--primary); 
            color: white; 
            border: none; 
            padding: 10px 20px; 
            border-radius: 10px; 
            cursor: pointer; 
            font-weight: 600; 
            text-decoration: none; 
            display: inline-flex; 
            align-items: center; 
            gap: 8px; 
            transition: all 0.2s; 
            font-size: 0.9rem; 
            height: 44px; 
            box-sizing: border-box;
        }
        .btn:hover { background: var(--primary-dark); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3); }
        .btn:active { transform: translateY(0); }
        .btn-outline { background: transparent; border: 1.5px solid var(--border); color: var(--text); }
        .btn-outline:hover { background: var(--hover); border-color: var(--primary); transform: translateY(-1px); box-shadow: none; }
        .btn-icon { width: 40px; height: 40px; padding: 0; justify-content: center; border-radius: 10px; }
        .btn-danger { background: rgba(239,68,68,0.1); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
        .btn-danger:hover { background: var(--danger); color: white; }

        #batchBar { 
            display: none; 
            align-items: center; 
            gap: 12px; 
            background: var(--gradient); 
            color: white; 
            padding: 12px 20px; 
            border-radius: 12px; 
            animation: slideDown 0.3s ease-out;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
        }
        @keyframes slideDown { from { transform: translateY(-10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

        .file-list { list-style: none; padding: 0; margin: 0; }
        .file-item { 
            display: flex; 
            align-items: center; 
            padding: 14px 18px; 
            border-bottom: 1px solid var(--border); 
            cursor: pointer; 
            transition: all 0.15s; 
            user-select: none;
        }
        .file-item:hover { background: var(--hover); }
        .file-item.selected { background: rgba(99, 102, 241, 0.08); border-left: 3px solid var(--primary); }
        
        .file-check { margin-right: 16px; transform: scale(1.3); cursor: pointer; accent-color: var(--primary); }
        .file-icon { font-size: 1.5rem; width: 44px; text-align: center; color: var(--text-secondary); transition: transform 0.2s; }
        .file-item:hover .file-icon { transform: scale(1.1); }
        .file-icon.folder { color: var(--folder); }
        .file-info { flex: 1; min-width: 0; margin-right: 12px; }
        .file-name { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.95rem; }
        .file-meta { font-size: 0.8rem; color: var(--text-secondary); margin-top: 3px; }
        .file-actions { opacity: 0; transition: opacity 0.2s; display: flex; gap: 6px; }
        .file-item:focus-within .file-actions, .file-item:hover .file-actions { opacity: 1; }
        
        .grid-view .file-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 14px; padding: 14px; }
        .grid-view .file-item { 
            flex-direction: column; 
            text-align: center; 
            height: 170px; 
            justify-content: center; 
            border-radius: 12px; 
            border: 1px solid var(--border); 
            padding: 12px; 
            position: relative;
            transition: all 0.2s;
        }
        .grid-view .file-item:hover { transform: translateY(-4px); box-shadow: 0 8px 20px rgba(0,0,0,0.1); }
        .grid-view .file-check { position: absolute; top: 10px; left: 10px; z-index: 2; }
        .grid-view .file-icon { font-size: 3rem; margin-bottom: 12px; width: auto; }
        .grid-view .file-info { margin: 0; width: 100%; }
        .grid-view .file-actions { display: none; } 
        .grid-view .file-item img.preview { width: 100%; height: 85px; object-fit: cover; border-radius: 8px; margin-bottom: 8px; }

        .overlay { 
            position: fixed; 
            inset: 0; 
            background: rgba(0,0,0,0.6); 
            z-index: 2000; 
            display: none; 
            justify-content: center; 
            align-items: center; 
            backdrop-filter: blur(6px);
            animation: fadeIn 0.2s;
        }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        
        .modal { 
            background: var(--card); 
            padding: 28px; 
            border-radius: 20px; 
            width: 90%; 
            max-width: 420px; 
            max-height: 85vh; 
            overflow-y: auto; 
            position: relative; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.3); 
            display: flex; 
            flex-direction: column;
            animation: scaleUp 0.25s ease-out;
        }
        @keyframes scaleUp { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .modal.large { max-width: 950px; width: 95%; height: 82vh; }
        
        .context-menu { 
            position: fixed; 
            background: var(--card); 
            border: 1px solid var(--border); 
            border-radius: 12px; 
            box-shadow: 0 8px 30px rgba(0,0,0,0.15); 
            z-index: 1000; 
            display: none; 
            overflow: hidden; 
            min-width: 180px;
            animation: contextPop 0.15s ease-out;
        }
        @keyframes contextPop { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .ctx-item { padding: 12px 18px; cursor: pointer; display: flex; align-items: center; gap: 10px; font-size: 0.9rem; transition: background 0.15s; }
        .ctx-item:hover { background: var(--hover); }
        .ctx-item.danger { color: var(--danger); }
        .ctx-item.danger:hover { background: rgba(239, 68, 68, 0.1); }

        .editor-container { flex: 1; position: relative; overflow: hidden; border: 1px solid var(--border); border-radius: 12px; margin-top: 12px; display: flex; }
        .editor-area { width: 100%; height: 100%; padding: 18px; background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', 'Consolas', monospace; resize: none; border: none; box-sizing: border-box; line-height: 1.6; font-size: 14px; outline: none; }
        .markdown-body { overflow-y: auto; line-height: 1.7; padding: 18px; }
        .markdown-body pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
        
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }
        .stat-card { 
            background: var(--bg); 
            padding: 18px; 
            border-radius: 12px; 
            border: 1px solid var(--border); 
            text-align: center;
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-2px); }
        .stat-value { font-size: 1.6rem; font-weight: 700; background: var(--gradient); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin: 6px 0; }
        .stat-label { font-size: 0.85rem; color: var(--text-secondary); }

        #toast-container { position: fixed; bottom: 32px; left: 50%; transform: translateX(-50%); z-index: 3000; display: flex; flex-direction: column; gap: 12px; }
        .toast { 
            background: rgba(30, 41, 59, 0.96); 
            backdrop-filter: blur(8px); 
            color: white; 
            padding: 14px 28px; 
            border-radius: 50px; 
            font-size: 0.9rem; 
            font-weight: 500;
            animation: toastSlide 0.3s ease-out; 
            display: flex; 
            align-items: center; 
            gap: 10px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }
        .toast.success { background: linear-gradient(135deg, #10b981 0%, #059669 100%); }
        .toast.error { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
        .toast.warning { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
        .toast.info { background: var(--gradient); }
        @keyframes toastSlide { from { transform: translateY(30px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        
        #drop-zone { 
            position: fixed; 
            inset: 0; 
            background: var(--gradient); 
            z-index: 9999; 
            display: none; 
            flex-direction: column; 
            justify-content: center; 
            align-items: center; 
            color: white; 
            font-size: 1.6rem; 
            font-weight: 600;
        }
        
        .disk-bar { height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; margin-top: 6px; }
        .disk-fill { height: 100%; background: linear-gradient(90deg, var(--success), #34d399); width: 0%; transition: width 0.6s ease-out; }

        @media (max-width: 600px) {
            .file-actions { opacity: 1; }
            .btn span { display: none; }
            .container { padding: 16px; }
            header { flex-direction: column; gap: 12px; }
        }
    </style>
</head>
<body>
    <div id="drop-zone" aria-hidden="true"><i class="fa-solid fa-cloud-arrow-up" style="font-size:4rem; margin-bottom:20px;"></i>폴더나 파일을 여기에 놓으세요</div>
    <div id="toast-container" aria-live="polite"></div>
    
    <div id="ctxMenu" class="context-menu" aria-hidden="true">
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('download')"><i class="fa-solid fa-download"></i> 다운로드</div>
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('rename')"><i class="fa-solid fa-pen"></i> 이름 변경</div>
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('info')"><i class="fa-solid fa-circle-info"></i> 상세 정보</div>
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('bookmark')"><i class="fa-solid fa-star"></i> 북마크 추가</div>
        {% if role == 'admin' %}
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('share')"><i class="fa-solid fa-link"></i> 공유 링크</div>
        <div class="ctx-item" id="ctxUnzip" role="button" tabindex="0" onclick="handleCtx('unzip')" style="display:none"><i class="fa-solid fa-box-open"></i> 압축 해제</div>
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('trash')"><i class="fa-solid fa-trash-can"></i> 휴지통으로</div>
        {% endif %}
        <div class="ctx-item danger" role="button" tabindex="0" onclick="handleCtx('delete')"><i class="fa-solid fa-trash"></i> 영구 삭제</div>
    </div>

    <div class="container">
        {% if not logged_in %}
            <div style="height:80vh; display:flex; justify-content:center; align-items:center;">
                <form method="post" class="card" style="padding:40px; width:100%; max-width:320px; text-align:center;">
                    <h1 style="color:var(--primary); margin-top:0; font-size:1.8rem"><i class="fa-solid fa-share-nodes"></i> WebShare</h1>
                    <label for="password" class="sr-only" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);">비밀번호</label>
                    <input type="password" id="password" name="password" placeholder="비밀번호 입력" required style="width:100%; padding:12px; border-radius:8px; border:1px solid var(--border); background:var(--bg); margin-bottom:15px; box-sizing:border-box;">
                    <button type="submit" class="btn" style="width:100%; justify-content:center; padding:12px;">접속하기</button>
                    {% if error %}<p style="color:var(--danger); font-size:0.9rem; margin-top:10px;" role="alert">{{ error }}</p>{% endif %}
                </form>
            </div>
        {% else %}
            <header>
                <h1 style="margin:0; color:var(--primary); cursor:pointer; font-size:1.5rem" onclick="location.href='/'" tabindex="0" role="link"><i class="fa-solid fa-folder-tree"></i> WebShare</h1>
                <nav style="display:flex; gap:8px;" aria-label="메인 메뉴">
                    <span style="background:rgba(79,70,229,0.1); color:var(--primary); padding:6px 12px; border-radius:20px; font-size:0.8rem; font-weight:bold; display:flex; align-items:center;">
                        {{ '👑 관리자' if role == 'admin' else '👤 게스트' }}
                    </span>
                    <button class="btn btn-outline btn-icon" onclick="openModal('bookmarkModal'); loadBookmarks()" aria-label="북마크"><i class="fa-solid fa-star"></i></button>
                    {% if role == 'admin' %}
                    <button class="btn btn-outline btn-icon" onclick="openModal('trashModal'); loadTrash()" aria-label="휴지통"><i class="fa-solid fa-trash-can"></i></button>
                    <button class="btn btn-outline btn-icon" onclick="openModal('shareListModal'); loadShareLinks()" aria-label="공유 링크"><i class="fa-solid fa-link"></i></button>
                    {% endif %}
                    <button class="btn btn-outline btn-icon" onclick="openModal('statsModal'); fetchStats()" aria-label="서버 상태"><i class="fa-solid fa-chart-line"></i></button>
                    <button class="btn btn-outline btn-icon" onclick="openModal('helpModal')" aria-label="도움말"><i class="fa-solid fa-circle-question"></i></button>
                    <button class="btn btn-outline btn-icon" onclick="toggleTheme()" aria-label="테마 변경"><i class="fa-solid fa-moon"></i></button>
                    <button class="btn btn-outline btn-icon" onclick="openModal('clipModal'); loadClipboard()" aria-label="공유 클립보드"><i class="fa-regular fa-clipboard"></i></button>
                    <a href="/logout" class="btn btn-danger btn-icon" aria-label="로그아웃" style="display:flex;align-items:center;text-decoration:none"><i class="fa-solid fa-power-off"></i></a>
                </nav>
            </header>

            <div class="toolbar" role="toolbar" aria-label="파일 도구">
                <div class="search-box">
                    <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
                    <label for="searchInput" class="sr-only" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);">검색</label>
                    <input type="text" id="searchInput" placeholder="파일 검색..." onkeyup="filterFiles()" aria-label="파일 검색">
                </div>
                
                <select id="sortOrder" class="sort-select" onchange="sortFiles()" aria-label="정렬 방식">
                    <option value="name">이름순</option>
                    <option value="size">크기순</option>
                    <option value="date">날짜순</option>
                </select>

                <div id="batchBar" role="region" aria-live="polite">
                    <span id="batchCount">0개 선택됨</span>
                    <button class="btn-icon" style="border:1px solid rgba(255,255,255,0.3); background:rgba(255,255,255,0.2); color:white" onclick="batchDownload()" title="일괄 다운로드" aria-label="일괄 다운로드"><i class="fa-solid fa-file-zipper"></i></button>
                    {% if can_modify %}
                    <button class="btn-icon" style="border:1px solid rgba(255,255,255,0.3); background:rgba(255,255,255,0.2); color:white" onclick="batchDelete()" title="일괄 삭제" aria-label="일괄 삭제"><i class="fa-solid fa-trash"></i></button>
                    {% endif %}
                </div>

                <div style="display:flex; gap:8px;">
                    <button class="btn btn-outline" onclick="toggleView()" title="뷰 전환" aria-label="뷰 전환"><i id="viewIcon" class="fa-solid fa-list"></i></button>
                    {% if current_path %}
                    <a href="/zip/{{ current_path }}" class="btn btn-outline" title="현재 폴더 압축 다운로드" aria-label="ZIP 다운로드" style="text-decoration:none;display:flex;align-items:center;gap:5px"><i class="fa-solid fa-file-zipper"></i> ZIP</a>
                    {% endif %}
                    {% if can_modify %}
                    <button class="btn" onclick="document.getElementById('fileInput').click()"><span>업로드</span> <i class="fa-solid fa-upload"></i></button>
                    <button class="btn btn-outline" onclick="openModal('mkdirModal')" aria-label="폴더 생성"><i class="fa-solid fa-folder-plus"></i></button>
                    {% endif %}
                </div>
            </div>
            <input type="file" id="fileInput" multiple style="display:none" onchange="handleFileSelect(this.files)">

            <main id="fileContainer" class="card" role="main">
                <ul class="file-list" id="fileList" aria-label="파일 목록">
                    {% if current_path %}
                    {% set parent_path = '/'.join(current_path.split('/')[:-1]) %}
                    {% set parent_link = '/' if parent_path == '' else '/browse/' + parent_path %}
                    <li class="file-item parent-folder" tabindex="0" role="link" onclick="location.href='{{ parent_link }}'" onkeydown="if(event.key==='Enter') location.href='{{ parent_link }}'">
                        <div class="file-icon folder"><i class="fa-solid fa-turn-up"></i></div>
                        <div class="file-info"><div class="file-name">.. (상위 폴더)</div></div>
                    </li>
                    {% endif %}
                    
                    {% for item in items %}
                    <li class="file-item data-item" 
                        tabindex="0"
                        role="listitem"
                        data-path="{{ item.rel_path }}" 
                        data-name="{{ item.name }}" 
                        data-type="{{ item.type }}" 
                        data-size="{{ item.raw_size }}" 
                        data-date="{{ item.raw_mtime }}"
                        data-ext="{{ item.ext }}"
                        oncontextmenu="openCtx(event, '{{ item.rel_path }}', '{{ item.name }}', '{{ item.type }}')"
                        onkeydown="if(event.key==='Enter') handleItemClick('{{ item.rel_path }}', '{{ item.type }}', {{ 'true' if item.is_dir else 'false' }}, '{{ item.ext }}')">
                        
                        <input type="checkbox" class="file-check" value="{{ item.name }}" onclick="event.stopPropagation(); toggleBatch(this)" aria-label="{{ item.name }} 선택">
                        
                        <div class="file-icon {{ 'folder' if item.is_dir else '' }}" aria-hidden="true">
                            {% if item.is_dir %}<i class="fa-solid fa-folder"></i>
                            {% elif item.type == 'image' %}<i class="fa-solid fa-image"></i>
                            {% elif item.type == 'video' %}<i class="fa-solid fa-film"></i>
                            {% elif item.type == 'audio' %}<i class="fa-solid fa-music"></i>
                            {% elif item.type == 'text' %}<i class="fa-solid fa-file-code"></i>
                            {% elif item.type == 'archive' %}<i class="fa-solid fa-file-zipper"></i>
                            {% elif item.ext == '.pdf' %}<i class="fa-solid fa-file-pdf"></i>
                            {% else %}<i class="fa-solid fa-file"></i>{% endif %}
                        </div>
                        
                        {% if item.type == 'image' %}<img src="/download/{{ item.rel_path }}" class="preview" style="display:none;" loading="lazy" alt="{{ item.name }}">{% endif %}
                        
                        <div class="file-info" onclick="handleItemClick('{{ item.rel_path }}', '{{ item.type }}', {{ 'true' if item.is_dir else 'false' }}, '{{ item.ext }}')">
                            <div class="file-name">{{ item.name }}</div>
                            <div class="file-meta">{{ item.size }} • {{ item.mod_time }}</div>
                        </div>
                        
                        <div class="file-actions">
                            {% if item.type == 'text' %}
                            <button class="btn-icon btn-outline" onclick="event.stopPropagation(); openEditor('{{ item.rel_path }}', '{{ item.name }}', '{{ item.ext }}')" aria-label="편집"><i class="fa-solid fa-pen"></i></button>
                            {% endif %}
                            <button class="btn-icon btn-outline" onclick="event.stopPropagation(); downloadItem('{{ item.rel_path }}')" aria-label="다운로드"><i class="fa-solid fa-download"></i></button>
                            {% if can_modify and not item.is_dir %}
                            <button class="btn-icon btn-danger" onclick="event.stopPropagation(); deleteItem('{{ item.rel_path }}')" aria-label="삭제"><i class="fa-solid fa-trash"></i></button>
                            {% endif %}
                        </div>
                    </li>
                    {% endfor %}
                    {% if not items %}<div id="emptyMsg" style="padding:40px; text-align:center; color:var(--text); opacity:0.5;">폴더가 비어있습니다.</div>{% endif %}
                </ul>
            </main>

            <div class="disk-info" style="margin-top:20px; font-size:0.8rem; opacity:0.8;" role="status">
                <div style="display:flex; justify-content:space-between;">
                    <span><i class="fa-solid fa-hard-drive"></i> 저장소 상태</span>
                    <span id="diskText">계산 중...</span>
                </div>
                <div class="disk-bar" aria-hidden="true"><div id="diskFill" class="disk-fill"></div></div>
            </div>
            
            {% if can_modify %}
            <div style="text-align:center; margin-top:20px; font-size:0.8rem; opacity:0.6;">
                <i class="fa-solid fa-circle-info"></i> 폴더나 파일을 화면에 드래그하여 업로드하세요.
            </div>
            {% endif %}
        {% endif %}
    </div>

    <!-- Modals -->
    <div id="statsModal" class="overlay" role="dialog" aria-modal="true" aria-labelledby="statsTitle">
        <div class="modal">
            <h3 id="statsTitle"><i class="fa-solid fa-chart-line"></i> 서버 상태</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="st_uptime">-</div>
                    <div class="stat-label">가동 시간</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="st_req">-</div>
                    <div class="stat-label">총 요청</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="st_sent">-</div>
                    <div class="stat-label">보낸 데이터</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="st_recv">-</div>
                    <div class="stat-label">받은 데이터</div>
                </div>
            </div>
            <div style="text-align:right; margin-top:20px">
                <button class="btn" onclick="closeModal('statsModal')">닫기</button>
            </div>
        </div>
    </div>

    <div id="helpModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal">
            <h3><i class="fa-solid fa-book"></i> 사용 가이드</h3>
            <div style="line-height:1.6; color:var(--text)">
                <p><b>1. 파일/폴더 업로드</b><br>- 드래그 앤 드롭으로 <b>폴더째 업로드</b>가 가능합니다.<br>- '업로드' 버튼으로 파일 여러 개를 선택할 수 있습니다.</p>
                <p><b>2. 미리보기</b><br>- 이미지, 동영상, 오디오, <b>PDF</b>, 텍스트/코드 파일을 지원합니다.</p>
                <p><b>3. 코드 뷰어</b><br>- 구문 강조(Syntax Highlight) 및 Markdown 미리보기를 지원합니다.</p>
                <p><b>4. 접근성 (A11y)</b><br>- 탭 키로 모든 요소 이동이 가능하며 스크린 리더를 지원합니다.</p>
            </div>
            <div style="text-align:right; margin-top:15px"><button class="btn" onclick="closeModal('helpModal')">닫기</button></div>
        </div>
    </div>

    <div id="clipModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal">
            <h3><i class="fa-regular fa-clipboard"></i> 공유 클립보드</h3>
            <label for="clipText" class="sr-only">클립보드 내용</label>
            <textarea id="clipText" style="width:100%; height:150px; padding:10px; border:1px solid var(--border); border-radius:8px; resize:none; background:var(--bg); color:var(--text); box-sizing:border-box;"></textarea>
            <div style="margin-top:10px; text-align:right; display:flex; gap:5px; justify-content:flex-end;">
                <button class="btn btn-outline" onclick="loadClipboard()">새로고침</button>
                <button class="btn" onclick="saveClipboard()">저장하기</button>
                <button class="btn btn-outline" onclick="closeModal('clipModal')">닫기</button>
            </div>
        </div>
    </div>

    <div id="editorModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal large">
            <h3 style="display:flex; justify-content:space-between; align-items:center; margin-top:0;">
                <span><i class="fa-solid fa-file-lines"></i> <span id="editorTitle"></span></span>
                <div style="display:flex; gap:10px; align-items:center">
                    <button id="previewToggle" class="btn-outline" style="font-size:0.8rem; padding:4px 8px; border-radius:4px; display:none" onclick="toggleMarkdownPreview()">미리보기</button>
                    <button class="btn-icon" style="border:none" onclick="closeModal('editorModal')" aria-label="닫기"><i class="fa-solid fa-xmark"></i></button>
                </div>
            </h3>
            <div class="editor-container">
                <textarea id="editorContent" class="editor-area" spellcheck="false" aria-label="코드 편집 영역"></textarea>
                <div id="codePreview" class="editor-area markdown-body" style="display:none; overflow-y:auto;" aria-label="미리보기 영역" tabindex="0"></div>
                <div id="mediaContainer" style="display:none; width:100%; height:100%; justify-content:center; align-items:center;"></div>
            </div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn btn-outline" onclick="closeModal('editorModal')">닫기</button>
                <button id="saveBtn" class="btn" onclick="saveFileContent()">저장</button>
            </div>
        </div>
    </div>

    <div id="mkdirModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal">
            <h3>새 폴더 생성</h3>
            <label for="newFolderInput" class="sr-only">폴더 이름</label>
            <input type="text" id="newFolderInput" placeholder="폴더 이름" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:6px; box-sizing:border-box; background:var(--bg); color:var(--text);">
            <div style="margin-top:15px; text-align:right; gap:5px; display:flex; justify-content:flex-end">
                <button class="btn btn-outline" onclick="closeModal('mkdirModal')">취소</button>
                <button class="btn" onclick="createFolder()">생성</button>
            </div>
        </div>
    </div>
    
    <div id="progressModal" class="overlay" role="alertdialog" aria-modal="true">
        <div class="modal" style="text-align:center;">
            <h3><i class="fa-solid fa-cloud-arrow-up"></i> 업로드 중...</h3>
            <div id="progressFileInfo" style="font-size:0.9rem; margin-bottom:10px; color:var(--text); opacity:0.8;"></div>
            <div style="background:var(--border); height:8px; border-radius:4px; overflow:hidden; margin:15px 0;">
                <div id="progressBar" style="width:0%; height:100%; background:linear-gradient(90deg, var(--primary), #818cf8); transition:width 0.2s;" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
            </div>
            <div id="progressText" style="font-size:1.2rem; font-weight:bold; color:var(--primary);">0%</div>
            <div id="progressStats" style="font-size:0.85rem; margin-top:10px; color:var(--text); opacity:0.7;"></div>
        </div>
    </div>

    <!-- 파일 정보 모달 -->
    <div id="fileInfoModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal">
            <h3><i class="fa-solid fa-circle-info"></i> 파일 정보</h3>
            <div id="fileInfoContent" style="line-height:1.8;"></div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('fileInfoModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- 북마크 모달 -->
    <div id="bookmarkModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal">
            <h3><i class="fa-solid fa-star"></i> 북마크</h3>
            <div id="bookmarkList" style="max-height:300px; overflow-y:auto;"></div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('bookmarkModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- 휴지통 모달 -->
    <div id="trashModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:500px;">
            <h3><i class="fa-solid fa-trash-can"></i> 휴지통</h3>
            <div id="trashList" style="max-height:300px; overflow-y:auto;"></div>
            <div style="margin-top:15px; text-align:right; display:flex; gap:5px; justify-content:flex-end;">
                <button class="btn btn-danger" onclick="emptyTrash()">휴지통 비우기</button>
                <button class="btn btn-outline" onclick="closeModal('trashModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- 공유 링크 목록 모달 -->
    <div id="shareListModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:600px;">
            <h3><i class="fa-solid fa-link"></i> 공유 링크 관리</h3>
            <div id="shareList" style="max-height:300px; overflow-y:auto;"></div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('shareListModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- 공유 링크 생성 모달 -->
    <div id="createShareModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal">
            <h3><i class="fa-solid fa-link"></i> 공유 링크 생성</h3>
            <p id="sharePathDisplay" style="word-break:break-all; color:var(--text); opacity:0.8;"></p>
            <label for="shareHours">유효 시간:</label>
            <select id="shareHours" style="width:100%; padding:8px; border:1px solid var(--border); border-radius:6px; background:var(--bg); color:var(--text); margin-top:5px;">
                <option value="1">1시간</option>
                <option value="6">6시간</option>
                <option value="24" selected>24시간</option>
                <option value="72">3일</option>
                <option value="168">7일</option>
            </select>
            <div id="generatedLink" style="margin-top:15px; display:none;">
                <label>생성된 링크:</label>
                <input type="text" id="shareLinkInput" readonly style="width:100%; padding:8px; border:1px solid var(--border); border-radius:6px; background:var(--bg); color:var(--text); margin-top:5px;">
                <button class="btn btn-outline" onclick="copyShareLink()" style="margin-top:10px;width:100%;"><i class="fa-solid fa-copy"></i> 복사</button>
            </div>
            <div style="margin-top:15px; text-align:right; display:flex; gap:5px; justify-content:flex-end;">
                <button class="btn btn-outline" onclick="closeModal('createShareModal')">취소</button>
                <button class="btn" id="createShareBtn" onclick="createShareLink()">생성</button>
            </div>
        </div>
    </div>

    <script>
        const currentPath = "{{ current_path }}";
        const canModify = {{ 'true' if can_modify else 'false' }};
        let selectedFiles = new Set();
        
        document.addEventListener('DOMContentLoaded', () => {
            fetchDiskInfo();
            document.addEventListener('keydown', (e) => {
                // Escape: 모든 모달 닫기
                if(e.key === "Escape") {
                    document.querySelectorAll('.overlay').forEach(el => el.style.display = 'none');
                }
                
                // 입력 필드에 포커스 중이면 단축키 무시
                if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
                
                // Ctrl+U: 업로드
                if(e.ctrlKey && e.key === 'u' && canModify) {
                    e.preventDefault();
                    document.getElementById('fileInput').click();
                }
                
                // Ctrl+N: 새 폴더
                if(e.ctrlKey && e.key === 'n' && canModify) {
                    e.preventDefault();
                    openModal('mkdirModal');
                    document.getElementById('newFolderInput').focus();
                }
                
                // Delete: 선택된 파일 삭제
                if(e.key === 'Delete' && selectedFiles.size > 0 && canModify) {
                    e.preventDefault();
                    batchDelete();
                }
                
                // Ctrl+A: 모든 파일 선택
                if(e.ctrlKey && e.key === 'a') {
                    e.preventDefault();
                    document.querySelectorAll('.file-check').forEach(c => {
                        if(!c.checked) {
                            c.checked = true;
                            toggleBatch(c);
                        }
                    });
                }
                
                // F2: 선택된 항목 이름 변경
                if(e.key === 'F2' && selectedFiles.size === 1) {
                    e.preventDefault();
                    const fileName = Array.from(selectedFiles)[0];
                    const newName = prompt("새 이름:", fileName);
                    if(newName && newName !== fileName) {
                        fetch('/rename/' + currentPath, {
                            method:'POST', 
                            headers:{'Content-Type':'application/json'}, 
                            body:JSON.stringify({old_name: fileName, new_name: newName})
                        }).then(r=>r.json()).then(d => { 
                            if(d.success) location.reload(); 
                            else showToast(d.error, 'error'); 
                        });
                    }
                }
            });
            
            // 단축키 힌트 표시
            console.log('📌 키보드 단축키: Ctrl+U(업로드), Ctrl+N(새폴더), Delete(삭제), Ctrl+A(전체선택), F2(이름변경)');
        });

        function fetchStats() {
            fetch('/metrics').then(r=>r.json()).then(d => {
                document.getElementById('st_uptime').innerText = d.uptime;
                document.getElementById('st_req').innerText = d.requests.toLocaleString();
                document.getElementById('st_sent').innerText = d.sent;
                document.getElementById('st_recv').innerText = d.recv;
            });
        }

        function toggleBatch(checkbox) {
            const row = checkbox.closest('.file-item');
            if (checkbox.checked) {
                selectedFiles.add(checkbox.value);
                row.classList.add('selected');
            } else {
                selectedFiles.delete(checkbox.value);
                row.classList.remove('selected');
            }
            updateBatchUI();
        }

        function updateBatchUI() {
            const bar = document.getElementById('batchBar');
            const cnt = document.getElementById('batchCount');
            if (selectedFiles.size > 0) {
                bar.style.display = 'flex';
                cnt.innerText = selectedFiles.size + '개 선택됨';
            } else {
                bar.style.display = 'none';
            }
        }

        function batchDownload() {
            if (selectedFiles.size === 0) return;
            const files = Array.from(selectedFiles);
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/batch_download/' + currentPath;
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'files';
            input.value = JSON.stringify(files);
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
            document.body.removeChild(form);
            document.querySelectorAll('.file-check').forEach(c => { c.checked = false; toggleBatch(c); });
        }

        function batchDelete() {
            if (selectedFiles.size === 0) return;
            if (!confirm(selectedFiles.size + "개 항목을 삭제하시겠습니까?")) return;
            fetch('/batch_delete/' + currentPath, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({files: Array.from(selectedFiles)})
            }).then(r => r.json()).then(d => {
                if (d.success) location.reload(); else alert(d.error);
            });
        }

        let editPath = '';
        let isMarkdown = false;
        
        function handleItemClick(path, type, isDir, ext) {
            if(isDir) location.href = '/browse/' + path;
            else if (['image', 'video', 'audio'].includes(type) || ext.toLowerCase() === '.pdf') {
                openEditor(path, path.split('/').pop(), ext, true);
            }
            else if (type === 'text') {
                openEditor(path, path.split('/').pop(), ext, false);
            }
            else location.href = '/download/' + path;
        }

        function openEditor(path, name, ext, readOnly) {
            editPath = path;
            ext = ext.toLowerCase();
            isMarkdown = ext === '.md';
            
            document.getElementById('editorTitle').innerText = name;
            
            const editor = document.getElementById('editorContent');
            const preview = document.getElementById('codePreview');
            const media = document.getElementById('mediaContainer');
            const saveBtn = document.getElementById('saveBtn');
            const toggleBtn = document.getElementById('previewToggle');
            
            editor.style.display = 'none';
            preview.style.display = 'none';
            media.style.display = 'none';
            toggleBtn.style.display = 'none';
            saveBtn.style.display = readOnly ? 'none' : 'inline-block';

            if (readOnly) {
                media.style.display = 'flex';
                const url = '/download/' + path;
                if(ext === '.pdf') {
                    media.innerHTML = `<iframe src="${url}" style="width:100%; height:100%; border:none;" title="PDF Preview"></iframe>`;
                } else if (['.mp4', '.webm', '.ogg'].includes(ext)) {
                    media.innerHTML = `<video controls autoplay style="max-width:100%; max-height:100%"><source src="${url}"></video>`;
                } else if (['.mp3', '.wav', '.ogg'].includes(ext)) {
                    media.innerHTML = `<audio controls autoplay><source src="${url}"></audio>`;
                } else if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) {
                    media.innerHTML = `<img src="${url}" style="max-width:100%; max-height:100%; object-fit:contain">`;
                }
                openModal('editorModal');
            } else {
                editor.style.display = 'block';
                toggleBtn.style.display = 'inline-block';
                toggleBtn.innerText = "미리보기";
                editor.value = "Loading...";
                
                fetch('/get_content/' + path).then(r=>r.json()).then(d => {
                    if(d.error) { alert(d.error); return; }
                    editor.value = d.content;
                    openModal('editorModal');
                });
            }
        }

        function toggleMarkdownPreview() {
            const editor = document.getElementById('editorContent');
            const preview = document.getElementById('codePreview');
            const btn = document.getElementById('previewToggle');
            
            if(editor.style.display !== 'none') {
                if(isMarkdown) {
                    preview.innerHTML = marked.parse(editor.value);
                } else {
                    const safeContent = editor.value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    const ext = editPath.split('.').pop();
                    preview.innerHTML = `<pre><code class="language-${ext}">${safeContent}</code></pre>`;
                    hljs.highlightElement(preview.querySelector('code'));
                }
                editor.style.display = 'none';
                preview.style.display = 'block';
                btn.innerText = "편집하기";
            } else {
                preview.style.display = 'none';
                editor.style.display = 'block';
                btn.innerText = "미리보기";
            }
        }

        function saveFileContent() {
            const content = document.getElementById('editorContent').value;
            fetch('/save_content/' + editPath, {
                method:'POST', headers:{'Content-Type':'application/json'},
                body:JSON.stringify({content: content})
            }).then(r=>r.json()).then(d => {
                if(d.success) { showToast('저장되었습니다.'); closeModal('editorModal'); }
                else alert(d.error);
            });
        }

        function handleFileSelect(files) { if(files.length > 0) uploadFiles(files); }

        function uploadFiles(files) {
            openModal('progressModal');
            const fd = new FormData();
            let totalSize = 0;
            
            for(let i=0; i<files.length; i++) {
                const file = files[i];
                const path = file.webkitRelativePath || file.name;
                fd.append('file', file);
                fd.append('paths', path);
                totalSize += file.size;
            }
            
            // 파일 정보 표시
            const formatSize = (bytes) => {
                if (bytes < 1024) return bytes + ' B';
                if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
                if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
                return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
            };
            
            document.getElementById('progressFileInfo').innerText = 
                `${files.length}개 파일 (${formatSize(totalSize)})`;
            
            const xhr = new XMLHttpRequest();
            const startTime = Date.now();
            
            xhr.open('POST', '/upload/' + currentPath);
            xhr.upload.onprogress = e => {
                if(e.lengthComputable) {
                    const p = Math.round((e.loaded/e.total)*100);
                    const elapsed = (Date.now() - startTime) / 1000;
                    const speed = e.loaded / elapsed;
                    const remaining = (e.total - e.loaded) / speed;
                    
                    document.getElementById('progressBar').style.width = p+'%';
                    document.getElementById('progressBar').setAttribute('aria-valuenow', p);
                    document.getElementById('progressText').innerText = p+'%';
                    
                    // 속도와 예상 시간 표시
                    const speedStr = formatSize(speed) + '/s';
                    const remainStr = remaining > 60 
                        ? Math.ceil(remaining / 60) + '분 남음'
                        : Math.ceil(remaining) + '초 남음';
                    document.getElementById('progressStats').innerText = 
                        `${speedStr} • ${formatSize(e.loaded)} / ${formatSize(e.total)} • ${remainStr}`;
                }
            };
            xhr.onload = () => {
                showToast('업로드 완료!', 'success');
                setTimeout(() => location.reload(), 500);
            };
            xhr.onerror = () => { 
                showToast('업로드 실패', 'error'); 
                closeModal('progressModal');
            };
            xhr.send(fd);
        }

        const dropZone = document.getElementById('drop-zone');
        window.addEventListener('dragenter', e => { if(canModify && e.dataTransfer.types.includes('Files')) dropZone.style.display='flex'; });
        dropZone.addEventListener('dragleave', e => dropZone.style.display='none');
        dropZone.addEventListener('drop', e => {
            e.preventDefault(); dropZone.style.display='none';
            if(canModify) uploadFiles(e.dataTransfer.files);
        });
        window.addEventListener('dragover', e => e.preventDefault());

        function showToast(msg, type = 'info') {
            const icons = {
                success: '<i class="fa-solid fa-check-circle"></i>',
                error: '<i class="fa-solid fa-exclamation-circle"></i>',
                warning: '<i class="fa-solid fa-exclamation-triangle"></i>',
                info: '<i class="fa-solid fa-info-circle"></i>'
            };
            const t = document.createElement('div'); 
            t.className = 'toast ' + type; 
            t.innerHTML = (icons[type] || '') + ' ' + msg; 
            t.setAttribute('role', 'alert');
            document.getElementById('toast-container').appendChild(t);
            setTimeout(() => t.remove(), 3500);
        }
        function sortFiles() {
            const list = document.getElementById('fileList');
            const items = Array.from(list.querySelectorAll('.data-item'));
            const type = document.getElementById('sortOrder').value;
            const parent = list.querySelector('.parent-folder');
            items.sort((a, b) => {
                const isDirA = a.querySelector('.file-icon').classList.contains('folder');
                const isDirB = b.querySelector('.file-icon').classList.contains('folder');
                if (isDirA !== isDirB) return isDirA ? -1 : 1;
                if (type === 'name') return a.getAttribute('data-name').localeCompare(b.getAttribute('data-name'));
                if (type === 'size') return parseInt(b.getAttribute('data-size')) - parseInt(a.getAttribute('data-size'));
                if (type === 'date') return parseFloat(b.getAttribute('data-date')) - parseFloat(a.getAttribute('data-date'));
                return 0;
            });
            list.innerHTML = '';
            if(parent) list.appendChild(parent);
            items.forEach(item => list.appendChild(item));
        }
        function fetchDiskInfo() {
            fetch('/disk_info').then(r=>r.json()).then(d => {
                if(d.error) return;
                document.getElementById('diskText').innerText = `${d.used} / ${d.total} (${d.percent}%)`;
                document.getElementById('diskFill').style.width = d.percent + '%';
            });
        }
        function downloadItem(path) { location.href = '/download/' + path; }
        function deleteItem(path) {
            if(!confirm('정말 삭제하시겠습니까?')) return;
            fetch('/delete/' + path, {method:'POST'})
                .then(r=>r.json()).then(d=>{ if(d.success) location.reload(); else alert(d.error); });
        }
        function createFolder() {
            const name = document.getElementById('newFolderInput').value;
            if(!name) return;
            fetch('/mkdir/' + currentPath, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name: name})})
            .then(r=>r.json()).then(d => { if(d.success) location.reload(); else alert(d.error); });
        }
        
        let ctxTarget = null;
        document.addEventListener('click', () => document.getElementById('ctxMenu').style.display='none');
        function openCtx(e, path, name, type) {
            e.preventDefault();
            ctxTarget = {path, name, type};
            const unzipBtn = document.getElementById('ctxUnzip');
            if(unzipBtn) unzipBtn.style.display = (type === 'archive') ? 'flex' : 'none';
            const menu = document.getElementById('ctxMenu');
            menu.style.display = 'block';
            menu.style.left = e.pageX + 'px';
            menu.style.top = e.pageY + 'px';
        }
        function handleCtx(action) {
            if(!ctxTarget) return;
            if(action === 'download') downloadItem(ctxTarget.path);
            if(action === 'delete') {
                if(!confirm('영구적으로 삭제하시겠습니까? (복구 불가)')) return;
                deleteItem(ctxTarget.path);
            }
            if(action === 'unzip') {
                if(!confirm('압축 해제?')) return;
                fetch('/unzip/' + ctxTarget.path, {method:'POST'}).then(r=>r.json()).then(d=>{ 
                    if(d.success) { showToast('압축 해제 완료', 'success'); location.reload(); }
                    else showToast(d.error, 'error'); 
                });
            }
            if(action === 'rename') {
                const newName = prompt("새 이름:", ctxTarget.name);
                if(newName && newName !== ctxTarget.name) {
                    fetch('/rename/' + currentPath, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({old_name: ctxTarget.name, new_name: newName})})
                    .then(r=>r.json()).then(d=>{ if(d.success) location.reload(); else showToast(d.error, 'error'); });
                }
            }
            if(action === 'info') {
                showFileInfo(ctxTarget.path);
            }
            if(action === 'bookmark') {
                addBookmark(ctxTarget.path, ctxTarget.name);
            }
            if(action === 'share') {
                openShareModal(ctxTarget.path);
            }
            if(action === 'trash') {
                if(!confirm('휴지통으로 이동하시겠습니까?')) return;
                fetch('/trash', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path: ctxTarget.path})})
                .then(r=>r.json()).then(d=>{ 
                    if(d.success) { showToast('휴지통으로 이동됨', 'success'); location.reload(); }
                    else showToast(d.error, 'error'); 
                });
            }
        }
        
        // 파일 정보 표시
        function showFileInfo(path) {
            fetch('/file_info/' + path).then(r=>r.json()).then(d => {
                if(d.error) { showToast(d.error, 'error'); return; }
                
                const formatSize = (bytes) => {
                    if (bytes < 1024) return bytes + ' B';
                    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
                    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
                    return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
                };
                
                let html = `
                    <p><strong>이름:</strong> ${d.name}</p>
                    <p><strong>경로:</strong> ${d.path}</p>
                    <p><strong>타입:</strong> ${d.is_dir ? '폴더' : '파일'}</p>
                    <p><strong>크기:</strong> ${formatSize(d.size)}</p>
                    <p><strong>생성:</strong> ${new Date(d.created).toLocaleString()}</p>
                    <p><strong>수정:</strong> ${new Date(d.modified).toLocaleString()}</p>
                `;
                
                if(!d.is_dir) {
                    html += `<p><strong>MIME:</strong> ${d.mime_type || '-'}</p>`;
                    if(d.md5) html += `<p><strong>MD5:</strong> <code style="font-size:0.8rem;">${d.md5}</code></p>`;
                } else {
                    html += `<p><strong>파일:</strong> ${d.file_count || 0}개</p>`;
                    html += `<p><strong>폴더:</strong> ${d.folder_count || 0}개</p>`;
                }
                
                document.getElementById('fileInfoContent').innerHTML = html;
                openModal('fileInfoModal');
            });
        }
        
        // 북마크 관련
        function addBookmark(path, name) {
            fetch('/bookmarks', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path, name})})
            .then(r=>r.json()).then(d => {
                if(d.success) showToast('북마크 추가됨', 'success');
                else showToast(d.error, 'warning');
            });
        }
        
        function loadBookmarks() {
            fetch('/bookmarks').then(r=>r.json()).then(d => {
                const list = document.getElementById('bookmarkList');
                if(!d.bookmarks || d.bookmarks.length === 0) {
                    list.innerHTML = '<p style="text-align:center; opacity:0.6;">북마크가 없습니다.</p>';
                    return;
                }
                list.innerHTML = d.bookmarks.map(b => `
                    <div style="display:flex; align-items:center; padding:8px; border-bottom:1px solid var(--border);">
                        <i class="fa-solid fa-star" style="color:var(--folder); margin-right:10px;"></i>
                        <a href="/browse/${b.path}" style="flex:1; color:var(--text); text-decoration:none;">${b.name}</a>
                        <button class="btn-icon btn-danger" onclick="removeBookmark('${b.path}')" style="border:none;background:transparent;"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                `).join('');
            });
        }
        
        function removeBookmark(path) {
            fetch('/bookmarks', {method:'DELETE', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path})})
            .then(r=>r.json()).then(d => {
                if(d.success) { showToast('북마크 삭제됨', 'success'); loadBookmarks(); }
            });
        }
        
        // 휴지통 관련
        function loadTrash() {
            fetch('/trash/list').then(r=>r.json()).then(d => {
                const list = document.getElementById('trashList');
                if(!d.items || d.items.length === 0) {
                    list.innerHTML = '<p style="text-align:center; opacity:0.6;">휴지통이 비어있습니다.</p>';
                    return;
                }
                list.innerHTML = d.items.map(item => `
                    <div style="display:flex; align-items:center; padding:8px; border-bottom:1px solid var(--border);">
                        <i class="fa-solid ${item.is_dir ? 'fa-folder' : 'fa-file'}" style="margin-right:10px; color:var(--text); opacity:0.5;"></i>
                        <div style="flex:1;">
                            <div>${item.original_name}</div>
                            <div style="font-size:0.75rem; opacity:0.6;">${new Date(item.deleted_at).toLocaleString()}</div>
                        </div>
                        <button class="btn btn-outline" style="font-size:0.75rem; padding:4px 8px;" onclick="restoreFromTrash('${item.name}')"><i class="fa-solid fa-undo"></i></button>
                    </div>
                `).join('');
            });
        }
        
        function restoreFromTrash(name) {
            fetch('/trash/restore', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})})
            .then(r=>r.json()).then(d => {
                if(d.success) { showToast('복원됨', 'success'); loadTrash(); }
                else showToast(d.error, 'error');
            });
        }
        
        function emptyTrash() {
            if(!confirm('휴지통을 비우시겠습니까? (모든 항목 영구 삭제)')) return;
            fetch('/trash/empty', {method:'POST'}).then(r=>r.json()).then(d => {
                if(d.success) { showToast('휴지통 비움', 'success'); loadTrash(); }
                else showToast(d.error, 'error');
            });
        }
        
        // 공유 링크 관련
        let currentSharePath = '';
        
        function openShareModal(path) {
            currentSharePath = path;
            document.getElementById('sharePathDisplay').innerText = '대상: ' + path;
            document.getElementById('generatedLink').style.display = 'none';
            document.getElementById('createShareBtn').disabled = false;
            openModal('createShareModal');
        }
        
        function createShareLink() {
            const hours = parseInt(document.getElementById('shareHours').value);
            fetch('/share/create', {
                method:'POST', 
                headers:{'Content-Type':'application/json'}, 
                body:JSON.stringify({path: currentSharePath, hours})
            }).then(r=>r.json()).then(d => {
                if(d.success) {
                    const fullLink = window.location.origin + d.link;
                    document.getElementById('shareLinkInput').value = fullLink;
                    document.getElementById('generatedLink').style.display = 'block';
                    document.getElementById('createShareBtn').disabled = true;
                    showToast('공유 링크 생성됨', 'success');
                } else {
                    showToast(d.error, 'error');
                }
            });
        }
        
        function copyShareLink() {
            const input = document.getElementById('shareLinkInput');
            input.select();
            document.execCommand('copy');
            showToast('클립보드에 복사되었습니다', 'success');
        }
        
        function loadShareLinks() {
            fetch('/share/list').then(r=>r.json()).then(d => {
                const list = document.getElementById('shareList');
                if(!d.links || d.links.length === 0) {
                    list.innerHTML = '<p style="text-align:center; opacity:0.6;">활성 공유 링크가 없습니다.</p>';
                    return;
                }
                list.innerHTML = d.links.map(link => `
                    <div style="display:flex; align-items:center; padding:8px; border-bottom:1px solid var(--border);">
                        <i class="fa-solid fa-link" style="margin-right:10px; color:var(--primary);"></i>
                        <div style="flex:1; min-width:0;">
                            <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${link.path}</div>
                            <div style="font-size:0.75rem; opacity:0.6;">만료: ${new Date(link.expires).toLocaleString()}</div>
                        </div>
                        <button class="btn btn-outline" style="font-size:0.75rem; padding:4px 8px; margin-right:5px;" onclick="navigator.clipboard.writeText(window.location.origin + '/share/${link.token}'); showToast('복사됨','success');"><i class="fa-solid fa-copy"></i></button>
                        <button class="btn-icon btn-danger" style="border:none;background:transparent;" onclick="deleteShareLink('${link.token}')"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                `).join('');
            });
        }
        
        function deleteShareLink(token) {
            fetch('/share/delete/' + token, {method:'POST'}).then(r=>r.json()).then(d => {
                if(d.success) { showToast('링크 삭제됨', 'success'); loadShareLinks(); }
            });
        }
        
        function loadClipboard() { fetch('/clipboard').then(r=>r.json()).then(d => document.getElementById('clipText').value = d.content); }
        function saveClipboard() { fetch('/clipboard', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({content: document.getElementById('clipText').value})}).then(()=> { showToast('저장됨', 'success'); closeModal('clipModal'); }); }
        function toggleTheme() {
            const html = document.documentElement;
            const isDark = html.getAttribute('data-theme') === 'dark';
            html.setAttribute('data-theme', isDark ? 'light' : 'dark');
            localStorage.setItem('theme', isDark ? 'light' : 'dark');
        }
        function toggleView() {
            const list = document.getElementById('fileList');
            const icon = document.getElementById('viewIcon');
            if(list.parentElement.classList.contains('grid-view')) {
                list.parentElement.classList.remove('grid-view');
                icon.className = 'fa-solid fa-list';
                localStorage.setItem('view', 'list');
            } else {
                list.parentElement.classList.add('grid-view');
                icon.className = 'fa-solid fa-border-all';
                localStorage.setItem('view', 'grid');
                document.querySelectorAll('.preview').forEach(img => img.style.display = 'block');
            }
        }
        function filterFiles() {
            const q = document.getElementById('searchInput').value.toLowerCase();
            document.querySelectorAll('.data-item').forEach(item => {
                const name = item.getAttribute('data-name').toLowerCase();
                item.style.display = name.includes(q) ? 'flex' : 'none';
            });
        }
        function openModal(id) { 
            document.getElementById(id).style.display = 'flex'; 
        }
        function closeModal(id) { document.getElementById(id).style.display = 'none'; }
        
        const savedTheme = localStorage.getItem('theme');
        if(savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
        else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) document.documentElement.setAttribute('data-theme', 'dark');
        if(localStorage.getItem('view') === 'grid') toggleView();
    </script>
</body>
</html>
"""

# ==========================================
# 4. Flask 웹 서버 로직
# ==========================================
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB 제한

clipboard_store = ""
login_block = {} 

def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

@app.before_request
def before_request():
    g.start = time.time()
    STATS['requests'] += 1
    STATS['active_connections'] += 1
    
    # 세션 타임아웃 검사
    if session.get('logged_in'):
        last_active = session.get('last_active')
        if last_active:
            timeout = conf.get('session_timeout') or SESSION_TIMEOUT_MINUTES
            if datetime.now().timestamp() - last_active > timeout * 60:
                session.clear()
                logger.add(f"세션 만료: {get_real_ip()}")
        session['last_active'] = datetime.now().timestamp()

@app.after_request
def after_request(response):
    if response.content_length:
        STATS['bytes_sent'] += response.content_length
    STATS['active_connections'] = max(0, STATS['active_connections'] - 1)
    return response

def login_required(role_req='guest'):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return jsonify({'error': '로그인이 필요합니다.'}), 401
            if role_req == 'admin' and session.get('role') != 'admin':
                return jsonify({'error': '관리자 권한이 필요합니다.'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_security():
    ip = get_real_ip()
    if ip in login_block:
        info = login_block[ip]
        if info['count'] >= 5:
            if datetime.now() < info['block_until']:
                return False
            else:
                del login_block[ip]
    return True

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/browse/<path:path>', methods=['GET', 'POST'])
def index(path):
    if not check_security():
        return render_template_string(HTML_TEMPLATE, logged_in=False, error="보안 차단됨: 잠시 후 다시 시도하세요.")

    if request.method == 'POST':
        pw = request.form.get('password')
        ip = get_real_ip()
        
        # v4: verify_password 사용 (해시 + 평문 호환)
        if verify_password(conf.get('admin_pw'), pw):
            session['logged_in'] = True
            session['role'] = 'admin'
            session['last_active'] = datetime.now().timestamp()
            if ip in login_block: del login_block[ip]
            logger.add(f"관리자 로그인: {ip}")
            log_access(ip, 'login', 'admin')
            return redirect(url_for('index', path=path))
        elif verify_password(conf.get('guest_pw'), pw):
            session['logged_in'] = True
            session['role'] = 'guest'
            session['last_active'] = datetime.now().timestamp()
            if ip in login_block: del login_block[ip]
            logger.add(f"게스트 로그인: {ip}")
            log_access(ip, 'login', 'guest')
            return redirect(url_for('index', path=path))
        else:
            if ip not in login_block: login_block[ip] = {'count': 0, 'block_until': None}
            login_block[ip]['count'] += 1
            if login_block[ip]['count'] >= 5:
                login_block[ip]['block_until'] = datetime.now() + timedelta(minutes=10)
                logger.add(f"로그인 차단됨: {ip}", "WARN")
            log_access(ip, 'login_failed', '')
            return render_template_string(HTML_TEMPLATE, logged_in=False, error="비밀번호가 올바르지 않습니다.")

    if not session.get('logged_in'):
        return render_template_string(HTML_TEMPLATE, logged_in=False)

    base_dir = conf.get('folder')
    abs_path = os.path.join(base_dir, path)
    
    try:
        if not os.path.abspath(abs_path).startswith(os.path.abspath(base_dir)):
            return abort(403)
    except: return abort(403)

    if not os.path.exists(abs_path): return abort(404)

    items = []
    try:
        with os.scandir(abs_path) as entries:
            for entry in entries:
                f_type = 'file'
                if entry.is_dir(): f_type = 'folder'
                else:
                    if entry.name.lower().endswith(tuple(TEXT_EXTENSIONS)):
                        f_type = 'text'
                    else:
                        mt, _ = mimetypes.guess_type(entry.name)
                        if mt:
                            if mt.startswith('image'): f_type = 'image'
                            elif mt.startswith('video'): f_type = 'video'
                            elif mt.startswith('audio'): f_type = 'audio'
                            elif mt in ['application/zip', 'application/x-rar-compressed']: f_type = 'archive'

                stat = entry.stat()
                size_str = "-"
                raw_size = 0
                if not entry.is_dir():
                    raw_size = stat.st_size
                    if raw_size < 1024: size_str = f"{raw_size} B"
                    elif raw_size < 1024*1024: size_str = f"{raw_size/1024:.1f} KB"
                    else: size_str = f"{raw_size/(1024*1024):.1f} MB"

                items.append({
                    'name': entry.name,
                    'is_dir': entry.is_dir(),
                    'type': f_type,
                    'size': size_str,
                    'raw_size': raw_size,
                    'raw_mtime': stat.st_mtime,
                    'ext': os.path.splitext(entry.name)[1],
                    'mod_time': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'rel_path': os.path.relpath(entry.path, base_dir).replace('\\', '/')
                })
    except Exception as e:
        logger.add(f"탐색 오류: {e}", "ERROR")

    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    can_modify = (session.get('role') == 'admin') or (conf.get('allow_guest_upload'))
    return render_template_string(HTML_TEMPLATE, logged_in=True, role=session.get('role'), 
                                  items=items, current_path=path, can_modify=can_modify)

@app.route('/metrics')
@login_required()
def metrics():
    uptime = datetime.now() - SERVER_START_TIME
    uptime_str = str(uptime).split('.')[0]
    
    def fmt_bytes(b):
        if b < 1024: return f"{b} B"
        elif b < 1024*1024: return f"{b/1024:.1f} KB"
        elif b < 1024*1024*1024: return f"{b/1024/1024:.1f} MB"
        return f"{b/1024/1024/1024:.1f} GB"

    return jsonify({
        'uptime': uptime_str,
        'requests': STATS['requests'],
        'sent': fmt_bytes(STATS['bytes_sent']),
        'recv': fmt_bytes(STATS['bytes_received'])
    })

@app.route('/upload/<path:path>', methods=['POST'])
def upload_file(path):
    # 권한 체크 로직 통합
    if not (session.get('role')=='admin' or conf.get('allow_guest_upload')):
        return jsonify({'error':'권한 없음'}), 403
    
    target_dir = os.path.join(conf.get('folder'), path)
    files = request.files.getlist('file')
    paths = request.form.getlist('paths') 
    
    count = 0
    total_size = 0
    for i, file in enumerate(files):
        if file.filename:
            file.seek(0, os.SEEK_END)
            total_size += file.tell()
            file.seek(0)
            
            # [수정됨] safe_filename 사용으로 한글 지원
            safe_name = safe_filename(file.filename)

            if paths and len(paths) > i and '/' in paths[i]:
                rel_path = paths[i]
                if '..' in rel_path: continue
                # 경로 부분의 파일명도 안전하게 처리해야 함
                parts = rel_path.split('/')
                safe_parts = [safe_filename(p) for p in parts]
                save_path = os.path.join(target_dir, *safe_parts)
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                file.save(save_path)
            else:
                file.save(os.path.join(target_dir, safe_name))
            count += 1
    
    STATS['bytes_received'] += total_size
    logger.add(f"업로드: {count}개 항목 -> /{path}")
    return jsonify({'success': True})

@app.route('/batch_download/<path:path>', methods=['POST'])
def batch_download(path):
    if not session.get('logged_in'): return abort(401)
    base_dir = conf.get('folder')
    current_dir = os.path.join(base_dir, path)
    
    try:
        data = json.loads(request.form.get('files'))
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for item_name in data:
                # [수정됨] safe_filename 적용
                item_path = os.path.join(current_dir, safe_filename(item_name))
                if os.path.isfile(item_path):
                    zf.write(item_path, item_name)
                elif os.path.isdir(item_path):
                    for root, dirs, files in os.walk(item_path):
                        for file in files:
                            abs_file = os.path.join(root, file)
                            rel_file = os.path.relpath(abs_file, current_dir)
                            zf.write(abs_file, rel_file)
        
        mem_zip.seek(0)
        return send_file(mem_zip, download_name=f"batch_download.zip", as_attachment=True)
    except Exception as e:
        logger.add(f"배치 다운로드 오류: {e}", "ERROR")
        return abort(500)

@app.route('/batch_delete/<path:path>', methods=['POST'])
@login_required('admin')
def batch_delete(path):
    base_dir = conf.get('folder')
    current_dir = os.path.join(base_dir, path)
    data = request.get_json()
    files = data.get('files', [])
    
    count = 0
    try:
        for item_name in files:
            # [수정됨] safe_filename 적용
            item_path = os.path.join(current_dir, safe_filename(item_name))
            if os.path.exists(item_path):
                if os.path.isfile(item_path): os.remove(item_path)
                else: shutil.rmtree(item_path)
                count += 1
        logger.add(f"일괄 삭제: {count}개 항목")
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

@app.route('/download/<path:filename>')
def download_file(filename):
    if not session.get('logged_in'): return abort(401)
    
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), filename)
    if not is_valid:
        logger.add(f"다운로드 경로 검증 실패: {filename}", "WARN")
        return abort(403)
    
    if not os.path.exists(full_path):
        return abort(404)
    
    return send_from_directory(conf.get('folder'), filename)

@app.route('/mkdir/<path:path>', methods=['POST'])
def mkdir(path):
    if not (session.get('role')=='admin' or conf.get('allow_guest_upload')): return jsonify({'error':'권한 없음'}), 403
    try:
        data = request.get_json()
        # [수정됨] safe_filename 적용
        new_dir = os.path.join(conf.get('folder'), path, safe_filename(data['name']))
        os.makedirs(new_dir, exist_ok=True)
        logger.add(f"폴더 생성: {data['name']}")
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

@app.route('/delete/<path:path>', methods=['POST'])
@login_required('admin')
def delete_item(path):
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid:
        return jsonify({'success': False, 'error': error}), 403
    
    try:
        if os.path.isfile(full_path): 
            os.remove(full_path)
        else: 
            shutil.rmtree(full_path)
        logger.add(f"삭제: {path}")
        return jsonify({'success': True})
    except Exception as e: 
        logger.add(f"삭제 오류: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/rename/<path:path>', methods=['POST'])
@login_required('admin')
def rename_item(path):
    data = request.get_json()
    base = os.path.join(conf.get('folder'), path)
    # [수정됨] safe_filename 적용
    old = os.path.join(base, safe_filename(data['old_name']))
    new = os.path.join(base, safe_filename(data['new_name']))
    try:
        os.rename(old, new)
        logger.add(f"이름변경: {data['old_name']} -> {data['new_name']}")
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

@app.route('/zip/<path:path>')
@login_required()
def download_zip(path):
    base_dir = conf.get('folder')
    target_dir = os.path.join(base_dir, path)
    if not os.path.exists(target_dir): return abort(404)
    
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zf.write(file_path, os.path.relpath(file_path, target_dir))
    mem_zip.seek(0)
    return send_file(mem_zip, download_name=f"{os.path.basename(target_dir)}.zip", as_attachment=True)

@app.route('/unzip/<path:path>', methods=['POST'])
@login_required('admin')
def unzip_file(path):
    zip_path = os.path.join(conf.get('folder'), path)
    extract_to = os.path.splitext(zip_path)[0]
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_to)
        logger.add(f"압축해제: {path}")
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

@app.route('/get_content/<path:path>')
@login_required()
def get_content(path):
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid:
        return jsonify({'error': error}), 403
    
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            return jsonify({'content': f.read()})
    except Exception as e: 
        logger.add(f"파일 읽기 오류: {e}", "ERROR")
        return jsonify({'error': str(e)})

@app.route('/save_content/<path:path>', methods=['POST'])
@login_required('admin')
def save_content(path):
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid:
        return jsonify({'success': False, 'error': error}), 403
    
    try:
        content = request.get_json().get('content', '')
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.add(f"파일수정: {path}")
        return jsonify({'success': True})
    except Exception as e: 
        logger.add(f"파일 저장 오류: {e}", "ERROR")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/disk_info')
@login_required()
def disk_info():
    try:
        t, u, f = shutil.disk_usage(conf.get('folder'))
        return jsonify({
            'total': f"{t/1024**3:.1f}GB", 
            'used': f"{u/1024**3:.1f}GB", 
            'percent': round((u/t)*100, 1)
        })
    except Exception as e:
        logger.add(f"디스크 정보 조회 오류: {e}", "ERROR")
        return jsonify({'error': '디스크 정보를 가져올 수 없습니다.'})

@app.route('/clipboard', methods=['GET', 'POST'])
def clipboard_handler():
    global clipboard_store
    if not session.get('logged_in'): return jsonify({'error':'Auth required'}), 401
    if request.method == 'POST':
        clipboard_store = request.get_json().get('content', '')
        return jsonify({'success': True})
    return jsonify({'content': clipboard_store})

# ==========================================
# v4 신규 API: 파일 관리 기능 확장
# ==========================================

@app.route('/copy', methods=['POST'])
@login_required('admin')
def copy_item():
    """파일/폴더 복사"""
    data = request.get_json()
    src_path = data.get('source', '')
    dst_path = data.get('destination', '')
    
    base_dir = conf.get('folder')
    is_valid_src, full_src, _ = validate_path(base_dir, src_path)
    is_valid_dst, full_dst, _ = validate_path(base_dir, dst_path)
    
    if not is_valid_src or not is_valid_dst:
        return jsonify({'success': False, 'error': '잘못된 경로입니다.'})
    
    if not os.path.exists(full_src):
        return jsonify({'success': False, 'error': '원본을 찾을 수 없습니다.'})
    
    try:
        if os.path.isdir(full_src):
            shutil.copytree(full_src, full_dst)
        else:
            os.makedirs(os.path.dirname(full_dst), exist_ok=True)
            shutil.copy2(full_src, full_dst)
        logger.add(f"복사: {src_path} -> {dst_path}")
        log_access(get_real_ip(), 'copy', f"{src_path} -> {dst_path}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/move', methods=['POST'])
@login_required('admin')
def move_item():
    """파일/폴더 이동"""
    data = request.get_json()
    src_path = data.get('source', '')
    dst_path = data.get('destination', '')
    
    base_dir = conf.get('folder')
    is_valid_src, full_src, _ = validate_path(base_dir, src_path)
    is_valid_dst, full_dst, _ = validate_path(base_dir, dst_path)
    
    if not is_valid_src or not is_valid_dst:
        return jsonify({'success': False, 'error': '잘못된 경로입니다.'})
    
    if not os.path.exists(full_src):
        return jsonify({'success': False, 'error': '원본을 찾을 수 없습니다.'})
    
    try:
        os.makedirs(os.path.dirname(full_dst), exist_ok=True)
        shutil.move(full_src, full_dst)
        logger.add(f"이동: {src_path} -> {dst_path}")
        log_access(get_real_ip(), 'move', f"{src_path} -> {dst_path}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/search')
@login_required()
def search_files():
    """서버 전체 파일 검색"""
    query = request.args.get('q', '').lower().strip()
    if not query or len(query) < 2:
        return jsonify({'results': [], 'error': '검색어는 2자 이상이어야 합니다.'})
    
    base_dir = conf.get('folder')
    results = []
    max_results = 100
    
    try:
        for root, dirs, files in os.walk(base_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for name in files + dirs:
                if query in name.lower():
                    rel_path = os.path.relpath(os.path.join(root, name), base_dir).replace('\\', '/')
                    results.append({'name': name, 'path': rel_path, 'is_dir': name in dirs})
                    if len(results) >= max_results:
                        break
            if len(results) >= max_results:
                break
    except Exception as e:
        logger.add(f"검색 오류: {e}", "ERROR")
    
    return jsonify({'results': results, 'count': len(results)})

@app.route('/thumbnail/<path:filepath>')
@login_required()
def get_thumbnail(filepath):
    """이미지 썸네일 생성"""
    is_valid, full_path, _ = validate_path(conf.get('folder'), filepath)
    if not is_valid or not os.path.exists(full_path):
        return abort(404)
    
    cache_key = f"{filepath}_{os.path.getmtime(full_path)}"
    if cache_key in THUMBNAIL_CACHE:
        return send_file(io.BytesIO(THUMBNAIL_CACHE[cache_key]), mimetype='image/jpeg')
    
    try:
        img = Image.open(full_path)
        img.thumbnail((150, 150), Image.Resampling.LANCZOS)
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=70)
        buffer.seek(0)
        if len(THUMBNAIL_CACHE) > 100:
            THUMBNAIL_CACHE.pop(next(iter(THUMBNAIL_CACHE)))
        THUMBNAIL_CACHE[cache_key] = buffer.getvalue()
        buffer.seek(0)
        return send_file(buffer, mimetype='image/jpeg')
    except Exception as e:
        logger.add(f"썸네일 생성 실패: {e}", "ERROR")
        return abort(500)

@app.route('/versions/<path:filepath>')
@login_required('admin')
def list_versions(filepath):
    """파일 버전 목록 조회"""
    filename = os.path.basename(filepath)
    version_dir = os.path.join(conf.get('folder'), VERSION_FOLDER_NAME)
    if not os.path.exists(version_dir):
        return jsonify({'versions': []})
    versions = []
    for f in os.listdir(version_dir):
        if f.endswith(f'_{filename}'):
            full_path = os.path.join(version_dir, f)
            versions.append({'name': f, 'timestamp': f.rsplit('_', 1)[0], 'size': os.path.getsize(full_path)})
    versions.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'versions': versions})

@app.route('/versions/restore', methods=['POST'])
@login_required('admin')
def restore_version():
    """파일 버전 복원"""
    data = request.get_json()
    version_name = data.get('version', '')
    target_path = data.get('target', '')
    version_dir = os.path.join(conf.get('folder'), VERSION_FOLDER_NAME)
    version_path = os.path.join(version_dir, safe_filename(version_name))
    is_valid, full_target, _ = validate_path(conf.get('folder'), target_path)
    if not os.path.exists(version_path) or not is_valid:
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'})
    try:
        shutil.copy2(version_path, full_target)
        logger.add(f"버전 복원: {version_name} -> {target_path}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/access_log')
@login_required('admin')
def get_access_log():
    """접속 기록 조회"""
    return jsonify({'logs': ACCESS_LOG})

# ==========================================
# 새 기능: 공유 링크
# ==========================================
import secrets

@app.route('/share/create', methods=['POST'])
@login_required('admin')
def create_share_link():
    """임시 공유 링크 생성"""
    data = request.get_json()
    path = data.get('path', '')
    hours = data.get('hours', 24)  # 기본 24시간 유효
    
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'success': False, 'error': '유효하지 않은 경로입니다.'}), 400
    
    # 토큰 생성
    token = secrets.token_urlsafe(16)
    expires = datetime.now() + timedelta(hours=hours)
    
    SHARE_LINKS[token] = {
        'path': path,
        'expires': expires,
        'created_by': session.get('role', 'unknown'),
        'is_dir': os.path.isdir(full_path)
    }
    
    logger.add(f"공유 링크 생성: {path} ({hours}시간)")
    return jsonify({
        'success': True,
        'token': token,
        'expires': expires.isoformat(),
        'link': f"/share/{token}"
    })

@app.route('/share/<token>')
def access_share_link(token):
    """공유 링크로 파일 접근"""
    if token not in SHARE_LINKS:
        return abort(404)
    
    share_info = SHARE_LINKS[token]
    
    # 만료 확인
    if datetime.now() > share_info['expires']:
        del SHARE_LINKS[token]
        return abort(410)  # Gone
    
    # 경로 검증
    is_valid, full_path, error = validate_path(conf.get('folder'), share_info['path'])
    if not is_valid or not os.path.exists(full_path):
        return abort(404)
    
    if share_info['is_dir']:
        # 폴더인 경우 ZIP으로 다운로드
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zf.write(file_path, os.path.relpath(file_path, full_path))
        mem_zip.seek(0)
        return send_file(mem_zip, download_name=f"{os.path.basename(full_path)}.zip", as_attachment=True)
    else:
        return send_from_directory(conf.get('folder'), share_info['path'])

@app.route('/share/list')
@login_required('admin')
def list_share_links():
    """활성 공유 링크 목록"""
    now = datetime.now()
    active_links = []
    expired_tokens = []
    
    for token, info in SHARE_LINKS.items():
        if now > info['expires']:
            expired_tokens.append(token)
        else:
            active_links.append({
                'token': token,
                'path': info['path'],
                'expires': info['expires'].isoformat(),
                'is_dir': info['is_dir']
            })
    
    # 만료된 링크 정리
    for token in expired_tokens:
        del SHARE_LINKS[token]
    
    return jsonify({'links': active_links})

@app.route('/share/delete/<token>', methods=['POST'])
@login_required('admin')
def delete_share_link(token):
    """공유 링크 삭제"""
    if token in SHARE_LINKS:
        del SHARE_LINKS[token]
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': '링크를 찾을 수 없습니다.'})

# ==========================================
# 새 기능: 파일 정보 상세
# ==========================================
@app.route('/file_info/<path:path>')
@login_required()
def get_file_info(path):
    """파일 상세 정보 조회"""
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'error': '파일을 찾을 수 없습니다.'}), 404
    
    stat = os.stat(full_path)
    info = {
        'name': os.path.basename(full_path),
        'path': path,
        'is_dir': os.path.isdir(full_path),
        'size': stat.st_size,
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
    }
    
    if not info['is_dir']:
        # 파일 해시 계산 (작은 파일만)
        if stat.st_size < 10 * 1024 * 1024:  # 10MB 이하
            try:
                with open(full_path, 'rb') as f:
                    info['md5'] = hashlib.md5(f.read()).hexdigest()
            except:
                pass
        
        # MIME 타입
        mime_type, _ = mimetypes.guess_type(full_path)
        info['mime_type'] = mime_type or 'application/octet-stream'
    else:
        # 폴더 내 파일/폴더 개수
        try:
            items = os.listdir(full_path)
            info['file_count'] = len([i for i in items if os.path.isfile(os.path.join(full_path, i))])
            info['folder_count'] = len([i for i in items if os.path.isdir(os.path.join(full_path, i))])
        except:
            pass
    
    return jsonify(info)

# ==========================================
# 새 기능: 북마크
# ==========================================
@app.route('/bookmarks', methods=['GET', 'POST', 'DELETE'])
@login_required()
def handle_bookmarks():
    """북마크 관리"""
    global BOOKMARKS
    
    if request.method == 'GET':
        return jsonify({'bookmarks': BOOKMARKS})
    
    elif request.method == 'POST':
        data = request.get_json()
        path = data.get('path', '')
        name = data.get('name', os.path.basename(path))
        
        # 중복 확인
        if any(b['path'] == path for b in BOOKMARKS):
            return jsonify({'success': False, 'error': '이미 북마크되어 있습니다.'})
        
        BOOKMARKS.append({'path': path, 'name': name, 'added': datetime.now().isoformat()})
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        data = request.get_json()
        path = data.get('path', '')
        BOOKMARKS = [b for b in BOOKMARKS if b['path'] != path]
        return jsonify({'success': True})

# ==========================================
# 새 기능: 휴지통 (Trash)
# ==========================================
@app.route('/trash', methods=['POST'])
@login_required('admin')
def move_to_trash():
    """파일을 휴지통으로 이동"""
    data = request.get_json()
    path = data.get('path', '')
    
    is_valid, full_path, error = validate_path(conf.get('folder'), path)
    if not is_valid or not os.path.exists(full_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'}), 404
    
    # 휴지통 폴더 생성
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    os.makedirs(trash_dir, exist_ok=True)
    
    # 타임스탬프를 붙여 이동
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = os.path.basename(full_path)
    trash_name = f"{timestamp}_{base_name}"
    trash_path = os.path.join(trash_dir, trash_name)
    
    try:
        shutil.move(full_path, trash_path)
        logger.add(f"휴지통 이동: {path}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/trash/list')
@login_required('admin')
def list_trash():
    """휴지통 목록"""
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    if not os.path.exists(trash_dir):
        return jsonify({'items': []})
    
    items = []
    for name in os.listdir(trash_dir):
        full_path = os.path.join(trash_dir, name)
        stat = os.stat(full_path)
        items.append({
            'name': name,
            'original_name': '_'.join(name.split('_')[2:]) if name.count('_') >= 2 else name,
            'is_dir': os.path.isdir(full_path),
            'size': stat.st_size,
            'deleted_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
    
    return jsonify({'items': items})

@app.route('/trash/restore', methods=['POST'])
@login_required('admin')
def restore_from_trash():
    """휴지통에서 복원"""
    data = request.get_json()
    name = data.get('name', '')
    
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    trash_path = os.path.join(trash_dir, safe_filename(name))
    
    if not os.path.exists(trash_path):
        return jsonify({'success': False, 'error': '파일을 찾을 수 없습니다.'})
    
    # 원래 이름 추출 (timestamp 제거)
    original_name = '_'.join(name.split('_')[2:]) if name.count('_') >= 2 else name
    restore_path = os.path.join(conf.get('folder'), original_name)
    
    try:
        shutil.move(trash_path, restore_path)
        logger.add(f"휴지통 복원: {original_name}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/trash/empty', methods=['POST'])
@login_required('admin')
def empty_trash():
    """휴지통 비우기"""
    trash_dir = os.path.join(conf.get('folder'), TRASH_FOLDER_NAME)
    if os.path.exists(trash_dir):
        try:
            shutil.rmtree(trash_dir)
            logger.add("휴지통 비움")
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ==========================================
# 5. 서버 스레드 관리 (Aggressive Shutdown)
# ==========================================
class ServerThread(threading.Thread):
    def __init__(self, use_https=False):
        threading.Thread.__init__(self)
        self.server = None
        self.daemon = True
        self.use_https = use_https
        self.port = int(conf.get('port'))

    def run(self):
        try:
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)
            
            ssl_ctx = None
            proto = "http"
            if self.use_https:
                try:
                    # cryptography 라이브러리가 없으면 에러 발생 가능
                    ssl_ctx = 'adhoc' 
                    proto = "https"
                except Exception as e:
                    logger.add(f"HTTPS(adhoc) 설정 실패: {e}\nHTTP로 전환합니다.", "ERROR")
                    self.use_https = False
                    ssl_ctx = None
                    proto = "http"

            import werkzeug.serving
            if hasattr(werkzeug.serving, 'make_server'):
                # Werkzeug 서버 생성
                self.server = make_server(
                    conf.get('display_host'), 
                    self.port, 
                    app,
                    threaded=True,
                    ssl_context=ssl_ctx
                )
            else:
                logger.add("Werkzeug 버전 호환성 경고: make_server를 찾을 수 없습니다.", "WARN")
                return

            logger.add(f"서버 시작: {proto}://{conf.get('display_host')}:{self.port}")
            
            # serve_forever 실행 (shutdown 시 socket error가 날 수 있으므로 예외 처리)
            try:
                self.server.serve_forever()
            except OSError:
                pass # 서버 소켓이 강제 종료되면 발생하는 정상적인 현상
            except Exception as e:
                logger.add(f"서버 실행 중 오류: {e}", "ERROR")
                
        except OSError as e:
            if e.errno == 98 or e.errno == 10048: # Address already in use
                logger.add(f"포트 {self.port}가 이미 사용 중입니다.", "ERROR")
            else:
                logger.add(f"서버 시작 오류: {e}", "ERROR")
        except Exception as e:
            logger.add(f"서버 치명적 오류: {e}", "ERROR")

    def shutdown(self):
        if self.server:
            try:
                logger.add("서버 종료 신호 전송 중...")
                
                # [강력한 종료 로직]
                # 1. 종료 플래그 설정 (모든 가능성 고려)
                if hasattr(self.server, '_BaseServer__shutdown_request'):
                    self.server._BaseServer__shutdown_request = True
                if hasattr(self.server, '_shutdown_request'):
                    self.server._shutdown_request = True
                    
                # 2. 소켓 강제 종료 (블로킹 해제 핵심)
                if hasattr(self.server, 'socket') and self.server.socket:
                    try:
                        import socket
                        self.server.socket.shutdown(socket.SHUT_RDWR)
                    except: pass
                    try:
                        self.server.socket.close()
                    except: pass
                
                # 3. 공식 shutdown 호출 (타임아웃 적용?)
                # serve_forever가 루프를 돌고 있다면, 위 소켓 close로 인해 이미 에러가 나거나
                # 플래그 체크로 종료되었을 것임.
                try:
                    self.server.shutdown()
                except: pass
                
                try:
                    self.server.server_close()
                except: pass
                
            except Exception as e:
                logger.add(f"서버 종료 중 예외 (무시됨): {e}", "WARN")
            
            logger.add("서버가 중지되었습니다.")

server_thread = None

# ==========================================
# 6. Modern GUI (PyQt6 with Tkinter fallback)
# ==========================================

if PYQT6_AVAILABLE:
    # ==========================================
    # PyQt6 Modern GUI Implementation
    # ==========================================
    
    STYLESHEET = """
    QMainWindow, QWidget {
        background-color: #0f172a;
        color: #f1f5f9;
        font-family: 'Segoe UI', 'Malgun Gothic', sans-serif;
    }
    
    QTabWidget::pane {
        border: 1px solid #334155;
        border-radius: 8px;
        background-color: #1e293b;
    }
    
    QTabBar::tab {
        background-color: #1e293b;
        color: #94a3b8;
        padding: 12px 24px;
        margin-right: 4px;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
    }
    
    QTabBar::tab:selected {
        background-color: #334155;
        color: #f1f5f9;
    }
    
    QTabBar::tab:hover {
        background-color: #334155;
    }
    
    QPushButton {
        background-color: #4f46e5;
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 13px;
    }
    
    QPushButton:hover {
        background-color: #6366f1;
    }
    
    QPushButton:pressed {
        background-color: #4338ca;
    }
    
    QPushButton:disabled {
        background-color: #475569;
        color: #94a3b8;
    }
    
    QPushButton#stopBtn {
        background-color: #ef4444;
    }
    
    QPushButton#stopBtn:hover {
        background-color: #f87171;
    }
    
    QPushButton#outlineBtn {
        background-color: transparent;
        border: 1px solid #475569;
        color: #f1f5f9;
    }
    
    QPushButton#outlineBtn:hover {
        background-color: #334155;
    }
    
    QLineEdit, QComboBox {
        background-color: #1e293b;
        border: 1px solid #475569;
        border-radius: 6px;
        padding: 10px 12px;
        color: #f1f5f9;
        font-size: 13px;
    }
    
    QLineEdit:focus, QComboBox:focus {
        border-color: #6366f1;
    }
    
    QComboBox::drop-down {
        border: none;
        padding-right: 10px;
    }
    
    QComboBox::down-arrow {
        image: none;
        border: none;
    }
    
    QTextEdit {
        background-color: #0f172a;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 10px;
        color: #94a3b8;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12px;
    }
    
    QGroupBox {
        border: 1px solid #334155;
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 20px;
        font-weight: bold;
        color: #f1f5f9;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 8px;
    }
    
    QCheckBox {
        color: #f1f5f9;
        spacing: 8px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 4px;
        border: 2px solid #475569;
        background-color: transparent;
    }
    
    QCheckBox::indicator:checked {
        background-color: #4f46e5;
        border-color: #4f46e5;
    }
    
    QLabel {
        color: #f1f5f9;
    }
    
    QLabel#subtitle {
        color: #94a3b8;
        font-size: 12px;
    }
    
    QLabel#statusLabel {
        font-size: 18px;
        font-weight: bold;
    }
    
    QLabel#urlLabel {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 12px;
        font-family: 'Consolas', monospace;
        font-size: 14px;
        color: #818cf8;
    }
    
    QScrollArea {
        border: none;
        background-color: transparent;
    }
    """
    
    class WebShareGUI(QMainWindow):
        # 스레드 안전한 UI 업데이트를 위한 시그널 정의
        server_update_signal = pyqtSignal(bool)

        def __init__(self):
            super().__init__()
            self.setWindowTitle(APP_TITLE)
            self.setMinimumSize(650, 700)
            self.resize(650, 750)
            self.setStyleSheet(STYLESHEET)
            
            self.is_closing = False
            self.log_timer = QTimer()
            self.log_timer.timeout.connect(self.process_logs)
            self.log_timer.start(200)
            
            # 시그널 연결
            self.server_update_signal.connect(self.update_ui)

            
            # v4: 실시간 통계 타이머
            self.stats_timer = QTimer()
            self.stats_timer.timeout.connect(self.update_stats)
            self.stats_timer.start(5000)  # 5초마다 업데이트
            
            # v4: 시스템 트레이 설정
            self.setup_tray()
            
            self.init_ui()
        
        def setup_tray(self):
            """v4: 시스템 트레이 아이콘 설정"""
            self.tray_icon = QSystemTrayIcon(self)
            self.tray_icon.setToolTip(APP_TITLE)
            
            # 트레이 메뉴
            tray_menu = QMenu()
            show_action = QAction("프로그램 열기", self)
            show_action.triggered.connect(self.show_normal)
            tray_menu.addAction(show_action)
            
            browser_action = QAction("브라우저로 열기", self)
            browser_action.triggered.connect(self.open_browser)
            tray_menu.addAction(browser_action)
            
            tray_menu.addSeparator()
            
            quit_action = QAction("종료", self)
            quit_action.triggered.connect(self.force_quit)
            tray_menu.addAction(quit_action)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self.tray_activated)
            self.tray_icon.show()
        
        def tray_activated(self, reason):
            if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
                self.show_normal()
        
        def show_normal(self):
            self.show()
            self.activateWindow()
        
        def force_quit(self):
            self.is_closing = True
            if server_thread and server_thread.is_alive():
                server_thread.shutdown()
            QApplication.quit()
        
        def show_notification(self, title, message):
            """v4: 시스템 알림 표시"""
            if conf.get('enable_notifications') and self.tray_icon.isVisible():
                self.tray_icon.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 3000)
        
        def update_stats(self):
            """v4: 실시간 통계 업데이트"""
            if hasattr(self, 'stats_requests'):
                self.stats_requests.setText(f"요청: {STATS['requests']}")
            if hasattr(self, 'stats_connections'):
                self.stats_connections.setText(f"접속: {STATS['active_connections']}")
            
        def init_ui(self):
            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)
            layout.setContentsMargins(20, 20, 20, 20)
            layout.setSpacing(0)
            
            # Header
            header = QHBoxLayout()
            title = QLabel("🚀 WebShare Pro")
            title.setStyleSheet("font-size: 24px; font-weight: bold; color: #818cf8;")
            header.addWidget(title)
            header.addStretch()
            version = QLabel("v4.1")
            version.setObjectName("subtitle")
            header.addWidget(version)
            layout.addLayout(header)
            layout.addSpacing(20)
            
            # Tabs
            tabs = QTabWidget()
            tabs.addTab(self.build_home_tab(), "🏠 홈")
            tabs.addTab(self.build_settings_tab(), "⚙️ 설정")
            tabs.addTab(self.build_logs_tab(), "📝 로그")
            layout.addWidget(tabs)
            
        def build_home_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.setSpacing(20)
            layout.setContentsMargins(40, 40, 40, 40)
            
            # Status indicator
            self.status_label = QLabel("⏹ 서버 중지됨")
            self.status_label.setObjectName("statusLabel")
            self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.status_label.setStyleSheet("color: #94a3b8;")
            layout.addWidget(self.status_label)
            
            layout.addSpacing(20)
            
            # Start/Stop button
            self.toggle_btn = QPushButton("▶  서버 시작")
            self.toggle_btn.setFixedHeight(60)
            self.toggle_btn.setStyleSheet("""
                QPushButton {
                    font-size: 16px;
                    font-weight: bold;
                }
            """)
            self.toggle_btn.clicked.connect(self.toggle_server)
            layout.addWidget(self.toggle_btn)
            
            layout.addSpacing(30)
            
            # Connection info
            info_group = QGroupBox(" 📡 접속 정보")
            info_layout = QVBoxLayout(info_group)
            
            self.url_label = QLabel("-")
            self.url_label.setObjectName("urlLabel")
            self.url_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            info_layout.addWidget(self.url_label)
            
            btn_layout = QHBoxLayout()
            
            browser_btn = QPushButton("🌐 브라우저 열기")
            browser_btn.setObjectName("outlineBtn")
            browser_btn.clicked.connect(self.open_browser)
            btn_layout.addWidget(browser_btn)
            
            qr_btn = QPushButton("📱 QR 코드")
            qr_btn.setObjectName("outlineBtn")
            qr_btn.clicked.connect(self.show_qr)
            btn_layout.addWidget(qr_btn)
            
            info_layout.addLayout(btn_layout)
            layout.addWidget(info_group)
            
            layout.addStretch()
            return widget
            
        def build_settings_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setSpacing(15)
            layout.setContentsMargins(30, 30, 30, 30)
            
            # Folder selection
            folder_label = QLabel("📁 공유 폴더")
            layout.addWidget(folder_label)
            
            folder_layout = QHBoxLayout()
            self.folder_input = QLineEdit(conf.get('folder'))
            folder_layout.addWidget(self.folder_input)
            
            folder_btn = QPushButton("선택")
            folder_btn.setObjectName("outlineBtn")
            folder_btn.setFixedWidth(80)
            folder_btn.clicked.connect(self.choose_folder)
            folder_layout.addWidget(folder_btn)
            layout.addLayout(folder_layout)
            
            layout.addSpacing(10)
            
            # Network settings
            net_label = QLabel("🌐 네트워크 (IP / Port)")
            layout.addWidget(net_label)
            
            net_layout = QHBoxLayout()
            self.ip_combo = QComboBox()
            ips = self.get_ip_list()
            self.ip_combo.addItems(ips)
            current = conf.get('display_host')
            if current in ips:
                self.ip_combo.setCurrentText(current)
            net_layout.addWidget(self.ip_combo, 3)
            
            self.port_input = QLineEdit(str(conf.get('port')))
            self.port_input.setFixedWidth(80)
            net_layout.addWidget(self.port_input, 1)
            layout.addLayout(net_layout)
            
            layout.addSpacing(10)
            
            # Password settings
            pw_label = QLabel("🔐 비밀번호 (관리자 / 게스트)")
            layout.addWidget(pw_label)
            
            pw_layout = QHBoxLayout()
            self.admin_pw = QLineEdit(conf.get('admin_pw'))
            self.admin_pw.setEchoMode(QLineEdit.EchoMode.Password)
            self.admin_pw.setPlaceholderText("관리자")
            pw_layout.addWidget(self.admin_pw)
            
            self.guest_pw = QLineEdit(conf.get('guest_pw'))
            self.guest_pw.setEchoMode(QLineEdit.EchoMode.Password)
            self.guest_pw.setPlaceholderText("게스트")
            pw_layout.addWidget(self.guest_pw)
            layout.addLayout(pw_layout)
            
            layout.addSpacing(15)
            
            # Checkboxes
            self.guest_upload_check = QCheckBox("게스트 업로드 허용")
            self.guest_upload_check.setChecked(conf.get('allow_guest_upload'))
            layout.addWidget(self.guest_upload_check)
            
            self.https_check = QCheckBox("HTTPS 사용 (자체 서명 인증서)")
            self.https_check.setChecked(conf.get('use_https'))
            layout.addWidget(self.https_check)
            
            layout.addSpacing(20)
            
            # Save button
            save_btn = QPushButton("💾 설정 저장")
            save_btn.clicked.connect(self.save_settings)
            layout.addWidget(save_btn)
            
            layout.addStretch()
            return widget
            
        def build_logs_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setContentsMargins(20, 20, 20, 20)
            
            self.log_text = QTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setPlaceholderText("서버 로그가 여기에 표시됩니다...")
            layout.addWidget(self.log_text)
            
            clear_btn = QPushButton("🗑 로그 클리어")
            clear_btn.setObjectName("outlineBtn")
            clear_btn.clicked.connect(lambda: self.log_text.clear())
            layout.addWidget(clear_btn)
            
            return widget
            
        def get_ip_list(self):
            ips = ['127.0.0.1']
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.1)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith('127.'):
                    ips.insert(0, ip)
                s.close()
            except: pass
            
            try:
                host_name = socket.gethostname()
                for ip in socket.gethostbyname_ex(host_name)[2]:
                    if ip and not ip.startswith("127.") and ip not in ips:
                        ips.append(ip)
            except: pass
            
            ips.append('0.0.0.0')
            return ips
            
        def choose_folder(self):
            path = QFileDialog.getExistingDirectory(self, "공유 폴더 선택")
            if path:
                self.folder_input.setText(os.path.abspath(path))
                
        def save_settings(self):
            conf.set('folder', self.folder_input.text())
            conf.set('display_host', self.ip_combo.currentText())
            try:
                conf.set('port', int(self.port_input.text()))
            except: pass
            conf.set('admin_pw', self.admin_pw.text())
            conf.set('guest_pw', self.guest_pw.text())
            conf.set('allow_guest_upload', self.guest_upload_check.isChecked())
            conf.set('use_https', self.https_check.isChecked())
            conf.save()
            QMessageBox.information(self, "저장", "설정이 저장되었습니다.")
            
        def toggle_server(self):
            global server_thread
            
            if server_thread and server_thread.is_alive():
                self.toggle_btn.setEnabled(False)
                self.toggle_btn.setText("⏳ 중지 중...")
                threading.Thread(target=self._stop_server, daemon=True).start()
            else:
                self.save_settings()
                if not os.path.exists(conf.get('folder')):
                    QMessageBox.critical(self, "오류", "공유 폴더 경로가 잘못되었습니다.")
                    return
                    
                server_thread = ServerThread(use_https=conf.get('use_https'))
                server_thread.start()
                self.update_ui(True)
                
        def _stop_server(self):
            global server_thread
            try:
                if server_thread:
                    server_thread.shutdown()
                    server_thread.join(timeout=2.0)
            except Exception as e:
                logger.add(f"서버 종료 중 오류: {e}", "ERROR")
            finally:
                server_thread = None
                if not self.is_closing:
                    # 시그널 통해 UI 업데이트 호출 (스레드 안전)
                    self.server_update_signal.emit(False)
                
        def update_ui(self, running):
            if self.is_closing:
                return
            self.toggle_btn.setEnabled(True)
            
            if running:
                self.toggle_btn.setText("⏹  서버 중지")
                self.toggle_btn.setObjectName("stopBtn")
                self.toggle_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #ef4444;
                        font-size: 16px;
                        font-weight: bold;
                    }
                    QPushButton:hover { background-color: #f87171; }
                """)
                self.status_label.setText("🟢 서버 실행 중")
                self.status_label.setStyleSheet("color: #22c55e;")
                
                proto = "https" if conf.get('use_https') else "http"
                url = f"{proto}://{conf.get('display_host')}:{conf.get('port')}"
                self.url_label.setText(url)
            else:
                self.toggle_btn.setText("▶  서버 시작")
                self.toggle_btn.setObjectName("")
                self.toggle_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #4f46e5;
                        font-size: 16px;
                        font-weight: bold;
                    }
                    QPushButton:hover { background-color: #6366f1; }
                """)
                self.status_label.setText("⏹ 서버 중지됨")
                self.status_label.setStyleSheet("color: #94a3b8;")
                self.url_label.setText("-")
                
        def open_browser(self):
            url = self.url_label.text()
            if url != "-":
                webbrowser.open(url)
                
        def show_qr(self):
            url = self.url_label.text()
            if url == "-":
                return
            try:
                import qrcode
                qr = qrcode.make(url)
                
                dialog = QDialog(self)
                dialog.setWindowTitle("QR Code")
                dialog.setFixedSize(300, 340)
                dialog.setStyleSheet("background-color: white;")
                
                layout = QVBoxLayout(dialog)
                
                # Convert PIL image to QPixmap
                qr_bytes = io.BytesIO()
                qr.save(qr_bytes, format='PNG')
                qr_bytes.seek(0)
                
                pixmap = QPixmap()
                pixmap.loadFromData(qr_bytes.read())
                pixmap = pixmap.scaled(250, 250, Qt.AspectRatioMode.KeepAspectRatio)
                
                qr_label = QLabel()
                qr_label.setPixmap(pixmap)
                qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(qr_label)
                
                text_label = QLabel("모바일로 스캔하여 접속하세요")
                text_label.setStyleSheet("color: #333; font-size: 12px;")
                text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(text_label)
                
                dialog.exec()
            except ImportError:
                QMessageBox.critical(self, "오류", "qrcode 라이브러리가 설치되지 않았습니다.\npip install qrcode")
                
        def process_logs(self):
            if self.is_closing:
                return
            try:
                while not logger.queue.empty():
                    msg = logger.queue.get()
                    self.log_text.append(msg)
                    
                    # Limit log lines
                    doc = self.log_text.document()
                    if doc.blockCount() > MAX_LOG_LINES:
                        cursor = self.log_text.textCursor()
                        cursor.movePosition(cursor.MoveOperation.Start)
                        cursor.movePosition(cursor.MoveOperation.Down, cursor.MoveMode.KeepAnchor, 
                                          doc.blockCount() - MAX_LOG_LINES)
                        cursor.removeSelectedText()
            except: pass
            
        def closeEvent(self, event):
            global server_thread
            
            # v4: 서버 실행 중이면 트레이로 최소화 (설정에 따라)
            if server_thread and server_thread.is_alive() and conf.get('minimize_to_tray'):
                event.ignore()
                self.hide()
                self.tray_icon.showMessage(
                    "WebShare Pro",
                    "서버가 백그라운드에서 계속 실행 중입니다.",
                    QSystemTrayIcon.MessageIcon.Information,
                    2000
                )
                return
            
            self.is_closing = True
            if server_thread and server_thread.is_alive():
                reply = QMessageBox.question(self, "종료", "서버가 실행 중입니다. 종료하시겠습니까?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    threading.Thread(target=self._stop_server, daemon=True).start()
                    self.tray_icon.hide()
                    event.accept()
                else:
                    self.is_closing = False
                    event.ignore()
            else:
                self.tray_icon.hide()
                event.accept()

else:
    # ==========================================
    # Fallback: Tkinter GUI (if PyQt6 not available)
    # ==========================================
    class WebShareGUI:
        def __init__(self, root):
            self.root = root
            self.root.title(APP_TITLE)
            self.root.geometry("600x750")
            
            style = ttk.Style()
            style.theme_use('clam')
            style.configure("TFrame", background="#f8fafc")
            style.configure("TLabel", background="#f8fafc", font=("맑은 고딕", 10))
            style.configure("TButton", font=("맑은 고딕", 10), padding=5)
            
            self.root.configure(bg="#f8fafc")
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)
            
            self.is_closing = False
            self.init_ui()
            self.process_logs()

        def init_ui(self):
            tabs = ttk.Notebook(self.root)
            tabs.pack(fill='both', expand=True, padx=15, pady=15)
            
            tab_home = ttk.Frame(tabs); tabs.add(tab_home, text="  🏠 홈  ")
            tab_set = ttk.Frame(tabs); tabs.add(tab_set, text="  ⚙️ 설정  ")
            tab_log = ttk.Frame(tabs); tabs.add(tab_log, text="  📝 로그  ")
            
            self.build_home(tab_home)
            self.build_settings(tab_set)
            self.build_logs(tab_log)

        def build_home(self, parent):
            frame = ttk.Frame(parent)
            frame.pack(fill='both', expand=True, padx=20, pady=20)
            
            self.status_lbl = ttk.Label(frame, text="서버 중지됨", font=("맑은 고딕", 16, "bold"), foreground="#64748b")
            self.status_lbl.pack(pady=20)

            self.btn_toggle = tk.Button(frame, text="서버 시작", bg="#4f46e5", fg="white", 
                                      font=("맑은 고딕", 14, "bold"), relief="flat", cursor="hand2",
                                      command=self.toggle_server)
            self.btn_toggle.pack(fill='x', pady=30, ipady=10)

            info_frame = ttk.LabelFrame(frame, text=" 접속 정보 ", padding=15)
            info_frame.pack(fill='x')
            
            self.url_var = tk.StringVar(value="-")
            url_ent = ttk.Entry(info_frame, textvariable=self.url_var, state="readonly", font=("Consolas", 12), justify="center")
            url_ent.pack(fill='x', pady=5)
            
            btn_box = ttk.Frame(info_frame)
            btn_box.pack(fill='x', pady=5)
            ttk.Button(btn_box, text="브라우저 열기", command=self.open_browser).pack(side='left', expand=True, fill='x', padx=2)
            ttk.Button(btn_box, text="QR 코드", command=self.show_qr).pack(side='right', expand=True, fill='x', padx=2)

        def build_settings(self, parent):
            frame = ttk.Frame(parent)
            frame.pack(fill='both', expand=True, padx=20, pady=20)

            ttk.Label(frame, text="공유 폴더").pack(anchor='w')
            f_box = ttk.Frame(frame); f_box.pack(fill='x', pady=5)
            self.ent_folder = ttk.Entry(f_box)
            self.ent_folder.insert(0, conf.get('folder'))
            self.ent_folder.pack(side='left', fill='x', expand=True)
            ttk.Button(f_box, text="선택", command=self.choose_folder).pack(side='right', padx=5)

            ttk.Label(frame, text="네트워크 (IP / Port)").pack(anchor='w', pady=(15, 0))
            net_box = ttk.Frame(frame); net_box.pack(fill='x', pady=5)
            
            ips = self.get_ip_list()
            self.cb_ip = ttk.Combobox(net_box, values=ips, state="readonly")
            current_host = conf.get('display_host')
            if current_host in ips: self.cb_ip.set(current_host)
            elif ips: self.cb_ip.current(0)
            
            self.cb_ip.pack(side='left', fill='x', expand=True)
            
            self.ent_port = ttk.Entry(net_box, width=8)
            self.ent_port.insert(0, conf.get('port'))
            self.ent_port.pack(side='right', padx=5)

            ttk.Label(frame, text="비밀번호 설정 (관리자 / 게스트)").pack(anchor='w', pady=(15, 0))
            pw_box = ttk.Frame(frame); pw_box.pack(fill='x', pady=5)
            self.ent_admin_pw = ttk.Entry(pw_box, show="*")
            self.ent_admin_pw.insert(0, conf.get('admin_pw'))
            self.ent_admin_pw.pack(side='left', fill='x', expand=True, padx=(0, 5))
            
            self.ent_guest_pw = ttk.Entry(pw_box, show="*")
            self.ent_guest_pw.insert(0, conf.get('guest_pw'))
            self.ent_guest_pw.pack(side='right', fill='x', expand=True)
            
            self.var_upload = tk.BooleanVar(value=conf.get('allow_guest_upload'))
            ttk.Checkbutton(frame, text="게스트 업로드 허용", variable=self.var_upload).pack(anchor='w', pady=(10, 5))

            self.var_https = tk.BooleanVar(value=conf.get('use_https'))
            ttk.Checkbutton(frame, text="HTTPS 사용 (자체 서명 인증서)", variable=self.var_https).pack(anchor='w', pady=5)
            
            ttk.Button(frame, text="설정 저장", command=self.save_settings).pack(fill='x', pady=10)

        def build_logs(self, parent):
            frame = ttk.Frame(parent)
            frame.pack(fill='both', expand=True, padx=10, pady=10)
            self.txt_log = scrolledtext.ScrolledText(frame, state='disabled', font=("Consolas", 9))
            self.txt_log.pack(fill='both', expand=True)
            ttk.Button(frame, text="로그 클리어", command=lambda: self.txt_log.configure(state='normal') or self.txt_log.delete(1.0, tk.END) or self.txt_log.configure(state='disabled')).pack(anchor='e', pady=5)

        def get_ip_list(self):
            ips = set(['0.0.0.0', '127.0.0.1'])
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.1)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith('127.'):
                    ips.add(ip)
                s.close()
            except: pass
            try:
                host_name = socket.gethostname()
                for ip in socket.gethostbyname_ex(host_name)[2]:
                    if ip and not ip.startswith("127."):
                        ips.add(ip)
            except: pass
            sorted_ips = sorted(list(ips))
            if '0.0.0.0' in sorted_ips:
                sorted_ips.remove('0.0.0.0')
                sorted_ips.append('0.0.0.0')
            return sorted_ips

        def choose_folder(self):
            path = filedialog.askdirectory()
            if path:
                self.ent_folder.delete(0, tk.END)
                self.ent_folder.insert(0, os.path.abspath(path))

        def save_settings(self):
            conf.set('folder', self.ent_folder.get())
            conf.set('display_host', self.cb_ip.get())
            try: conf.set('port', int(self.ent_port.get()))
            except: pass
            conf.set('admin_pw', self.ent_admin_pw.get())
            conf.set('guest_pw', self.ent_guest_pw.get())
            conf.set('allow_guest_upload', self.var_upload.get())
            conf.set('use_https', self.var_https.get())
            conf.save()
            messagebox.showinfo("저장", "설정이 저장되었습니다.")

        def toggle_server(self):
            global server_thread
            if server_thread and server_thread.is_alive():
                self.btn_toggle.config(state='disabled', text="중지 중...")
                threading.Thread(target=self._stop_server_task, daemon=True).start()
            else:
                self.save_settings()
                if not os.path.exists(conf.get('folder')):
                    messagebox.showerror("오류", "공유 폴더 경로가 잘못되었습니다.")
                    return
                server_thread = ServerThread(use_https=conf.get('use_https'))
                server_thread.start()
                self.update_ui_state(True)

        def _stop_server_task(self):
            global server_thread
            if server_thread:
                server_thread.shutdown()
                server_thread.join(timeout=2.0)
                server_thread = None
            if not self.is_closing:
                self.root.after(0, lambda: self.update_ui_state(False))

        def update_ui_state(self, running):
            if self.is_closing: return
            self.btn_toggle.config(state='normal')
            if running:
                self.btn_toggle.config(text="서버 중지", bg="#ef4444")
                self.status_lbl.config(text="서버 실행 중", foreground="#22c55e")
                proto = "https" if conf.get('use_https') else "http"
                url = f"{proto}://{conf.get('display_host')}:{conf.get('port')}"
                self.url_var.set(url)
            else:
                self.btn_toggle.config(text="서버 시작", bg="#4f46e5")
                self.status_lbl.config(text="서버 중지됨", foreground="#64748b")
                self.url_var.set("-")

        def open_browser(self):
            url = self.url_var.get()
            if url != "-": webbrowser.open(url)
        
        def show_qr(self):
            url = self.url_var.get()
            if url == "-": return
            try:
                import qrcode
                qr = qrcode.make(url)
                win = tk.Toplevel(self.root)
                win.title("QR Code")
                win.geometry("300x300")
                img_tk = ImageTk.PhotoImage(qr)
                lbl = tk.Label(win, image=img_tk)
                lbl.image = img_tk
                lbl.pack(expand=True)
                tk.Label(win, text="모바일로 스캔하여 접속하세요").pack(pady=10)
            except ImportError:
                messagebox.showerror("오류", "qrcode/pillow 라이브러리가 설치되지 않았습니다.")

        def process_logs(self):
            if self.is_closing: return
            try:
                while not logger.queue.empty():
                    msg = logger.queue.get()
                    self.txt_log.configure(state='normal')
                    self.txt_log.insert(tk.END, msg + "\n")
                    num_lines = float(self.txt_log.index('end-1c'))
                    if num_lines > MAX_LOG_LINES:
                        self.txt_log.delete('1.0', f'{num_lines - MAX_LOG_LINES + 1}.0')
                    self.txt_log.see(tk.END)
                    self.txt_log.configure(state='disabled')
            except tk.TclError:
                pass 
            self.root.after(200, self.process_logs)

        def on_close(self):
            global server_thread
            self.is_closing = True
            if server_thread and server_thread.is_alive():
                if messagebox.askokcancel("종료", "서버가 실행 중입니다. 종료하시겠습니까?"):
                    try:
                        server_thread.shutdown()
                    except Exception as e:
                        logger.add(f"서버 종료 중 오류: {e}", "ERROR")
                    finally:
                        server_thread = None
                    self.root.destroy()
                    sys.exit(0)
                else:
                    self.is_closing = False
            else:
                self.root.destroy()
                sys.exit(0)


# ==========================================
# 7. Main Entry Point
# ==========================================
if __name__ == '__main__':
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass

    if PYQT6_AVAILABLE:
        qt_app = QApplication(sys.argv)
        qt_app.setStyle('Fusion')
        window = WebShareGUI()
        window.show()
        sys.exit(qt_app.exec())
    else:
        root = tk.Tk()
        app_gui = WebShareGUI(root)
        root.mainloop()
