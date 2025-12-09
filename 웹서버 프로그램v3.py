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

# GUI Imports
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
APP_TITLE = "WebShare Pro v3.1 (Fixed)"
CONFIG_FILE = "webshare_config.json"
DEFAULT_PORT = 5000
TEXT_EXTENSIONS = {'.txt', '.py', '.html', '.css', '.js', '.json', '.md', '.log', '.xml', '.ini', '.conf', '.sh', '.bat', '.c', '.cpp', '.h', '.java', '.sql', '.yaml', '.yml'}
MAX_LOG_LINES = 1000

# 서버 통계 전역 변수
SERVER_START_TIME = datetime.now()
STATS = {
    'requests': 0,
    'bytes_sent': 0,
    'bytes_received': 0,
    'errors': 0
}

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

class LogManager:
    def __init__(self):
        self.queue = queue.Queue()

    def add(self, msg, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] [{level}] {msg}"
        self.queue.put(formatted_msg)
        print(formatted_msg) 

logger = LogManager()

class ConfigManager:
    def __init__(self):
        self.config = {
            'folder': os.path.abspath(os.path.join(os.getcwd(), 'shared_files')),
            'port': DEFAULT_PORT,
            'admin_pw': "1234",
            'guest_pw': "0000",
            'allow_guest_upload': False,
            'display_host': '0.0.0.0',
            'use_https': False
        }
        self.load()

    def load(self):
        if not os.path.exists(self.config['folder']):
            try: os.makedirs(self.config['folder'])
            except: pass
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
            --primary: #4f46e5; --bg: #f8fafc; --card: #ffffff; --text: #334155; 
            --border: #e2e8f0; --danger: #ef4444; --folder: #fbbf24; --hover: #f1f5f9;
            --success: #22c55e; --focus-ring: #6366f1;
        }
        [data-theme="dark"] {
            --primary: #818cf8; --bg: #0f172a; --card: #1e293b; --text: #f1f5f9;
            --border: #334155; --folder: #f59e0b; --hover: #334155;
        }
        body { font-family: 'Pretendard', -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; transition: 0.3s; padding-bottom: 80px; -webkit-tap-highlight-color: transparent; }
        
        *:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; }

        .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .card { background: var(--card); border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); border: 1px solid var(--border); overflow: hidden; }
        
        .toolbar { display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; align-items: center; }
        .search-box { flex: 1; position: relative; min-width: 200px; }
        .search-box input { width: 100%; padding: 10px 10px 10px 35px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg); color: var(--text); box-sizing: border-box; height: 40px; }
        .search-box i { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); opacity: 0.6; }
        
        .sort-select { padding: 0 10px; height: 40px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg); color: var(--text); cursor: pointer; }

        .btn { background: var(--primary); color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; transition: 0.2s; font-size: 0.9rem; height: 40px; box-sizing: border-box; }
        .btn:hover { filter: brightness(1.1); }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
        .btn-outline:hover { background: var(--hover); }
        .btn-icon { width: 36px; padding: 0; justify-content: center; border-radius: 50%; }
        .btn-danger { background: rgba(239,68,68,0.1); color: var(--danger); }

        #batchBar { display: none; align-items: center; gap: 10px; background: var(--primary); color: white; padding: 8px 15px; border-radius: 8px; animation: slideDown 0.3s; }
        @keyframes slideDown { from { transform: translateY(-10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

        .file-list { list-style: none; padding: 0; margin: 0; }
        .file-item { display: flex; align-items: center; padding: 12px 15px; border-bottom: 1px solid var(--border); cursor: pointer; transition: 0.2s; user-select: none; }
        .file-item:hover { background: var(--hover); }
        .file-item.selected { background: rgba(79, 70, 229, 0.1); }
        
        .file-check { margin-right: 15px; transform: scale(1.3); cursor: pointer; accent-color: var(--primary); }
        .file-icon { font-size: 1.4rem; width: 40px; text-align: center; color: var(--text); opacity: 0.7; }
        .file-icon.folder { color: var(--folder); opacity: 1; }
        .file-info { flex: 1; min-width: 0; margin-right: 10px; }
        .file-name { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .file-meta { font-size: 0.8rem; opacity: 0.6; margin-top: 2px; }
        .file-actions { opacity: 0; transition: 0.2s; display: flex; gap: 5px; }
        .file-item:focus-within .file-actions, .file-item:hover .file-actions { opacity: 1; }
        
        .grid-view .file-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 10px; padding: 10px; }
        .grid-view .file-item { flex-direction: column; text-align: center; height: 160px; justify-content: center; border-radius: 8px; border: 1px solid var(--border); padding: 10px; position: relative; }
        .grid-view .file-check { position: absolute; top: 8px; left: 8px; z-index: 2; }
        .grid-view .file-icon { font-size: 3rem; margin-bottom: 10px; width: auto; }
        .grid-view .file-info { margin: 0; width: 100%; }
        .grid-view .file-actions { display: none; } 
        .grid-view .file-item img.preview { width: 100%; height: 80px; object-fit: cover; border-radius: 6px; margin-bottom: 5px; }

        .overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 2000; display: none; justify-content: center; align-items: center; backdrop-filter: blur(4px); }
        .modal { background: var(--card); padding: 25px; border-radius: 16px; width: 90%; max-width: 400px; max-height: 85vh; overflow-y: auto; position: relative; box-shadow: 0 10px 25px rgba(0,0,0,0.2); display: flex; flex-direction: column; }
        .modal.large { max-width: 900px; width: 95%; height: 80vh; }
        .context-menu { position: fixed; background: var(--card); border: 1px solid var(--border); border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); z-index: 1000; display: none; overflow: hidden; min-width: 150px; }
        .ctx-item { padding: 10px 15px; cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 0.9rem; }
        .ctx-item:hover { background: var(--hover); }
        .ctx-item.danger { color: var(--danger); }

        .editor-container { flex: 1; position: relative; overflow: hidden; border: 1px solid var(--border); border-radius: 8px; margin-top: 10px; display: flex; }
        .editor-area { width: 100%; height: 100%; padding: 15px; background: var(--bg); color: var(--text); font-family: 'Consolas', monospace; resize: none; border: none; box-sizing: border-box; line-height: 1.5; font-size: 14px; outline: none; }
        .markdown-body { overflow-y: auto; line-height: 1.6; }
        .markdown-body pre { background: #2d2d2d; color: #ccc; padding: 1em; border-radius: 5px; overflow-x: auto; }
        
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 10px; }
        .stat-card { background: var(--bg); padding: 15px; border-radius: 8px; border: 1px solid var(--border); text-align: center; }
        .stat-value { font-size: 1.5rem; font-weight: bold; color: var(--primary); margin: 5px 0; }
        .stat-label { font-size: 0.85rem; color: var(--text); opacity: 0.7; }

        #toast-container { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); z-index: 3000; display: flex; flex-direction: column; gap: 10px; }
        .toast { background: rgba(30, 41, 59, 0.9); backdrop-filter: blur(4px); color: white; padding: 12px 24px; border-radius: 30px; font-size: 0.9rem; animation: fadeUp 0.3s; opacity: 0.95; }
        @keyframes fadeUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 0.95; } }
        #drop-zone { position: fixed; inset: 0; background: rgba(79, 70, 229, 0.95); z-index: 9999; display: none; flex-direction: column; justify-content: center; align-items: center; color: white; font-size: 1.5rem; font-weight: bold; }
        .disk-bar { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin-top: 5px; }
        .disk-fill { height: 100%; background: var(--success); width: 0%; transition: width 0.5s; }

        @media (max-width: 600px) {
            .file-actions { opacity: 1; }
            .btn span { display: none; }
        }
    </style>
</head>
<body>
    <div id="drop-zone" aria-hidden="true"><i class="fa-solid fa-cloud-arrow-up" style="font-size:4rem; margin-bottom:20px;"></i>폴더나 파일을 여기에 놓으세요</div>
    <div id="toast-container" aria-live="polite"></div>
    
    <div id="ctxMenu" class="context-menu" aria-hidden="true">
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('download')"><i class="fa-solid fa-download"></i> 다운로드</div>
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('rename')"><i class="fa-solid fa-pen"></i> 이름 변경</div>
        {% if role == 'admin' %}
        <div class="ctx-item" id="ctxUnzip" role="button" tabindex="0" onclick="handleCtx('unzip')" style="display:none"><i class="fa-solid fa-box-open"></i> 압축 해제</div>
        {% endif %}
        <div class="ctx-item danger" role="button" tabindex="0" onclick="handleCtx('delete')"><i class="fa-solid fa-trash"></i> 삭제</div>
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
            <h3>업로드 중...</h3>
            <div style="background:var(--border); height:8px; border-radius:4px; overflow:hidden; margin:15px 0;">
                <div id="progressBar" style="width:0%; height:100%; background:var(--primary); transition:width 0.2s;" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
            </div>
            <div id="progressText">0%</div>
        </div>
    </div>

    <script>
        const currentPath = "{{ current_path }}";
        const canModify = {{ 'true' if can_modify else 'false' }};
        let selectedFiles = new Set();
        
        document.addEventListener('DOMContentLoaded', () => {
            fetchDiskInfo();
            document.addEventListener('keydown', (e) => {
                if(e.key === "Escape") {
                    document.querySelectorAll('.overlay').forEach(el => el.style.display = 'none');
                }
            });
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
            for(let i=0; i<files.length; i++) {
                const file = files[i];
                const path = file.webkitRelativePath || file.name;
                fd.append('file', file);
                fd.append('paths', path); 
            }
            
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/upload/' + currentPath);
            xhr.upload.onprogress = e => {
                if(e.lengthComputable) {
                    const p = Math.round((e.loaded/e.total)*100);
                    document.getElementById('progressBar').style.width = p+'%';
                    document.getElementById('progressBar').setAttribute('aria-valuenow', p);
                    document.getElementById('progressText').innerText = p+'%';
                }
            };
            xhr.onload = () => location.reload();
            xhr.onerror = () => { alert('업로드 실패'); location.reload(); };
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

        function showToast(msg) {
            const t = document.createElement('div'); t.className='toast'; t.innerText=msg; t.setAttribute('role', 'alert');
            document.getElementById('toast-container').appendChild(t);
            setTimeout(()=>t.remove(), 3000);
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
            if(action === 'delete') deleteItem(ctxTarget.path);
            if(action === 'unzip') {
                if(!confirm('압축 해제?')) return;
                fetch('/unzip/' + ctxTarget.path, {method:'POST'}).then(r=>r.json()).then(d=>{ if(d.success) location.reload(); else alert(d.error); });
            }
            if(action === 'rename') {
                const newName = prompt("새 이름:", ctxTarget.name);
                if(newName && newName !== ctxTarget.name) {
                    fetch('/rename/' + currentPath, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({old_name: ctxTarget.name, new_name: newName})})
                    .then(r=>r.json()).then(d=>{ if(d.success) location.reload(); else alert(d.error); });
                }
            }
        }
        function loadClipboard() { fetch('/clipboard').then(r=>r.json()).then(d => document.getElementById('clipText').value = d.content); }
        function saveClipboard() { fetch('/clipboard', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({content: document.getElementById('clipText').value})}).then(()=> { showToast('저장됨'); closeModal('clipModal'); }); }
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

@app.after_request
def after_request(response):
    if response.content_length:
        STATS['bytes_sent'] += response.content_length
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
        
        if pw == conf.get('admin_pw'):
            session['logged_in'] = True; session['role'] = 'admin'
            if ip in login_block: del login_block[ip]
            logger.add(f"관리자 로그인: {ip}")
            return redirect(url_for('index', path=path))
        elif pw == conf.get('guest_pw'):
            session['logged_in'] = True; session['role'] = 'guest'
            if ip in login_block: del login_block[ip]
            logger.add(f"게스트 로그인: {ip}")
            return redirect(url_for('index', path=path))
        else:
            if ip not in login_block: login_block[ip] = {'count': 0, 'block_until': None}
            login_block[ip]['count'] += 1
            if login_block[ip]['count'] >= 5:
                login_block[ip]['block_until'] = datetime.now() + timedelta(minutes=10)
                logger.add(f"로그인 차단됨: {ip}", "WARN")
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
    full_path = os.path.join(conf.get('folder'), path)
    try:
        if os.path.isfile(full_path): os.remove(full_path)
        else: shutil.rmtree(full_path)
        logger.add(f"삭제: {path}")
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

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
    try:
        with open(os.path.join(conf.get('folder'), path), 'r', encoding='utf-8', errors='ignore') as f:
            return jsonify({'content': f.read()})
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/save_content/<path:path>', methods=['POST'])
@login_required('admin')
def save_content(path):
    try:
        content = request.get_json().get('content', '')
        with open(os.path.join(conf.get('folder'), path), 'w', encoding='utf-8') as f:
            f.write(content)
        logger.add(f"파일수정: {path}")
        return jsonify({'success': True})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

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
    except: return jsonify({'error': 'Error'})

@app.route('/clipboard', methods=['GET', 'POST'])
def clipboard_handler():
    global clipboard_store
    if not session.get('logged_in'): return jsonify({'error':'Auth required'}), 401
    if request.method == 'POST':
        clipboard_store = request.get_json().get('content', '')
        return jsonify({'success': True})
    return jsonify({'content': clipboard_store})

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
                
                # [핵심 로직] HTTPS/Keep-Alive 연결이 있어도 즉시 종료시키기 위해
                # Listening 소켓을 먼저 강제로 닫습니다.
                # 이는 accept() 블로킹을 즉시 해제하여 serve_forever 루프를 깨뜨립니다.
                if hasattr(self.server, 'socket') and self.server.socket:
                    try:
                        self.server.socket.close()
                    except: pass
                
                # 그 다음 표준 shutdown 호출 (이미 소켓이 닫혀서 에러가 날 수도 있음)
                self.server.shutdown()
                self.server.server_close()
                
            except Exception as e:
                # 이미 닫혔거나 하는 경우 무시
                pass
            
            logger.add("서버가 중지되었습니다.")

server_thread = None

# ==========================================
# 6. Tkinter GUI (IP 감지 개선 등)
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
        
        self.status_cvs = tk.Canvas(frame, width=120, height=120, bg="#f8fafc", highlightthickness=0)
        self.status_cvs.pack(pady=20)
        self.status_ind = self.status_cvs.create_oval(10, 10, 110, 110, fill="#e2e8f0", outline="")
        self.status_lbl = ttk.Label(frame, text="서버 중지됨", font=("맑은 고딕", 16, "bold"), foreground="#64748b")
        self.status_lbl.pack()

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
        ttk.Checkbutton(frame, text="HTTPS 사용 (주의: 자체 서명 인증서 사용)", variable=self.var_https).pack(anchor='w', pady=5)
        
        ttk.Button(frame, text="사용 가이드", command=self.show_help).pack(anchor='e', pady=5)
        ttk.Button(frame, text="설정 저장", command=self.save_settings).pack(fill='x', pady=10)

    def build_logs(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.txt_log = scrolledtext.ScrolledText(frame, state='disabled', font=("Consolas", 9))
        self.txt_log.pack(fill='both', expand=True)
        ttk.Button(frame, text="로그 클리어", command=lambda: self.txt_log.configure(state='normal') or self.txt_log.delete(1.0, tk.END) or self.txt_log.configure(state='disabled')).pack(anchor='e', pady=5)

    def get_ip_list(self):
        # 향상된 IP 감지 로직
        ips = set()
        ips.add('0.0.0.0')
        ips.add('127.0.0.1')
        
        # 1. 외부 연결 시도로 정확한 내부 IP 확인
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            # Google DNS에 연결 시도 (패킷 전송 X)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith('127.'):
                ips.add(ip)
            s.close()
        except: pass
        
        # 2. 호스트네임 기반 확인
        try:
            host_name = socket.gethostname()
            for ip in socket.gethostbyname_ex(host_name)[2]:
                if ip and not ip.startswith("127."):
                    ips.add(ip)
        except: pass

        # 정렬하여 반환 (0.0.0.0을 맨 뒤로)
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

            if conf.get('use_https'):
                try:
                    import cryptography
                except ImportError:
                    if not messagebox.askyesno("경고", "HTTPS를 사용하려면 'cryptography' 라이브러리가 필요합니다.\n설치하지 않으면 서버가 시작되지 않을 수 있습니다.\n(pip install cryptography)\n\n계속하시겠습니까?"):
                        return

            server_thread = ServerThread(use_https=conf.get('use_https'))
            server_thread.start()
            self.update_ui_state(True)

    def _stop_server_task(self):
        global server_thread
        if server_thread:
            server_thread.shutdown()
            # 최대 2초 대기 후 강제 진행 (UI 프리징 방지)
            server_thread.join(timeout=2.0)
            server_thread = None
        
        if not self.is_closing:
            self.root.after(0, lambda: self.update_ui_state(False))

    def update_ui_state(self, running):
        if self.is_closing: return
        self.btn_toggle.config(state='normal')
        if running:
            self.btn_toggle.config(text="서버 중지", bg="#ef4444")
            self.status_cvs.itemconfig(self.status_ind, fill="#22c55e")
            self.status_lbl.config(text="서버 실행 중", foreground="#22c55e")
            
            # 실제 사용된 프로토콜 확인 (adhoc 실패 시 http일 수 있음)
            use_https_actual = conf.get('use_https')
            if server_thread and not server_thread.use_https:
                use_https_actual = False
                
            proto = "https" if use_https_actual else "http"
            url = f"{proto}://{conf.get('display_host')}:{conf.get('port')}"
            self.url_var.set(url)
            self.ent_folder.config(state='disabled')
            self.ent_port.config(state='disabled')
        else:
            self.btn_toggle.config(text="서버 시작", bg="#4f46e5")
            self.status_cvs.itemconfig(self.status_ind, fill="#e2e8f0")
            self.status_lbl.config(text="서버 중지됨", foreground="#64748b")
            self.url_var.set("-")
            self.ent_folder.config(state='normal')
            self.ent_port.config(state='normal')

    def open_browser(self):
        url = self.url_var.get()
        if url != "-": webbrowser.open(url)
    
    def show_help(self):
        messagebox.showinfo("사용 가이드", """[1] 서버 설정\n- 공유 폴더: 파일 저장 위치 선택\n- 보안: 비밀번호 설정\n\n[2] 서버 실행\n- '서버 시작' 버튼 클릭\n- HTTPS 사용 시 브라우저에서 '주의 요함'이 뜰 수 있음 (자체 서명)\n\n[3] 웹 접속\n- 브라우저 버튼: PC에서 열기\n- QR코드: 모바일 접속""")

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
        self.is_closing = True
        if server_thread and server_thread.is_alive():
            if messagebox.askokcancel("종료", "서버가 실행 중입니다. 종료하시겠습니까?"):
                threading.Thread(target=server_thread.shutdown, daemon=True).start()
                self.root.destroy()
                sys.exit(0)
            else:
                self.is_closing = False
        else:
            self.root.destroy()
            sys.exit(0)

if __name__ == '__main__':
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass

    root = tk.Tk()
    app_gui = WebShareGUI(root)
    root.mainloop()
