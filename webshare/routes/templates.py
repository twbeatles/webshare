"""
WebShare Pro - HTML Templates
백업 파일에서 완전 복구된 HTML 템플릿 (v7.2)

이 파일은 다음 템플릿들을 포함합니다:
- HTML_TEMPLATE: 로그인/브라우징 통합 템플릿
- SHARE_PASSWORD_TEMPLATE: 공유 링크 비밀번호 입력 폼
- SHARE_EXPIRED_TEMPLATE: 공유 링크 만료 메시지
"""

SHARE_PASSWORD_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>비밀번호 필요 - WebShare Pro</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 20px; box-shadow: 0 25px 50px rgba(0,0,0,0.2); text-align: center; max-width: 400px; width: 90%; }
        h2 { color: #1e293b; margin-bottom: 10px; }
        p { color: #64748b; margin-bottom: 25px; }
        input { width: 100%; padding: 15px; border: 2px solid #e2e8f0; border-radius: 12px; font-size: 1rem; margin-bottom: 15px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #6366f1; }
        button { width: 100%; padding: 15px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; border: none; border-radius: 12px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(99,102,241,0.4); }
        .error { color: #ef4444; font-size: 0.9rem; margin-bottom: 15px; }
        .icon { font-size: 4rem; color: #6366f1; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon"><i class="fa-solid fa-lock"></i></div>
        <h2>비밀번호 필요</h2>
        <p>이 파일에 접근하려면 비밀번호가 필요합니다.</p>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="password" name="password" placeholder="비밀번호를 입력하세요" required autofocus>
            <button type="submit"><i class="fa-solid fa-unlock"></i> 확인</button>
        </form>
    </div>
</body>
</html>
"""


SHARE_EXPIRED_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>접근 불가 - WebShare Pro</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 20px; box-shadow: 0 25px 50px rgba(0,0,0,0.2); text-align: center; max-width: 400px; width: 90%; }
        h2 { color: #1e293b; margin-bottom: 10px; }
        p { color: #64748b; }
        .icon { font-size: 4rem; color: #ef4444; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon"><i class="fa-solid fa-circle-xmark"></i></div>
        <h2>접근 불가</h2>
        <p>{{ message }}</p>
    </div>
</body>
</html>
"""


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="description" content="WebShare Pro - 파일 공유 및 관리 시스템">
    <title>WebShare Pro</title>
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/github-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>

    <style>
        :root {
            --primary: #6366f1; --primary-dark: #4f46e5; --primary-light: #a5b4fc;
            --bg: #f8fafc; --card: #ffffff; --text: #1e293b; 
            --text-secondary: #64748b; --border: #e2e8f0; --danger: #ef4444; --danger-light: #fecaca;
            --folder: #f59e0b; --hover: #f1f5f9;
            --success: #10b981; --success-dark: #059669; --success-light: #d1fae5;
            --warning: #f59e0b; --info: #3b82f6;
            --focus-ring: #818cf8;
            --gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-primary: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            --gradient-success: linear-gradient(135deg, #10b981 0%, #059669 100%);
            --gradient-danger: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            --gradient-subtle: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%);
            --input-bg: #ffffff;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
            --shadow-md: 0 4px 12px rgba(0,0,0,0.08);
            --shadow-lg: 0 12px 40px rgba(0,0,0,0.12);
            --shadow-xl: 0 25px 50px rgba(0,0,0,0.15);
            --glow-primary: 0 0 30px rgba(99, 102, 241, 0.35);
            --glow-success: 0 0 30px rgba(16, 185, 129, 0.35);
            --glow-danger: 0 0 30px rgba(239, 68, 68, 0.35);
            --transition-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
            --transition-normal: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            --transition-slow: 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            --glass-bg: rgba(255, 255, 255, 0.85);
            --glass-border: rgba(255, 255, 255, 0.2);
        }
        [data-theme="dark"] {
            --primary: #818cf8; --primary-dark: #6366f1; --primary-light: #c7d2fe;
            --bg: #0f172a; --card: #1e293b; --text: #f1f5f9;
            --text-secondary: #94a3b8; --border: #334155; --folder: #fbbf24; --hover: #334155;
            --danger-light: #7f1d1d; --success-light: #064e3b;
            --gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-primary: linear-gradient(135deg, #818cf8 0%, #a78bfa 100%);
            --gradient-subtle: linear-gradient(135deg, rgba(129, 140, 248, 0.15) 0%, rgba(167, 139, 250, 0.15) 100%);
            --input-bg: #1e293b;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.25);
            --shadow-md: 0 4px 12px rgba(0,0,0,0.35);
            --shadow-lg: 0 12px 40px rgba(0,0,0,0.45);
            --shadow-xl: 0 25px 50px rgba(0,0,0,0.5);
            --glow-primary: 0 0 35px rgba(129, 140, 248, 0.45);
            --glass-bg: rgba(30, 41, 59, 0.9);
            --glass-border: rgba(255, 255, 255, 0.08);
        }
        
        * { box-sizing: border-box; }
        
        body { 
            font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: var(--bg); 
            color: var(--text); 
            margin: 0; 
            transition: background var(--transition-slow), color var(--transition-normal); 
            padding-bottom: 80px; 
            -webkit-tap-highlight-color: transparent;
            line-height: 1.6;
            font-size: 15px;
        }
        
        /* Enhanced scrollbar for modern look */
        ::-webkit-scrollbar { width: 10px; height: 10px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { 
            background: var(--border); 
            border-radius: 10px; 
            border: 2px solid var(--bg);
        }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-secondary); }
        
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
            background: var(--glass-bg); 
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 20px; 
            box-shadow: var(--shadow-md); 
            border: 1px solid var(--glass-border); 
            overflow: hidden;
            transition: all var(--transition-normal);
        }
        .card:hover {
            box-shadow: var(--shadow-lg);
        }
        
        .toolbar { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
        .search-box { flex: 1; position: relative; min-width: 200px; }
        .search-box input { 
            width: 100%; 
            padding: 12px 12px 12px 44px; 
            border-radius: 14px; 
            border: 2px solid var(--border); 
            background: var(--input-bg); 
            color: var(--text); 
            box-sizing: border-box; 
            height: 48px;
            font-size: 0.95rem;
            transition: all var(--transition-fast);
        }
        .search-box input:focus { 
            border-color: var(--primary); 
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.12); 
            background: var(--card);
        }
        .search-box input::placeholder { color: var(--text-secondary); opacity: 0.7; }
        .search-box i { 
            position: absolute; 
            left: 16px; 
            top: 50%; 
            transform: translateY(-50%); 
            color: var(--text-secondary); 
            font-size: 1rem;
            transition: color var(--transition-fast);
        }
        .search-box:focus-within i { color: var(--primary); }
        
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
            background: var(--gradient-primary); 
            color: white; 
            border: none; 
            padding: 10px 20px; 
            border-radius: 12px; 
            cursor: pointer; 
            font-weight: 600; 
            text-decoration: none; 
            display: inline-flex; 
            align-items: center; 
            gap: 8px; 
            transition: all var(--transition-normal); 
            font-size: 0.9rem; 
            height: 44px; 
            box-sizing: border-box;
            position: relative;
            overflow: hidden;
        }
        .btn::before {
            content: '';
            position: absolute;
            top: 0; left: -100%;
            width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        .btn:hover::before { left: 100%; }
        .btn:hover { transform: translateY(-2px); box-shadow: var(--glow-primary); }
        .btn:active { transform: translateY(0); box-shadow: none; }
        .btn-outline { background: transparent; border: 1.5px solid var(--border); color: var(--text); }
        .btn-outline::before { display: none; }
        .btn-outline:hover { background: var(--hover); border-color: var(--primary); transform: translateY(-1px); box-shadow: none; }
        .btn-icon { width: 40px; height: 40px; padding: 0; justify-content: center; border-radius: 10px; }
        .btn-icon::before { display: none; }
        .btn-danger { background: var(--danger-light); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }
        .btn-danger::before { display: none; }
        .btn-danger:hover { background: var(--gradient-danger); color: white; box-shadow: 0 4px 15px rgba(239,68,68,0.4); }
        .btn-success { background: var(--gradient-success); color: white; }
        .btn-success:hover { box-shadow: var(--glow-success); }

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
            padding: 16px 20px; 
            border-bottom: 1px solid var(--border); 
            cursor: pointer; 
            transition: all var(--transition-fast); 
            user-select: none;
            position: relative;
            background: transparent;
        }
        .file-item::before {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--gradient-subtle);
            opacity: 0;
            transition: opacity var(--transition-fast);
            pointer-events: none;
        }
        .file-item:hover::before { opacity: 1; }
        .file-item::after {
            content: '';
            position: absolute;
            left: 0; bottom: 0;
            width: 0; height: 3px;
            background: var(--gradient-primary);
            transition: width var(--transition-normal);
            border-radius: 0 3px 0 0;
        }
        .file-item:hover::after { width: 100%; }
        .file-item:hover { transform: translateX(4px); }
        .file-item.selected { 
            background: rgba(99, 102, 241, 0.08); 
            border-left: 4px solid var(--primary); 
        }
        
        .file-check { 
            margin-right: 16px; 
            width: 20px;
            height: 20px;
            cursor: pointer; 
            accent-color: var(--primary);
            transition: transform var(--transition-fast);
        }
        .file-check:hover { transform: scale(1.2); }
        .file-icon { 
            font-size: 1.6rem; 
            width: 48px; 
            text-align: center; 
            color: var(--text-secondary); 
            transition: all var(--transition-normal); 
        }
        .file-item:hover .file-icon { transform: scale(1.15) rotate(3deg); color: var(--primary); }
        .file-icon.folder { color: var(--folder); }
        .file-item:hover .file-icon.folder { color: var(--warning); transform: scale(1.15); }
        .file-info { flex: 1; min-width: 0; margin-right: 12px; }
        .file-name { 
            font-weight: 600; 
            overflow: hidden; 
            text-overflow: ellipsis; 
            white-space: nowrap; 
            font-size: 0.95rem; 
            transition: color var(--transition-fast); 
        }
        .file-item:hover .file-name { color: var(--primary); }
        .file-meta { font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px; display: flex; gap: 12px; }
        .file-actions { opacity: 0; transition: all var(--transition-fast); display: flex; gap: 8px; }
        .file-item:focus-within .file-actions, .file-item:hover .file-actions { opacity: 1; transform: translateX(0); }
        
        .grid-view .file-list { 
            display: grid; 
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); 
            gap: 18px; 
            padding: 20px; 
        }
        .grid-view .file-item { 
            flex-direction: column; 
            text-align: center; 
            height: 190px; 
            justify-content: center; 
            border-radius: 18px; 
            border: 2px solid var(--border); 
            padding: 18px; 
            position: relative;
            transition: all var(--transition-normal);
            background: var(--card);
        }
        .grid-view .file-item::before { border-radius: 18px; }
        .grid-view .file-item::after { display: none; }
        .grid-view .file-item:hover { 
            transform: translateY(-8px) scale(1.02); 
            box-shadow: var(--shadow-lg), var(--glow-primary); 
            border-color: var(--primary);
        }
        .grid-view .file-check { position: absolute; top: 12px; left: 12px; z-index: 2; }
        .grid-view .file-icon { font-size: 3.5rem; margin-bottom: 14px; width: auto; }
        .grid-view .file-item:hover .file-icon { transform: scale(1.1); }
        .grid-view .file-info { margin: 0; width: 100%; }
        .grid-view .file-actions { display: none; } 
        .grid-view .file-item img.preview { 
            width: 100%; 
            height: 90px; 
            object-fit: cover; 
            border-radius: 12px; 
            margin-bottom: 10px; 
            transition: transform var(--transition-normal); 
        }
        .grid-view .file-item:hover img.preview { transform: scale(1.05); }

        .overlay { 
            position: fixed; 
            inset: 0; 
            background: rgba(0,0,0,0.6); 
            z-index: 2000; 
            display: none; 
            justify-content: center; 
            align-items: center; 
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            animation: fadeIn 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        
        .modal { 
            background: var(--glass-bg); 
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            padding: 32px; 
            border-radius: 28px; 
            width: 90%; 
            max-width: 440px; 
            max-height: 85vh; 
            overflow-y: auto; 
            position: relative; 
            box-shadow: var(--shadow-xl), 0 0 80px rgba(99, 102, 241, 0.2); 
            display: flex; 
            flex-direction: column;
            animation: modalSlide 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
            border: 1px solid var(--glass-border);
        }
        @keyframes modalSlide { 
            from { transform: translateY(-30px) scale(0.9); opacity: 0; } 
            to { transform: translateY(0) scale(1); opacity: 1; } 
        }
        .modal h3 {
            margin-top: 0;
            padding-bottom: 18px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.2rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .modal.large { max-width: 980px; width: 95%; height: 85vh; }
        
        .context-menu { 
            position: fixed; 
            background: var(--glass-bg); 
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--glass-border); 
            border-radius: 16px; 
            box-shadow: var(--shadow-lg); 
            z-index: 1000; 
            display: none; 
            overflow: hidden; 
            min-width: 200px;
            padding: 8px;
            animation: contextPop 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        @keyframes contextPop { from { transform: scale(0.9) translateY(-8px); opacity: 0; } to { transform: scale(1) translateY(0); opacity: 1; } }
        .ctx-item { 
            padding: 12px 16px; 
            cursor: pointer; 
            display: flex; 
            align-items: center; 
            gap: 12px; 
            font-size: 0.9rem; 
            border-radius: 10px;
            transition: all var(--transition-fast); 
        }
        .ctx-item:hover { background: var(--hover); transform: translateX(4px); }
        .ctx-item i { width: 18px; text-align: center; color: var(--text-secondary); }
        .ctx-item:hover i { color: var(--primary); }
        .ctx-item.danger { color: var(--danger); }
        .ctx-item.danger:hover { background: rgba(239, 68, 68, 0.1); }
        .ctx-item.danger i { color: var(--danger); }

        .editor-container { flex: 1; position: relative; overflow: hidden; border: 1px solid var(--border); border-radius: 12px; margin-top: 12px; display: flex; }
        .editor-area { width: 100%; height: 100%; padding: 18px; background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', 'Consolas', monospace; resize: none; border: none; box-sizing: border-box; line-height: 1.6; font-size: 14px; outline: none; }
        .markdown-body { overflow-y: auto; line-height: 1.7; padding: 18px; }
        .markdown-body pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
        
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 16px; }
        .stat-card { 
            background: var(--gradient-subtle); 
            padding: 22px; 
            border-radius: 16px; 
            border: 1px solid var(--glass-border); 
            text-align: center;
            transition: all var(--transition-normal);
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            inset: 0;
            background: var(--gradient-primary);
            opacity: 0;
            transition: opacity var(--transition-normal);
        }
        .stat-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-md); }
        .stat-card:hover::before { opacity: 0.05; }
        .stat-value { font-size: 1.8rem; font-weight: 700; background: var(--gradient); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin: 8px 0; position: relative; }
        .stat-label { font-size: 0.85rem; color: var(--text-secondary); font-weight: 500; position: relative; }

        #toast-container { position: fixed; bottom: 36px; left: 50%; transform: translateX(-50%); z-index: 3000; display: flex; flex-direction: column; gap: 14px; }
        .toast { 
            background: var(--glass-bg); 
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            color: var(--text); 
            padding: 16px 28px; 
            border-radius: 16px; 
            font-size: 0.95rem; 
            font-weight: 500;
            animation: toastSlide 0.35s cubic-bezier(0.34, 1.56, 0.64, 1); 
            display: flex; 
            align-items: center; 
            gap: 12px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--glass-border);
        }
        .toast.success { 
            background: linear-gradient(135deg, #10b981 0%, #059669 100%); 
            color: white;
            border: none;
        }
        .toast.error { 
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); 
            color: white;
            border: none;
        }
        .toast.warning { 
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); 
            color: white;
            border: none;
        }
        .toast.info { 
            background: var(--gradient); 
            color: white;
            border: none;
        }
        @keyframes toastSlide { from { transform: translateY(40px) scale(0.9); opacity: 0; } to { transform: translateY(0) scale(1); opacity: 1; } }
        
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
            font-size: 1.8rem; 
            font-weight: 600;
            animation: dropZonePulse 2s ease-in-out infinite;
        }
        @keyframes dropZonePulse {
            0%, 100% { opacity: 0.95; }
            50% { opacity: 1; }
        }
        #drop-zone i { font-size: 4rem; margin-bottom: 20px; animation: dropIconBounce 1s ease-in-out infinite; }
        @keyframes dropIconBounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        .disk-bar { height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; margin-top: 6px; }
        .disk-fill { height: 100%; background: linear-gradient(90deg, var(--success), #34d399); width: 0%; transition: width 0.6s ease-out; }

        @media (max-width: 600px) {
            .file-actions { opacity: 1; }
            .btn span { display: none; }
            .container { padding: 12px; }
            header { flex-direction: column; gap: 10px; align-items: stretch; }
            header h1 { font-size: 1.2rem; text-align: center; }
            header nav { justify-content: center; flex-wrap: wrap; }
            .toolbar { gap: 8px; }
            .search-box { min-width: 100%; }
            .btn { padding: 8px 12px; font-size: 0.85rem; height: 40px; }
            .btn-icon { width: 36px; height: 36px; }
            .modal { padding: 20px; width: 95%; }
            .file-item { padding: 12px 14px; }
            .grid-view .file-list { grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 10px; }
            .grid-view .file-item { height: 140px; }
            #toast-container { bottom: 70px; width: 90%; }
            .toast { padding: 12px 20px; font-size: 0.85rem; }
        }
        
        /* 로딩 상태 애니메이션 */
        .btn.loading { pointer-events: none; opacity: 0.7; }
        .btn.loading::after {
            content: '';
            width: 14px;
            height: 14px;
            border: 2px solid transparent;
            border-top-color: currentColor;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-left: 8px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        /* 빈 폴더 상태 개선 */
        .empty-state {
            padding: 60px 40px;
            text-align: center;
            color: var(--text-secondary);
        }
        .empty-state i { font-size: 4rem; opacity: 0.3; margin-bottom: 16px; }
        .empty-state p { margin: 8px 0; }
        .empty-state .subtitle { font-size: 0.85rem; opacity: 0.7; }
        
        /* 그리드 뷰 접근성 개선 - 호버 시 액션 표시 */
        .grid-view .file-item:hover .file-actions,
        .grid-view .file-item:focus-within .file-actions {
            display: flex;
            position: absolute;
            bottom: 8px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0,0,0,0.7);
            padding: 6px 10px;
            border-radius: 8px;
            gap: 8px;
        }
        
        /* v5: Breadcrumb 네비게이션 */
        .breadcrumb {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 10px 0;
            font-size: 0.9rem;
            flex-wrap: wrap;
        }
        .breadcrumb a {
            color: var(--primary);
            text-decoration: none;
            padding: 4px 8px;
            border-radius: 6px;
            transition: background 0.2s;
        }
        .breadcrumb a:hover {
            background: var(--hover);
        }
        .breadcrumb .separator {
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
        .breadcrumb .current {
            color: var(--text);
            font-weight: 500;
        }
        
        /* v5: 파일 목록 키보드 포커스 */
        .file-item.keyboard-focused {
            outline: 2px solid var(--primary);
            outline-offset: -2px;
        }
        
        /* v7.0: 툴팁 스타일 */
        [data-tooltip] {
            position: relative;
        }
        [data-tooltip]::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%) translateY(-4px);
            background: rgba(15, 23, 42, 0.95);
            color: white;
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 500;
            white-space: nowrap;
            opacity: 0;
            visibility: hidden;
            transition: all 0.2s ease;
            pointer-events: none;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        [data-tooltip]:hover::after,
        [data-tooltip]:focus::after {
            opacity: 1;
            visibility: visible;
            transform: translateX(-50%) translateY(-8px);
        }
        
        /* v7.0: 드롭다운 메뉴 */
        .dropdown {
            position: relative;
            display: inline-block;
        }
        .dropdown-menu {
            position: absolute;
            top: 100%;
            right: 0;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
            min-width: 200px;
            padding: 8px;
            opacity: 0;
            visibility: hidden;
            transform: translateY(-10px);
            transition: all 0.2s ease;
            z-index: 1000;
        }
        .dropdown.open .dropdown-menu {
            opacity: 1;
            visibility: visible;
            transform: translateY(4px);
        }
        .dropdown-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px;
            border-radius: 8px;
            cursor: pointer;
            color: var(--text);
            font-size: 0.9rem;
            transition: background 0.15s;
            text-decoration: none;
        }
        .dropdown-item:hover {
            background: var(--hover);
        }
        .dropdown-item i {
            width: 18px;
            text-align: center;
            color: var(--text-secondary);
        }
        .dropdown-divider {
            height: 1px;
            background: var(--border);
            margin: 6px 0;
        }
        
        /* v7.0: 헤더 버튼 그룹 */
        .header-actions {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .header-group {
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 4px;
            background: var(--bg);
            border-radius: 12px;
            border: 1px solid var(--border);
        }
        
        /* v7.0: 모바일 하단 액션바 */
        @media (max-width: 600px) {
            .mobile-bottom-bar {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                background: var(--card);
                border-top: 1px solid var(--border);
                padding: 8px 16px;
                display: flex;
                justify-content: space-around;
                gap: 8px;
                z-index: 100;
                box-shadow: 0 -4px 20px rgba(0,0,0,0.1);
            }
            .mobile-bottom-bar .btn {
                flex: 1;
                justify-content: center;
                min-height: 44px;
            }
            body { padding-bottom: 120px; }
            .dropdown-menu { 
                right: auto; 
                left: 50%; 
                transform: translateX(-50%) translateY(-10px); 
            }
            .dropdown.open .dropdown-menu {
                transform: translateX(-50%) translateY(4px);
            }
        }
        
        /* v7.0: 파일 타입 아이콘 색상 */
        .file-icon.image { color: #ec4899; }
        .file-icon.video { color: #8b5cf6; }
        .file-icon.audio { color: #06b6d4; }
        .file-icon.document { color: #3b82f6; }
        .file-icon.archive { color: #84cc16; }
        .file-icon.code { color: #f97316; }
        
        /* v7.0: 스켈레톤 로딩 */
        .skeleton {
            background: linear-gradient(90deg, var(--border) 25%, var(--hover) 50%, var(--border) 75%);
            background-size: 200% 100%;
            animation: skeleton-loading 1.5s infinite;
            border-radius: 8px;
        }
        @keyframes skeleton-loading {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }
        
        /* ==========================================
         * v7.2: 탭 바 스타일
         * ========================================== */
        #tabBar {
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 8px 12px;
            background: var(--hover);
            border-bottom: 1px solid var(--border);
            border-radius: 12px 12px 0 0;
            overflow-x: auto;
            scrollbar-width: thin;
        }
        .tab {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            font-size: 0.85rem;
            white-space: nowrap;
            transition: all var(--transition-fast);
        }
        .tab:hover { background: var(--hover); }
        .tab.active {
            background: var(--card);
            border-bottom-color: var(--card);
            font-weight: 600;
            color: var(--primary);
        }
        .tab-close {
            width: 18px;
            height: 18px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            cursor: pointer;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
            line-height: 1;
        }
        .tab-close:hover { background: var(--danger-light); color: var(--danger); }
        #newTabBtn {
            width: 28px;
            height: 28px;
            border: 1px dashed var(--border);
            background: transparent;
            color: var(--text-secondary);
            cursor: pointer;
            border-radius: 6px;
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        #newTabBtn:hover { background: var(--hover); color: var(--primary); }
        
        /* v7.2: 드래그 앤 드롭 스타일 */
        .file-item[draggable="true"] { cursor: grab; }
        .file-item[draggable="true"]:active { cursor: grabbing; }
        .file-item.dragging {
            opacity: 0.5;
            transform: scale(0.95);
            border: 2px dashed var(--primary);
        }
        .file-item.drop-target {
            background: rgba(99, 102, 241, 0.15) !important;
            border: 2px dashed var(--primary) !important;
            border-radius: 12px;
        }
        .file-item.drop-target .file-icon { color: var(--primary); transform: scale(1.1); }
        
        /* v7.2: 단축키 도움말 모달 */
        .shortcuts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 16px;
        }
        .shortcut-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: var(--hover);
            border-radius: 8px;
        }
        .shortcut-key {
            background: var(--card);
            border: 1px solid var(--border);
            padding: 4px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8rem;
            font-weight: 600;
            min-width: 50px;
            text-align: center;
        }
        .shortcut-desc { font-size: 0.85rem; color: var(--text-secondary); }
        
        /* v7.2: PDF 뷰어 */
        #pdfViewer {
            max-height: 70vh;
            overflow-y: auto;
            background: var(--hover);
            border-radius: 8px;
            padding: 16px;
        }
        #pdfViewer canvas {
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            border-radius: 4px;
        }
        
        /* v7.2: 관리자 모달 스타일 */
        .admin-section {
            margin-bottom: 24px;
            padding: 16px;
            background: var(--hover);
            border-radius: 12px;
        }
        .admin-section h4 {
            margin: 0 0 12px 0;
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--primary);
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
        <!-- v7.0: 새로운 메뉴 항목 -->
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('tag')"><i class="fa-solid fa-tag"></i> 태그 추가</div>
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('memo')"><i class="fa-solid fa-note-sticky"></i> 메모</div>
        <div class="ctx-item" id="ctxFavorite" role="button" tabindex="0" onclick="handleCtx('favorite')" style="display:none"><i class="fa-solid fa-folder-heart"></i> 즐겨찾기</div>
        {% if role == 'admin' %}
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('share')"><i class="fa-solid fa-link"></i> 공유 링크</div>
        <div class="ctx-item" id="ctxUnzip" role="button" tabindex="0" onclick="handleCtx('unzip')" style="display:none"><i class="fa-solid fa-box-open"></i> 압축 해제</div>
        <div class="ctx-item" id="ctxEncrypt" role="button" tabindex="0" onclick="handleCtx('encrypt')"><i class="fa-solid fa-lock"></i> 암호화</div>
        <div class="ctx-item" id="ctxDecrypt" role="button" tabindex="0" onclick="handleCtx('decrypt')" style="display:none"><i class="fa-solid fa-unlock"></i> 복호화</div>
        <div class="ctx-item" role="button" tabindex="0" onclick="handleCtx('trash')"><i class="fa-solid fa-trash-can"></i> 휴지통으로</div>
        {% endif %}
        <div class="ctx-item danger" role="button" tabindex="0" onclick="handleCtx('delete')"><i class="fa-solid fa-trash"></i> 영구 삭제</div>
    </div>

    <div class="container">
        {% if not logged_in %}
            <div style="height:80vh; display:flex; justify-content:center; align-items:center;">
                <form method="post" class="card login-card" style="
                    padding: 44px; 
                    width: 100%; 
                    max-width: 360px; 
                    text-align: center; 
                    animation: modalSlide 0.5s ease-out;
                    background: var(--card);
                    backdrop-filter: blur(20px);
                    -webkit-backdrop-filter: blur(20px);
                    border: 1px solid var(--border);
                    position: relative;
                    overflow: hidden;
                ">
                    <!-- Animated gradient border -->
                    <div style="
                        position: absolute;
                        top: -2px; left: -2px; right: -2px; bottom: -2px;
                        background: var(--gradient);
                        border-radius: 18px;
                        z-index: -1;
                        opacity: 0.5;
                        animation: pulse 3s ease-in-out infinite;
                    "></div>
                    <style>
                        @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 0.6; } }
                        @keyframes iconFloat { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
                    </style>
                    
                    <div class="login-icon" style="
                        width: 80px; 
                        height: 80px; 
                        background: var(--gradient-primary); 
                        border-radius: 50%; 
                        display: flex; 
                        align-items: center; 
                        justify-content: center; 
                        margin: 0 auto 24px;
                        box-shadow: var(--glow-primary);
                        animation: iconFloat 3s ease-in-out infinite;
                    ">
                        <i class="fa-solid fa-share-nodes" style="font-size: 2rem; color: white;"></i>
                    </div>
                    <h1 style="color: var(--text); margin-top: 0; font-size: 1.6rem; margin-bottom: 8px; font-weight: 700;">WebShare Pro</h1>
                    <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 28px;">안전한 파일 공유 시스템</p>
                    <label for="password" class="sr-only" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);">비밀번호</label>
                    <div class="input-group" style="position: relative; margin-bottom: 20px;">
                        <i class="fa-solid fa-lock" style="position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: var(--text-secondary); transition: color 0.2s;"></i>
                        <input type="password" id="password" name="password" placeholder="비밀번호 입력" required 
                               style="
                                   width: 100%; 
                                   padding: 16px 48px 16px 48px; 
                                   border-radius: 14px; 
                                   border: 2px solid var(--border); 
                                   background: var(--input-bg); 
                                   color: var(--text); 
                                   font-size: 1rem; 
                                   transition: all 0.25s;
                                   box-sizing: border-box;
                               "
                               onfocus="this.style.borderColor='var(--primary)'; this.style.boxShadow='0 0 0 4px rgba(99,102,241,0.1)'; this.previousElementSibling.style.color='var(--primary)';"
                               onblur="this.style.borderColor='var(--border)'; this.style.boxShadow='none'; this.previousElementSibling.style.color='var(--text-secondary)';">
                        <button type="button" onclick="togglePasswordVisibility()" class="pw-toggle" style="position: absolute; right: 14px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; color: var(--text-secondary); padding: 6px; transition: color 0.2s;" aria-label="비밀번호 표시">
                            <i id="pwToggleIcon" class="fa-solid fa-eye"></i>
                        </button>
                    </div>
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <button type="submit" class="btn" style="width: 100%; justify-content: center; padding: 16px; font-size: 1.05rem; font-weight: 600;">
                        <i class="fa-solid fa-arrow-right-to-bracket"></i> 접속하기
                    </button>
                    {% if error %}<p style="color: var(--danger); font-size: 0.9rem; margin-top: 16px; background: var(--danger-light); padding: 12px; border-radius: 10px; border: 1px solid rgba(239,68,68,0.2);" role="alert"><i class="fa-solid fa-exclamation-circle"></i> {{ error }}</p>{% endif %}
                </form>
            </div>
        {% else %}
            <header>
                <h1 style="margin:0; color:var(--primary); cursor:pointer; font-size:1.5rem" onclick="location.href='/'" tabindex="0" role="link"><i class="fa-solid fa-folder-tree"></i> WebShare</h1>
                <nav class="header-actions" aria-label="메인 메뉴">
                    <!-- 역할 배지 -->
                    <span style="background:rgba(79,70,229,0.1); color:var(--primary); padding:6px 12px; border-radius:20px; font-size:0.8rem; font-weight:bold;">
                        {{ '👑 관리자' if role == 'admin' else '👤 게스트' }}
                    </span>
                    
                    <!-- v7.0: 빠른 접근 그룹 -->
                    <div class="header-group">
                        <button class="btn btn-outline btn-icon" onclick="openModal('recentModal'); loadRecentFiles()" data-tooltip="최근 파일"><i class="fa-solid fa-clock-rotate-left"></i></button>
                        <button class="btn btn-outline btn-icon" onclick="openModal('bookmarkModal'); loadBookmarks()" data-tooltip="북마크"><i class="fa-solid fa-star"></i></button>
                        <button class="btn btn-outline btn-icon" onclick="openModal('clipModal'); loadClipboard()" data-tooltip="클립보드"><i class="fa-regular fa-clipboard"></i></button>
                    </div>
                    
                    {% if role == 'admin' %}
                    <!-- v7.0: 관리 드롭다운 -->
                    <div class="dropdown" id="adminDropdown">
                        <button class="btn btn-outline btn-icon" onclick="toggleDropdown('adminDropdown')" data-tooltip="관리 메뉴"><i class="fa-solid fa-gear"></i></button>
                        <div class="dropdown-menu">
                            <div class="dropdown-item" onclick="openModal('trashModal'); loadTrash(); closeDropdowns()">
                                <i class="fa-solid fa-trash-can"></i> 휴지통
                            </div>
                            <div class="dropdown-item" onclick="openModal('shareListModal'); loadShareLinks(); closeDropdowns()">
                                <i class="fa-solid fa-link"></i> 공유 링크
                            </div>
                            <div class="dropdown-item" onclick="openModal('sessionsModal'); loadActiveSessions(); closeDropdowns()">
                                <i class="fa-solid fa-users"></i> 접속자 현황
                            </div>
                            <div class="dropdown-item" onclick="openUserManagement(); closeDropdowns()">
                                <i class="fa-solid fa-users-gear"></i> 사용자 관리
                            </div>
                            <div class="dropdown-divider"></div>
                            <div class="dropdown-item" onclick="openModal('accessDashboardModal'); loadAccessDashboard(); closeDropdowns()">
                                <i class="fa-solid fa-chart-bar"></i> 접속 대시보드
                            </div>
                        </div>
                    </div>
                    {% endif %}
                    
                    <!-- v7.0: 설정 그룹 -->
                    <div class="header-group">
                        <button class="btn btn-outline btn-icon" onclick="openModal('statsModal'); fetchStats()" data-tooltip="서버 상태"><i class="fa-solid fa-chart-line"></i></button>
                        <button class="btn btn-outline btn-icon" onclick="toggleLanguage()" data-tooltip="한/영 전환"><i class="fa-solid fa-globe"></i></button>
                        <button class="btn btn-outline btn-icon" onclick="toggleTheme()" data-tooltip="테마 변경"><i class="fa-solid fa-moon"></i></button>
                        <button class="btn btn-outline btn-icon" onclick="openModal('helpModal')" data-tooltip="도움말"><i class="fa-solid fa-circle-question"></i></button>
                    </div>
                    
                    <!-- 로그아웃 -->
                    <a href="/logout" class="btn btn-danger btn-icon" data-tooltip="로그아웃" style="display:flex;align-items:center;text-decoration:none"><i class="fa-solid fa-power-off"></i></a>
                </nav>
            </header>

            <!-- v5: Breadcrumb 네비게이션 -->
            {% if current_path %}
            <nav class="breadcrumb" aria-label="폴더 경로">
                <a href="/"><i class="fa-solid fa-home"></i></a>
                <span class="separator">/</span>
                {% set path_parts = current_path.split('/') %}
                {% for i in range(path_parts | length) %}
                    {% if i < path_parts | length - 1 %}
                        <a href="/browse/{{ path_parts[:i+1] | join('/') }}">{{ path_parts[i] }}</a>
                        <span class="separator">/</span>
                    {% else %}
                        <span class="current">{{ path_parts[i] }}</span>
                    {% endif %}
                {% endfor %}
            </nav>
            {% endif %}

            <div class="toolbar" role="toolbar" aria-label="파일 도구">
                <div class="search-box">
                    <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
                    <label for="searchInput" class="sr-only" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);">검색</label>
                    <input type="text" id="searchInput" placeholder="파일 검색..." onkeyup="filterFiles()" aria-label="파일 검색" autocomplete="off">
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

            <!-- v7.2: 탭 바 -->
            <div id="tabBar"></div>
            
            <script>const CURRENT_PATH = '{{ current_path or "" }}';</script>
            
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
                        data-is-dir="{{ 'true' if item.is_dir else 'false' }}"
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
                    {% if not items %}
                    <div class="empty-state">
                        <i class="fa-solid fa-folder-open"></i>
                        <p>폴더가 비어있습니다</p>
                        <p class="subtitle">파일을 드래그하거나 업로드 버튼을 클릭하세요</p>
                    </div>
                    {% endif %}
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
    
    <!-- v5.1: 최근 파일 모달 -->
    <div id="recentModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:500px;">
            <h3><i class="fa-solid fa-clock-rotate-left"></i> 최근 파일</h3>
            <div id="recentList" style="max-height:400px; overflow-y:auto;"></div>
            <div style="text-align:right; margin-top:15px">
                <button class="btn" onclick="closeModal('recentModal')">닫기</button>
            </div>
        </div>
    </div>
    
    <!-- v5.1: 접속자 모니터링 모달 -->
    <div id="sessionsModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:550px;">
            <h3><i class="fa-solid fa-users"></i> 접속자 현황 <span id="sessionCount" style="font-size:0.8rem; opacity:0.7;"></span></h3>
            <div id="sessionsList" style="max-height:300px; overflow-y:auto;"></div>
            <div style="text-align:right; margin-top:15px">
                <button class="btn btn-outline" onclick="loadActiveSessions()">새로고침</button>
                <button class="btn" onclick="closeModal('sessionsModal')">닫기</button>
            </div>
        </div>
    </div>

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
        <div class="modal" style="max-width:500px;">
            <h3 style="margin-top:0;"><i class="fa-solid fa-book"></i> 사용 가이드</h3>
            <div style="line-height:1.7; color:var(--text)">
                <p><b>📁 파일/폴더 업로드</b><br>- 드래그 앤 드롭으로 <b>폴더째 업로드</b> 가능<br>- '업로드' 버튼으로 파일 여러 개 선택</p>
                <p><b>👁️ 미리보기 지원</b><br>- 이미지, 동영상, 오디오, <b>PDF</b>, 텍스트/코드</p>
                <p><b>✏️ 코드 뷰어</b><br>- 구문 강조 및 Markdown 미리보기</p>
                
                <hr style="border:none; border-top:1px solid var(--border); margin:16px 0;">
                
                <p style="margin-bottom:8px;"><b>⌨️ 키보드 단축키</b></p>
                <div style="display:grid; grid-template-columns:auto 1fr; gap:6px 16px; font-size:0.9rem;">
                    <kbd style="background:var(--hover); padding:4px 8px; border-radius:4px; border:1px solid var(--border);">Ctrl+U</kbd>
                    <span>파일 업로드</span>
                    <kbd style="background:var(--hover); padding:4px 8px; border-radius:4px; border:1px solid var(--border);">Ctrl+N</kbd>
                    <span>새 폴더 생성</span>
                    <kbd style="background:var(--hover); padding:4px 8px; border-radius:4px; border:1px solid var(--border);">Ctrl+A</kbd>
                    <span>전체 선택</span>
                    <kbd style="background:var(--hover); padding:4px 8px; border-radius:4px; border:1px solid var(--border);">Delete</kbd>
                    <span>선택 항목 삭제</span>
                    <kbd style="background:var(--hover); padding:4px 8px; border-radius:4px; border:1px solid var(--border);">F2</kbd>
                    <span>이름 변경</span>
                    <kbd style="background:var(--hover); padding:4px 8px; border-radius:4px; border:1px solid var(--border);">Escape</kbd>
                    <span>모달 닫기</span>
                </div>
            </div>
            <div style="text-align:right; margin-top:20px"><button class="btn" onclick="closeModal('helpModal')">닫기</button></div>
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

    <!-- v6.0: 비디오 플레이어 모달 -->
    <div id="videoPlayerModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal large" style="padding:0; background:#000;">
            <div style="position:relative; width:100%; height:100%;">
                <button onclick="closeModal('videoPlayerModal')" style="position:absolute; top:15px; right:15px; z-index:10; background:rgba(0,0,0,0.5); border:none; color:white; width:40px; height:40px; border-radius:50%; cursor:pointer; font-size:1.2rem;">
                    <i class="fa-solid fa-times"></i>
                </button>
                <video id="videoPlayer" controls style="width:100%; height:100%; object-fit:contain;">
                    Your browser does not support video playback.
                </video>
            </div>
        </div>
    </div>

    <!-- v6.0: 오디오 플레이어 모달 -->
    <div id="audioPlayerModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:500px;">
            <h3><i class="fa-solid fa-music"></i> 오디오 플레이어</h3>
            <div id="audioNowPlaying" style="text-align:center; margin:15px 0; font-weight:600; color:var(--primary);"></div>
            <audio id="audioPlayer" controls style="width:100%; margin-bottom:15px;"></audio>
            <div id="audioPlaylist" style="max-height:250px; overflow-y:auto; border:1px solid var(--border); border-radius:10px;"></div>
            <div style="margin-top:15px; display:flex; gap:8px; justify-content:center;">
                <button class="btn btn-outline btn-icon" onclick="audioPlayPrev()"><i class="fa-solid fa-backward-step"></i></button>
                <button class="btn btn-outline btn-icon" onclick="audioPlayNext()"><i class="fa-solid fa-forward-step"></i></button>
                <button class="btn" onclick="closeModal('audioPlayerModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v6.0: 이미지 갤러리 모달 -->
    <div id="galleryModal" class="overlay" role="dialog" aria-modal="true" style="background:rgba(0,0,0,0.95);">
        <div style="position:relative; width:100%; height:100%; display:flex; align-items:center; justify-content:center;">
            <button onclick="closeModal('galleryModal')" style="position:absolute; top:20px; right:20px; z-index:10; background:rgba(255,255,255,0.1); border:none; color:white; width:50px; height:50px; border-radius:50%; cursor:pointer; font-size:1.5rem;">
                <i class="fa-solid fa-times"></i>
            </button>
            <button onclick="galleryPrev()" style="position:absolute; left:20px; top:50%; transform:translateY(-50%); background:rgba(255,255,255,0.1); border:none; color:white; width:60px; height:60px; border-radius:50%; cursor:pointer; font-size:1.5rem;">
                <i class="fa-solid fa-chevron-left"></i>
            </button>
            <img id="galleryImage" src="" style="max-width:90%; max-height:90%; object-fit:contain; border-radius:8px;">
            <button onclick="galleryNext()" style="position:absolute; right:20px; top:50%; transform:translateY(-50%); background:rgba(255,255,255,0.1); border:none; color:white; width:60px; height:60px; border-radius:50%; cursor:pointer; font-size:1.5rem;">
                <i class="fa-solid fa-chevron-right"></i>
            </button>
            <div id="galleryInfo" style="position:absolute; bottom:30px; color:white; text-align:center; font-size:0.9rem; opacity:0.8;"></div>
        </div>
    </div>

    <!-- v6.0: 사용자 관리 모달 -->
    {% if role == 'admin' %}
    <div id="userManageModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:600px;">
            <h3><i class="fa-solid fa-users-gear"></i> 사용자 관리</h3>
            <div style="margin-bottom:15px;">
                <button class="btn" onclick="showAddUserForm()"><i class="fa-solid fa-user-plus"></i> 새 사용자</button>
            </div>
            <div id="userFormArea" style="display:none; background:var(--hover); padding:15px; border-radius:10px; margin-bottom:15px;">
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                    <input type="text" id="newUsername" placeholder="사용자명" style="padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--card); color:var(--text);">
                    <input type="password" id="newPassword" placeholder="비밀번호" style="padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--card); color:var(--text);">
                    <select id="newRole" style="padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--card); color:var(--text);">
                        <option value="user">일반 사용자</option>
                        <option value="admin">관리자</option>
                    </select>
                    <input type="number" id="newQuota" placeholder="용량 제한 (MB)" value="1024" style="padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--card); color:var(--text);">
                </div>
                <div style="margin-top:10px; display:flex; gap:8px; justify-content:flex-end;">
                    <button class="btn btn-outline" onclick="hideAddUserForm()">취소</button>
                    <button class="btn" onclick="createUser()">생성</button>
                </div>
            </div>
            <div id="userList" style="max-height:300px; overflow-y:auto;"></div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('userManageModal')">닫기</button>
            </div>
        </div>
    </div>
    {% endif %}

    <!-- v7.0: 태그 추가 모달 -->
    <div id="tagModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:400px;">
            <h3><i class="fa-solid fa-tag"></i> 태그 추가</h3>
            <p id="tagTargetPath" style="font-size:0.85rem; opacity:0.7; margin-bottom:15px;"></p>
            <div style="display:flex; gap:10px; margin-bottom:15px;">
                <input type="text" id="tagInput" placeholder="태그 이름" style="flex:1; padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--text);">
                <input type="color" id="tagColor" value="#6366f1" style="width:50px; height:40px; border:none; border-radius:8px; cursor:pointer;">
            </div>
            <div id="existingTags" style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:15px;"></div>
            <div style="display:flex; gap:8px; justify-content:flex-end;">
                <button class="btn btn-outline" onclick="closeModal('tagModal')">취소</button>
                <button class="btn" onclick="addTag()">추가</button>
            </div>
        </div>
    </div>

    <!-- v7.0: 메모 모달 -->
    <div id="memoModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:500px;">
            <h3><i class="fa-solid fa-note-sticky"></i> 파일 메모</h3>
            <p id="memoTargetPath" style="font-size:0.85rem; opacity:0.7; margin-bottom:10px;"></p>
            <textarea id="memoText" placeholder="메모를 입력하세요..." style="width:100%; height:150px; padding:12px; border:1px solid var(--border); border-radius:10px; background:var(--bg); color:var(--text); resize:none; font-family:inherit;"></textarea>
            <p id="memoUpdated" style="font-size:0.75rem; opacity:0.5; margin-top:5px;"></p>
            <div style="margin-top:15px; display:flex; gap:8px; justify-content:flex-end;">
                <button class="btn btn-danger" onclick="deleteMemo()">삭제</button>
                <button class="btn btn-outline" onclick="closeModal('memoModal')">취소</button>
                <button class="btn" onclick="saveMemo()">저장</button>
            </div>
        </div>
    </div>

    <!-- v7.0: 암호화 모달 -->
    <div id="encryptModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:400px;">
            <h3><i class="fa-solid fa-lock"></i> 파일 암호화</h3>
            <p id="encryptTargetPath" style="font-size:0.85rem; opacity:0.7; margin-bottom:15px;"></p>
            <div style="margin-bottom:15px;">
                <label style="font-size:0.85rem; display:block; margin-bottom:5px;">암호화 비밀번호:</label>
                <input type="password" id="encryptPassword" placeholder="비밀번호 (기본: 관리자 암호)" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--text); box-sizing:border-box;">
            </div>
            <p style="font-size:0.8rem; opacity:0.6; background:var(--hover); padding:10px; border-radius:8px;">
                <i class="fa-solid fa-info-circle"></i> 비밀번호를 잊으면 파일을 복구할 수 없습니다.
            </p>
            <div style="margin-top:15px; display:flex; gap:8px; justify-content:flex-end;">
                <button class="btn btn-outline" onclick="closeModal('encryptModal')">취소</button>
                <button class="btn" onclick="encryptFile()">암호화</button>
            </div>
        </div>
    </div>

    <!-- v7.0: 복호화 모달 -->
    <div id="decryptModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:400px;">
            <h3><i class="fa-solid fa-unlock"></i> 파일 복호화</h3>
            <p id="decryptTargetPath" style="font-size:0.85rem; opacity:0.7; margin-bottom:15px;"></p>
            <div style="margin-bottom:15px;">
                <label style="font-size:0.85rem; display:block; margin-bottom:5px;">복호화 비밀번호:</label>
                <input type="password" id="decryptPassword" placeholder="암호화 시 사용한 비밀번호" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--bg); color:var(--text); box-sizing:border-box;">
            </div>
            <div style="margin-top:15px; display:flex; gap:8px; justify-content:flex-end;">
                <button class="btn btn-outline" onclick="closeModal('decryptModal')">취소</button>
                <button class="btn" onclick="decryptFile()">복호화</button>
            </div>
        </div>
    </div>

    <!-- v7.0: 즐겨찾기 모달 -->
    <div id="favoritesModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:500px;">
            <h3><i class="fa-solid fa-folder-heart"></i> 즐겨찾기 폴더</h3>
            <div id="favoritesList" style="max-height:350px; overflow-y:auto;"></div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('favoritesModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v7.0: 접속 로그 대시보드 모달 -->
    <div id="accessDashboardModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal large" style="max-width:800px;">
            <h3><i class="fa-solid fa-chart-line"></i> 접속 대시보드</h3>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px;">
                <div style="background:var(--bg); padding:15px; border-radius:12px; border:1px solid var(--border);">
                    <h4 style="margin:0 0 10px 0; font-size:0.9rem; opacity:0.7;">활동별 통계</h4>
                    <div id="actionStats"></div>
                </div>
                <div style="background:var(--bg); padding:15px; border-radius:12px; border:1px solid var(--border);">
                    <h4 style="margin:0 0 10px 0; font-size:0.9rem; opacity:0.7;">차단된 IP</h4>
                    <div id="blockedIpsList"></div>
                </div>
            </div>
            <div style="background:var(--bg); padding:15px; border-radius:12px; border:1px solid var(--border);">
                <h4 style="margin:0 0 10px 0; font-size:0.9rem; opacity:0.7;">최근 접속 기록</h4>
                <div id="recentLogs" style="max-height:200px; overflow-y:auto;"></div>
            </div>
            <div style="margin-top:15px; display:flex; gap:8px; justify-content:flex-end;">
                <button class="btn btn-outline" onclick="loadAccessDashboard()">새로고침</button>
                <button class="btn" onclick="closeModal('accessDashboardModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v7.0: 문서 미리보기 모달 -->
    <div id="docPreviewModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal large" style="max-width:900px; max-height:90vh;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                <h3 id="docPreviewTitle" style="margin:0;"><i class="fa-solid fa-file-alt"></i> 문서 미리보기</h3>
                <button class="btn btn-outline" onclick="closeModal('docPreviewModal')" style="font-size:1.2rem; padding:5px 12px;">&times;</button>
            </div>
            <div id="docPreviewContent" style="max-height:calc(90vh - 150px); overflow-y:auto; background:var(--bg); padding:20px; border-radius:12px; border:1px solid var(--border);"></div>
            <div style="margin-top:15px; display:flex; gap:8px; justify-content:flex-end;">
                <button class="btn btn-outline" onclick="downloadCurrentDoc()"><i class="fa-solid fa-download"></i> 다운로드</button>
                <button class="btn" onclick="closeModal('docPreviewModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v7.2: 키보드 단축키 모달 -->
    <div id="shortcutsModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:550px;">
            <h3><i class="fa-solid fa-keyboard"></i> 키보드 단축키</h3>
            <div class="shortcuts-grid">
                <div class="shortcut-item"><span class="shortcut-key">↑/↓</span><span class="shortcut-desc">파일 선택</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Enter</span><span class="shortcut-desc">열기/다운로드</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Delete</span><span class="shortcut-desc">삭제</span></div>
                <div class="shortcut-item"><span class="shortcut-key">F2</span><span class="shortcut-desc">이름 변경</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+A</span><span class="shortcut-desc">전체 선택</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+C</span><span class="shortcut-desc">복사</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+X</span><span class="shortcut-desc">잘라내기</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+V</span><span class="shortcut-desc">붙여넣기</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+N</span><span class="shortcut-desc">새 폴더</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+U</span><span class="shortcut-desc">업로드</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+F</span><span class="shortcut-desc">검색</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Ctrl+T</span><span class="shortcut-desc">새 탭</span></div>
                <div class="shortcut-item"><span class="shortcut-key">G</span><span class="shortcut-desc">뷰 전환</span></div>
                <div class="shortcut-item"><span class="shortcut-key">D</span><span class="shortcut-desc">다크모드</span></div>
                <div class="shortcut-item"><span class="shortcut-key">?</span><span class="shortcut-desc">단축키 도움말</span></div>
                <div class="shortcut-item"><span class="shortcut-key">Esc</span><span class="shortcut-desc">닫기/취소</span></div>
            </div>
            <div style="margin-top:20px; text-align:right;">
                <button class="btn" onclick="closeModal('shortcutsModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v7.2: PDF 미리보기 모달 -->
    <div id="pdfPreviewModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal large" style="max-width:900px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                <h3 style="margin:0;"><i class="fa-solid fa-file-pdf"></i> PDF 미리보기</h3>
                <button class="btn btn-outline" onclick="closeModal('pdfPreviewModal')" style="font-size:1.2rem; padding:5px 12px;">&times;</button>
            </div>
            <div id="pdfViewer"></div>
        </div>
    </div>

    <!-- v7.2: 감사 로그 모달 -->
    <div id="auditLogModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal large" style="max-width:800px;">
            <h3><i class="fa-solid fa-clipboard-list"></i> 감사 로그</h3>
            <div style="display:flex; gap:8px; margin-bottom:15px;">
                <button class="btn btn-outline" onclick="loadAuditLog()"><i class="fa-solid fa-refresh"></i> 새로고침</button>
                <a href="/api/audit_log/export" class="btn btn-outline" style="text-decoration:none;"><i class="fa-solid fa-download"></i> CSV 내보내기</a>
            </div>
            <div id="auditLogList" style="max-height:400px; overflow-y:auto; border:1px solid var(--border); border-radius:8px;"></div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('auditLogModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v7.2: 중복 파일 검사 모달 -->
    <div id="duplicatesModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal large" style="max-width:700px;">
            <h3><i class="fa-solid fa-clone"></i> 중복 파일 검사</h3>
            <div style="display:flex; gap:8px; align-items:center; margin-bottom:15px;">
                <button class="btn" onclick="startDuplicateScan()"><i class="fa-solid fa-magnifying-glass"></i> 스캔 시작</button>
                <span id="duplicateProgress" style="opacity:0.7;"></span>
            </div>
            <div id="duplicatesList" style="max-height:400px; overflow-y:auto;"></div>
            <div style="margin-top:15px; display:flex; gap:8px; justify-content:flex-end;">
                <button class="btn btn-danger" onclick="deleteSelectedDuplicates()"><i class="fa-solid fa-trash"></i> 선택 삭제</button>
                <button class="btn" onclick="closeModal('duplicatesModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v7.2: 폴더 권한 모달 -->
    <div id="permissionsModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:600px;">
            <h3><i class="fa-solid fa-shield-halved"></i> 폴더 권한 관리</h3>
            <div style="display:flex; gap:8px; margin-bottom:15px;">
                <button class="btn" onclick="addPermission()"><i class="fa-solid fa-plus"></i> 권한 추가</button>
                <button class="btn btn-outline" onclick="loadPermissions()"><i class="fa-solid fa-refresh"></i></button>
            </div>
            <div id="permissionsList" style="max-height:350px; overflow-y:auto; border:1px solid var(--border); border-radius:8px; position:relative;"></div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('permissionsModal')">닫기</button>
            </div>
        </div>
    </div>

    <!-- v7.2: 클라우드 동기화 모달 -->
    <div id="cloudSyncModal" class="overlay" role="dialog" aria-modal="true">
        <div class="modal" style="max-width:500px;">
            <h3><i class="fa-solid fa-cloud"></i> 클라우드 동기화</h3>
            <div class="admin-section">
                <h4><i class="fa-brands fa-google-drive"></i> Google Drive</h4>
                <p style="font-size:0.85rem; opacity:0.7;">API 키 설정이 필요합니다.</p>
                <button class="btn btn-outline" disabled><i class="fa-solid fa-link"></i> 연결</button>
            </div>
            <div class="admin-section">
                <h4><i class="fa-brands fa-dropbox"></i> Dropbox</h4>
                <p style="font-size:0.85rem; opacity:0.7;">API 키 설정이 필요합니다.</p>
                <button class="btn btn-outline" disabled><i class="fa-solid fa-link"></i> 연결</button>
            </div>
            <div style="margin-top:15px; text-align:right;">
                <button class="btn" onclick="closeModal('cloudSyncModal')">닫기</button>
            </div>
        </div>
    </div>

    <script>
        const currentPath = "{{ current_path }}";
        const canModify = {{ 'true' if can_modify else 'false' }};
        let selectedFiles = new Set();
        
        // Utility: Format bytes to human readable size
        function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
            return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
        }
        
        // Utility: Escape HTML to prevent XSS
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // v5: 키보드 탐색 인덱스
        let currentKeyboardIndex = -1;
        
        // v5: 파일 목록 키보드 탐색
        function navigateFileList(direction) {
            const items = document.querySelectorAll('.file-item.data-item');
            if(items.length === 0) return;
            
            // 이전 포커스 제거
            if(currentKeyboardIndex >= 0 && items[currentKeyboardIndex]) {
                items[currentKeyboardIndex].classList.remove('keyboard-focused');
            }
            
            // 새 인덱스 계산
            currentKeyboardIndex += direction;
            if(currentKeyboardIndex < 0) currentKeyboardIndex = items.length - 1;
            if(currentKeyboardIndex >= items.length) currentKeyboardIndex = 0;
            
            // 새 포커스 적용
            items[currentKeyboardIndex].classList.add('keyboard-focused');
            items[currentKeyboardIndex].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
        
        // Utility: Toggle password visibility
        function togglePasswordVisibility() {
            const pwInput = document.getElementById('password');
            const icon = document.getElementById('pwToggleIcon');
            if (pwInput.type === 'password') {
                pwInput.type = 'text';
                icon.className = 'fa-solid fa-eye-slash';
            } else {
                pwInput.type = 'password';
                icon.className = 'fa-solid fa-eye';
            }
        }
        
        document.addEventListener('DOMContentLoaded', () => {
             // v7.1: Global Fetch Interceptor for CSRF
            const originalFetch = window.fetch;
            window.fetch = function(url, options) {
                if (options && options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
                    options.headers = options.headers || {};
                    const token = document.querySelector('meta[name="csrf-token"]').content;
                    if (options.headers instanceof Headers) {
                        options.headers.append('X-CSRF-Token', token);
                    } else {
                        options.headers['X-CSRF-Token'] = token;
                    }
                }
                return originalFetch(url, options);
            };

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
                
                // v5: 방향키로 파일 목록 탐색
                if(e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                    e.preventDefault();
                    navigateFileList(e.key === 'ArrowDown' ? 1 : -1);
                }
                
                // v5: Enter로 선택된 항목 열기
                if(e.key === 'Enter' && currentKeyboardIndex >= 0) {
                    e.preventDefault();
                    const items = document.querySelectorAll('.file-item.data-item');
                    if(items[currentKeyboardIndex]) {
                        items[currentKeyboardIndex].querySelector('.file-info').click();
                    }
                }
            });
            
            // 단축키 힌트 표시
            console.log('📌 키보드 단축키: Ctrl+U(업로드), Ctrl+N(새폴더), Delete(삭제), Ctrl+A(전체선택), F2(이름변경)');
        });
        
        // v7.0: 드롭다운 메뉴 토글
        function toggleDropdown(id) {
            const dropdown = document.getElementById(id);
            const isOpen = dropdown.classList.contains('open');
            closeDropdowns();
            if (!isOpen) dropdown.classList.add('open');
        }
        
        function closeDropdowns() {
            document.querySelectorAll('.dropdown.open').forEach(d => d.classList.remove('open'));
        }
        
        // 드롭다운 외부 클릭 시 닫기
        document.addEventListener('click', e => {
            if (!e.target.closest('.dropdown')) closeDropdowns();
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
            // CSRF 토큰 추가
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = document.querySelector('meta[name="csrf-token"]').content;
            form.appendChild(csrfInput);
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
            // v6.0: 비디오는 스트리밍 플레이어로 재생
            else if (type === 'video') {
                playVideo(path);
            }
            // v6.0: 오디오는 현재 폴더 플레이리스트로 재생 (단일 파일은 기존 방식)
            else if (type === 'audio') {
                openEditor(path, path.split('/').pop(), ext, true);
            }
            else if (type === 'image' || ext.toLowerCase() === '.pdf') {
                openEditor(path, path.split('/').pop(), ext, true);
            }
            else if (type === 'text') {
                openEditor(path, path.split('/').pop(), ext, false);
            }
            // v7.0: 문서 미리보기 (Word, Excel, PowerPoint, CSV, JSON)
            else if (['.docx', '.xlsx', '.xls', '.pptx', '.csv', '.json'].includes(ext.toLowerCase())) {
                openDocumentPreview(path, path.split('/').pop());
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
            
            // 파일 정보 표시 (전역 formatSize 함수 사용)
            document.getElementById('progressFileInfo').innerText = 
                `${files.length}개 파일 (${formatSize(totalSize)})`;
            
            const xhr = new XMLHttpRequest();
            const startTime = Date.now();
            
            xhr.open('POST', '/upload/' + currentPath);
            // v7.1: CSRF Token for XHR
            xhr.setRequestHeader('X-CSRF-Token', document.querySelector('meta[name="csrf-token"]').content);
            
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
            
            // v7.0: 암호화/복호화 버튼 표시 로직
            const encryptBtn = document.getElementById('ctxEncrypt');
            const decryptBtn = document.getElementById('ctxDecrypt');
            const favoriteBtn = document.getElementById('ctxFavorite');
            
            if(encryptBtn && decryptBtn) {
                const isEncrypted = name.endsWith('.enc');
                const isFolder = (type === 'folder');
                encryptBtn.style.display = (!isEncrypted && !isFolder) ? 'flex' : 'none';
                decryptBtn.style.display = isEncrypted ? 'flex' : 'none';
            }
            
            // v7.0: 즐겨찾기는 폴더만
            if(favoriteBtn) {
                favoriteBtn.style.display = (type === 'folder') ? 'flex' : 'none';
            }
            
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
            // v7.0: 태그 추가
            if(action === 'tag') {
                openTagModal(ctxTarget.path, ctxTarget.name);
            }
            // v7.0: 메모
            if(action === 'memo') {
                openMemoModal(ctxTarget.path, ctxTarget.name);
            }
            // v7.0: 즐겨찾기
            if(action === 'favorite') {
                addFavorite(ctxTarget.path, ctxTarget.name);
            }
            // v7.0: 암호화
            if(action === 'encrypt') {
                document.getElementById('encryptTargetPath').textContent = '대상: ' + ctxTarget.name;
                document.getElementById('encryptPassword').value = '';
                openModal('encryptModal');
            }
            // v7.0: 복호화
            if(action === 'decrypt') {
                document.getElementById('decryptTargetPath').textContent = '대상: ' + ctxTarget.name;
                document.getElementById('decryptPassword').value = '';
                openModal('decryptModal');
            }
        }
        
        // 파일 정보 표시
        function showFileInfo(path) {
            fetch('/file_info/' + path).then(r=>r.json()).then(d => {
                if(d.error) { showToast(d.error, 'error'); return; }
                
                // 전역 formatSize 함수 사용
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
                        <a href="/browse/${escapeHtml(b.path)}" style="flex:1; color:var(--text); text-decoration:none;">${escapeHtml(b.name)}</a>
                        <button class="btn-icon btn-danger" onclick="removeBookmark('${escapeHtml(b.path)}')" style="border:none;background:transparent;"><i class="fa-solid fa-xmark"></i></button>
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
                            <div>${escapeHtml(item.original_name)}</div>
                            <div style="font-size:0.75rem; opacity:0.6;">${new Date(item.deleted_at).toLocaleString()}</div>
                        </div>
                        <button class="btn btn-outline" style="font-size:0.75rem; padding:4px 8px;" onclick="restoreFromTrash('${escapeHtml(item.name)}')"><i class="fa-solid fa-undo"></i></button>
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
                            <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(link.path)}</div>
                            <div style="font-size:0.75rem; opacity:0.6;">만료: ${new Date(link.expires).toLocaleString()}</div>
                        </div>
                        <button class="btn btn-outline" style="font-size:0.75rem; padding:4px 8px; margin-right:5px;" onclick="navigator.clipboard.writeText(window.location.origin + '/share/${escapeHtml(link.token)}'); showToast('복사됨','success');"><i class="fa-solid fa-copy"></i></button>
                        <button class="btn-icon btn-danger" style="border:none;background:transparent;" onclick="deleteShareLink('${escapeHtml(link.token)}')"><i class="fa-solid fa-xmark"></i></button>
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
        
        // v5.1: 언어 전환
        function toggleLanguage() {
            const currentLang = localStorage.getItem('lang') || 'ko';
            const newLang = currentLang === 'ko' ? 'en' : 'ko';
            fetch('/set_language/' + newLang).then(r => r.json()).then(d => {
                if(d.success) {
                    localStorage.setItem('lang', newLang);
                    showToast(newLang === 'ko' ? '한국어로 변경됨' : 'Changed to English', 'success');
                    setTimeout(() => location.reload(), 500);
                }
            });
        }
        
        // v5.1: 최근 파일 로드
        function loadRecentFiles() {
            fetch('/recent_files').then(r => r.json()).then(d => {
                const list = document.getElementById('recentList');
                if(!d.files || d.files.length === 0) {
                    list.innerHTML = '<p style="text-align:center; opacity:0.6; padding:20px;">최근 파일이 없습니다</p>';
                    return;
                }
                list.innerHTML = d.files.map(f => `
                    <div style="display:flex; align-items:center; padding:10px; border-bottom:1px solid var(--border);">
                        <i class="fa-solid ${f.type === 'folder' ? 'fa-folder' : 'fa-file'}" style="margin-right:12px; color:${f.type === 'folder' ? 'var(--folder)' : 'var(--text-secondary)'}"></i>
                        <div style="flex:1; min-width:0;">
                            <a href="${f.type === 'folder' ? '/browse/' : '/download/'}${escapeHtml(f.path)}" style="color:var(--text); text-decoration:none; display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(f.name)}</a>
                            <div style="font-size:0.75rem; opacity:0.6;">${new Date(f.accessed).toLocaleString()}</div>
                        </div>
                    </div>
                `).join('');
            });
        }
        
        // v5.1: 접속자 목록 로드
        function loadActiveSessions() {
            fetch('/active_sessions').then(r => r.json()).then(d => {
                document.getElementById('sessionCount').textContent = `(${d.count}명 접속 중)`;
                const list = document.getElementById('sessionsList');
                if(d.sessions.length === 0) {
                    list.innerHTML = '<p style="text-align:center; opacity:0.6; padding:20px;">현재 접속자가 없습니다</p>';
                    return;
                }
                list.innerHTML = d.sessions.map(s => `
                    <div style="display:flex; align-items:center; padding:10px; border-bottom:1px solid var(--border);">
                        <i class="fa-solid fa-user-circle" style="font-size:1.5rem; margin-right:12px; color:${s.role === 'admin' ? 'var(--primary)' : 'var(--text-secondary)'};"></i>
                        <div style="flex:1;">
                            <div style="font-weight:500;">${escapeHtml(s.ip)}</div>
                            <div style="font-size:0.75rem; opacity:0.7;">${s.role === 'admin' ? '👑 관리자' : '👤 게스트'} · ${s.idle_minutes}분 전 활동</div>
                        </div>
                    </div>
                `).join('');
            });
        }
        
        // v5.1: 디스크 상태 체크
        function checkDiskStatus() {
            fetch('/disk_status').then(r => r.json()).then(d => {
                if(d.warning) {
                    showToast(`⚠️ 디스크 용량 경고! ${d.percent}% 사용 중 (잔여: ${d.free})`, 'error');
                }
            }).catch(() => {});
        }
        
        // v5.1: 드래그앤드롭 파일 이동
        function initFileDragDrop() {
            document.querySelectorAll('.file-item.data-item').forEach(item => {
                // 파일은 드래그 가능
                if(!item.querySelector('.fa-folder')) {
                    item.setAttribute('draggable', 'true');
                    item.addEventListener('dragstart', (e) => {
                        e.dataTransfer.setData('text/plain', item.getAttribute('data-name'));
                        e.dataTransfer.effectAllowed = 'move';
                        item.style.opacity = '0.5';
                    });
                    item.addEventListener('dragend', () => {
                        item.style.opacity = '1';
                    });
                }
                
                // 폴더는 드롭 대상
                if(item.querySelector('.fa-folder')) {
                    item.addEventListener('dragover', (e) => {
                        e.preventDefault();
                        e.dataTransfer.dropEffect = 'move';
                        item.style.background = 'var(--primary)';
                        item.style.opacity = '0.8';
                    });
                    item.addEventListener('dragleave', () => {
                        item.style.background = '';
                        item.style.opacity = '1';
                    });
                    item.addEventListener('drop', (e) => {
                        e.preventDefault();
                        item.style.background = '';
                        item.style.opacity = '1';
                        const sourceFile = e.dataTransfer.getData('text/plain');
                        const destFolder = item.getAttribute('data-name');
                        if(sourceFile && destFolder && canModify) {
                            const srcPath = currentPath ? currentPath + '/' + sourceFile : sourceFile;
                            const dstPath = currentPath ? currentPath + '/' + destFolder : destFolder;
                            fetch('/move', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({source: srcPath, destination: dstPath})
                            }).then(r => r.json()).then(d => {
                                if(d.success) {
                                    showToast(`${sourceFile} → ${destFolder}로 이동됨`, 'success');
                                    location.reload();
                                } else {
                                    showToast(d.error || '이동 실패', 'error');
                                }
                            });
                        }
                    });
                }
            });
        }
        
        // 페이지 로드 시 초기화
        document.addEventListener('DOMContentLoaded', () => {
            initFileDragDrop();
            checkDiskStatus();
            // v7.0: 메타데이터 로드는 서버 시작 시 처리됨
        });
        
        // ==========================================
        // v7.0: 태그 관리
        // ==========================================
        let currentTagPath = '';
        
        function openTagModal(path, name) {
            currentTagPath = path;
            document.getElementById('tagTargetPath').textContent = '대상: ' + name;
            document.getElementById('tagInput').value = '';
            loadExistingTags(path);
            openModal('tagModal');
        }
        
        function loadExistingTags(path) {
            fetch('/api/tags?path=' + encodeURIComponent(path)).then(r => r.json()).then(d => {
                const container = document.getElementById('existingTags');
                if(!d.tags || d.tags.length === 0) {
                    container.innerHTML = '<span style="opacity:0.5; font-size:0.85rem;">태그 없음</span>';
                    return;
                }
                container.innerHTML = d.tags.map(t => `
                    <span style="background:${t.color}; color:white; padding:4px 10px; border-radius:12px; font-size:0.8rem; display:inline-flex; align-items:center; gap:5px;">
                        ${escapeHtml(t.tag)}
                        <i class="fa-solid fa-xmark" style="cursor:pointer;" onclick="removeTag('${escapeHtml(path)}', '${escapeHtml(t.tag)}')"></i>
                    </span>
                `).join('');
            });
        }
        
        function addTag() {
            const tag = document.getElementById('tagInput').value.trim();
            const color = document.getElementById('tagColor').value;
            if(!tag) { showToast('태그 이름을 입력하세요', 'warning'); return; }
            
            fetch('/api/tags', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({path: currentTagPath, tag, color})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('태그 추가됨', 'success');
                    document.getElementById('tagInput').value = '';
                    loadExistingTags(currentTagPath);
                } else {
                    showToast(d.error || '태그 추가 실패', 'error');
                }
            });
        }
        
        function removeTag(path, tag) {
            fetch('/api/tags', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({path, tag})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('태그 삭제됨', 'success');
                    loadExistingTags(path);
                }
            });
        }
        
        // ==========================================
        // v7.0: 메모 관리
        // ==========================================
        let currentMemoPath = '';
        
        function openMemoModal(path, name) {
            currentMemoPath = path;
            document.getElementById('memoTargetPath').textContent = '대상: ' + name;
            document.getElementById('memoText').value = '';
            document.getElementById('memoUpdated').textContent = '';
            
            fetch('/api/memo/' + encodeURIComponent(path)).then(r => r.json()).then(d => {
                document.getElementById('memoText').value = d.memo || '';
                if(d.updated) {
                    document.getElementById('memoUpdated').textContent = '마지막 수정: ' + new Date(d.updated).toLocaleString();
                }
            });
            openModal('memoModal');
        }
        
        function saveMemo() {
            const memo = document.getElementById('memoText').value;
            fetch('/api/memo/' + encodeURIComponent(currentMemoPath), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({memo})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('메모 저장됨', 'success');
                    closeModal('memoModal');
                } else {
                    showToast('메모 저장 실패', 'error');
                }
            });
        }
        
        function deleteMemo() {
            if(!confirm('메모를 삭제하시겠습니까?')) return;
            fetch('/api/memo/' + encodeURIComponent(currentMemoPath), {
                method: 'DELETE'
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('메모 삭제됨', 'success');
                    closeModal('memoModal');
                }
            });
        }
        
        // ==========================================
        // v7.0: 암호화/복호화
        // ==========================================
        function encryptFile() {
            const password = document.getElementById('encryptPassword').value || '';
            fetch('/encrypt/' + encodeURIComponent(ctxTarget.path), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('파일 암호화됨: ' + d.new_path, 'success');
                    closeModal('encryptModal');
                    setTimeout(() => location.reload(), 500);
                } else {
                    showToast(d.error || '암호화 실패', 'error');
                }
            });
        }
        
        function decryptFile() {
            const password = document.getElementById('decryptPassword').value || '';
            fetch('/decrypt/' + encodeURIComponent(ctxTarget.path), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('파일 복호화됨: ' + d.new_path, 'success');
                    closeModal('decryptModal');
                    setTimeout(() => location.reload(), 500);
                } else {
                    showToast(d.error || '복호화 실패', 'error');
                }
            });
        }
        
        // ==========================================
        // v7.0: 즐겨찾기 관리
        // ==========================================
        function addFavorite(path, name) {
            fetch('/api/favorites', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({path, name})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('즐겨찾기 추가됨', 'success');
                } else {
                    showToast(d.error || '즐겨찾기 추가 실패', 'warning');
                }
            });
        }
        
        function loadFavorites() {
            fetch('/api/favorites').then(r => r.json()).then(d => {
                const list = document.getElementById('favoritesList');
                if(!d.favorites || d.favorites.length === 0) {
                    list.innerHTML = '<p style="text-align:center; opacity:0.6;">즐겨찾기가 없습니다.</p>';
                    return;
                }
                list.innerHTML = d.favorites.map(f => `
                    <div style="display:flex; align-items:center; padding:10px; border-bottom:1px solid var(--border);">
                        <i class="fa-solid fa-folder-heart" style="color:var(--danger); margin-right:12px;"></i>
                        <a href="/browse/${escapeHtml(f.path)}" style="flex:1; color:var(--text); text-decoration:none;">${escapeHtml(f.name)}</a>
                        <button class="btn-icon btn-danger" onclick="removeFavorite('${escapeHtml(f.path)}')" style="border:none;background:transparent;">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                `).join('');
            });
        }
        
        function removeFavorite(path) {
            fetch('/api/favorites', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({path})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('즐겨찾기 삭제됨', 'success');
                    loadFavorites();
                }
            });
        }
        
        // ==========================================
        // v7.0: 접속 대시보드
        // ==========================================
        function loadAccessDashboard() {
            fetch('/api/access_dashboard').then(r => r.json()).then(d => {
                // 활동별 통계
                const actionStats = document.getElementById('actionStats');
                if(d.action_stats && Object.keys(d.action_stats).length > 0) {
                    actionStats.innerHTML = Object.entries(d.action_stats).map(([action, count]) => `
                        <div style="display:flex; justify-content:space-between; padding:4px 0; font-size:0.85rem;">
                            <span>${escapeHtml(action)}</span>
                            <span style="font-weight:bold;">${count}</span>
                        </div>
                    `).join('');
                } else {
                    actionStats.innerHTML = '<span style="opacity:0.5;">데이터 없음</span>';
                }
                
                // 차단 IP
                const blockedList = document.getElementById('blockedIpsList');
                if(d.blocked_ips && d.blocked_ips.length > 0) {
                    blockedList.innerHTML = d.blocked_ips.map(b => `
                        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; font-size:0.85rem; border-bottom:1px solid var(--border);">
                            <span><i class="fa-solid fa-ban" style="color:var(--danger); margin-right:5px;"></i>${escapeHtml(b.ip)}</span>
                            <button class="btn btn-outline" style="font-size:0.7rem; padding:2px 8px;" onclick="unblockIp('${escapeHtml(b.ip)}')">해제</button>
                        </div>
                    `).join('');
                } else {
                    blockedList.innerHTML = '<span style="opacity:0.5; color:var(--success);">차단된 IP 없음</span>';
                }
                
                // 최근 로그
                const recentLogs = document.getElementById('recentLogs');
                if(d.recent_logs && d.recent_logs.length > 0) {
                    recentLogs.innerHTML = d.recent_logs.map(log => `
                        <div style="display:flex; gap:10px; padding:6px 0; font-size:0.8rem; border-bottom:1px solid var(--border);">
                            <span style="width:60px; opacity:0.6;">${new Date(log.time).toLocaleTimeString()}</span>
                            <span style="width:100px;">${escapeHtml(log.ip)}</span>
                            <span style="flex:1;">${escapeHtml(log.action)}</span>
                        </div>
                    `).join('');
                } else {
                    recentLogs.innerHTML = '<span style="opacity:0.5;">로그 없음</span>';
                }
            });
        }
        
        function unblockIp(ip) {
            fetch('/api/unblock/' + encodeURIComponent(ip), {method: 'POST'})
            .then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('IP 차단 해제됨', 'success');
                    loadAccessDashboard();
                } else {
                    showToast(d.error || '차단 해제 실패', 'error');
                }
            });
        }
        
        // ==========================================
        // v7.0: 문서 미리보기
        // ==========================================
        let currentDocPath = '';
        
        function openDocumentPreview(path, filename) {
            currentDocPath = path;
            document.getElementById('docPreviewTitle').innerHTML = '<i class="fa-solid fa-file-alt"></i> ' + escapeHtml(filename);
            document.getElementById('docPreviewContent').innerHTML = '<div style="text-align:center; padding:40px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:2rem;"></i><br>로딩 중...</div>';
            openModal('docPreviewModal');
            
            fetch('/preview/' + encodeURIComponent(path)).then(r => r.json()).then(d => {
                if(d.success) {
                    if(d.type === 'html') {
                        document.getElementById('docPreviewContent').innerHTML = d.content;
                    } else {
                        document.getElementById('docPreviewContent').innerText = d.content;
                    }
                } else {
                    document.getElementById('docPreviewContent').innerHTML = '<div style="color:var(--danger); text-align:center; padding:20px;"><i class="fa-solid fa-exclamation-circle"></i> ' + (d.error || '미리보기 실패') + '</div>';
                }
            }).catch(e => {
                document.getElementById('docPreviewContent').innerHTML = '<div style="color:var(--danger); text-align:center; padding:20px;"><i class="fa-solid fa-exclamation-circle"></i> 네트워크 오류</div>';
            });
        }
        
        function downloadCurrentDoc() {
            if(currentDocPath) {
                location.href = '/download/' + currentDocPath;
            }
        }

        // ==========================================
        // v6.0: 비디오 플레이어
        // ==========================================
        function playVideo(path) {
            const video = document.getElementById('videoPlayer');
            video.src = '/stream/' + path;
            openModal('videoPlayerModal');
            video.play();
        }
        
        // ==========================================
        // v6.0: 오디오 플레이어
        // ==========================================
        let audioTracks = [];
        let currentTrackIndex = 0;
        
        function openAudioPlayer(folderPath) {
            fetch('/playlist/' + folderPath).then(r => r.json()).then(d => {
                if(d.error || d.count === 0) {
                    showToast('오디오 파일이 없습니다', 'warning');
                    return;
                }
                audioTracks = d.tracks;
                currentTrackIndex = 0;
                renderAudioPlaylist();
                playAudioTrack(0);
                openModal('audioPlayerModal');
            });
        }
        
        function renderAudioPlaylist() {
            const list = document.getElementById('audioPlaylist');
            list.innerHTML = audioTracks.map((t, i) => `
                <div class="audio-track" onclick="playAudioTrack(${i})" style="
                    padding:12px 15px; cursor:pointer; display:flex; align-items:center; gap:10px;
                    border-bottom:1px solid var(--border); transition: background 0.2s;
                    ${i === currentTrackIndex ? 'background:var(--hover); color:var(--primary);' : ''}
                " onmouseover="this.style.background='var(--hover)'" onmouseout="this.style.background='${i === currentTrackIndex ? 'var(--hover)' : ''}'">
                    <i class="fa-solid ${i === currentTrackIndex ? 'fa-volume-high' : 'fa-music'}" style="width:20px;"></i>
                    <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(t.name)}</span>
                </div>
            `).join('');
        }
        
        function playAudioTrack(index) {
            if(index < 0 || index >= audioTracks.length) return;
            currentTrackIndex = index;
            const track = audioTracks[index];
            const audio = document.getElementById('audioPlayer');
            audio.src = track.stream_url;
            audio.play();
            document.getElementById('audioNowPlaying').textContent = track.name;
            renderAudioPlaylist();
        }
        
        function audioPlayPrev() {
            playAudioTrack((currentTrackIndex - 1 + audioTracks.length) % audioTracks.length);
        }
        
        function audioPlayNext() {
            playAudioTrack((currentTrackIndex + 1) % audioTracks.length);
        }
        
        // 오디오 자동 재생: 다음 트랙
        document.addEventListener('DOMContentLoaded', () => {
            const audio = document.getElementById('audioPlayer');
            if(audio) {
                audio.addEventListener('ended', audioPlayNext);
            }
        });
        
        // ==========================================
        // v6.0: 이미지 갤러리
        // ==========================================
        let galleryImages = [];
        let currentGalleryIndex = 0;
        
        function openGallery(folderPath, startIndex = 0) {
            fetch('/gallery/' + folderPath).then(r => r.json()).then(d => {
                if(d.error || d.count === 0) {
                    showToast('이미지가 없습니다', 'warning');
                    return;
                }
                galleryImages = d.images;
                currentGalleryIndex = startIndex;
                showGalleryImage();
                openModal('galleryModal');
            });
        }
        
        function showGalleryImage() {
            if(galleryImages.length === 0) return;
            const img = galleryImages[currentGalleryIndex];
            document.getElementById('galleryImage').src = img.url;
            document.getElementById('galleryInfo').textContent = `${img.name} (${currentGalleryIndex + 1} / ${galleryImages.length})`;
        }
        
        function galleryPrev() {
            currentGalleryIndex = (currentGalleryIndex - 1 + galleryImages.length) % galleryImages.length;
            showGalleryImage();
        }
        
        function galleryNext() {
            currentGalleryIndex = (currentGalleryIndex + 1) % galleryImages.length;
            showGalleryImage();
        }
        
        // 갤러리 키보드 탐색
        document.addEventListener('keydown', (e) => {
            if(document.getElementById('galleryModal').style.display === 'flex') {
                if(e.key === 'ArrowLeft') galleryPrev();
                if(e.key === 'ArrowRight') galleryNext();
                if(e.key === 'Escape') closeModal('galleryModal');
            }
        });
        
        // ==========================================
        // v6.0: 사용자 관리
        // ==========================================
        function showAddUserForm() {
            document.getElementById('userFormArea').style.display = 'block';
        }
        
        function hideAddUserForm() {
            document.getElementById('userFormArea').style.display = 'none';
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
        }
        
        function loadUsers() {
            fetch('/api/users').then(r => r.json()).then(d => {
                const list = document.getElementById('userList');
                const users = Object.entries(d.users || {});
                if(users.length === 0) {
                    list.innerHTML = '<p style="text-align:center; opacity:0.6; padding:20px;">등록된 사용자가 없습니다</p>';
                    return;
                }
                list.innerHTML = users.map(([username, info]) => `
                    <div style="display:flex; align-items:center; padding:12px; border-bottom:1px solid var(--border);">
                        <i class="fa-solid ${info.role === 'admin' ? 'fa-user-shield' : 'fa-user'}" style="font-size:1.3rem; margin-right:12px; color:${info.role === 'admin' ? 'var(--primary)' : 'var(--text-secondary)'};"></i>
                        <div style="flex:1;">
                            <div style="font-weight:500;">${escapeHtml(username)}</div>
                            <div style="font-size:0.75rem; opacity:0.7;">
                                ${info.role === 'admin' ? '👑 관리자' : '👤 사용자'} · 
                                ${info.quota_mb > 0 ? info.usage_mb + ' / ' + info.quota_mb + ' MB' : '무제한'}
                            </div>
                        </div>
                        <button class="btn btn-outline btn-icon" onclick="deleteUser('${username}')" title="삭제">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                `).join('');
            });
        }
        
        function createUser() {
            const username = document.getElementById('newUsername').value.trim();
            const password = document.getElementById('newPassword').value;
            const role = document.getElementById('newRole').value;
            const quota = parseInt(document.getElementById('newQuota').value) || 1024;
            
            if(!username || !password) {
                showToast('사용자명과 비밀번호를 입력하세요', 'warning');
                return;
            }
            
            fetch('/api/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password, role, quota_mb: quota})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast(`사용자 '${username}' 생성됨`, 'success');
                    hideAddUserForm();
                    loadUsers();
                } else {
                    showToast(d.error || '생성 실패', 'error');
                }
            });
        }
        
        function deleteUser(username) {
            if(!confirm(`'${username}' 사용자를 삭제하시겠습니까?`)) return;
            fetch('/api/users/' + username, {method: 'DELETE'})
                .then(r => r.json()).then(d => {
                    if(d.success) {
                        showToast(`'${username}' 삭제됨`, 'success');
                        loadUsers();
                    } else {
                        showToast(d.error || '삭제 실패', 'error');
                    }
                });
        }
        
        function openUserManagement() {
            openModal('userManageModal');
            loadUsers();
        }
        
        // ==========================================
        // v6.0: 청크 업로드
        // ==========================================
        async function uploadLargeFile(file, targetPath) {
            const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
            const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
            
            // 세션 시작
            const initRes = await fetch('/upload/chunk/init', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    filename: file.name,
                    total_size: file.size,
                    path: targetPath
                })
            }).then(r => r.json());
            
            if(!initRes.success) {
                showToast('업로드 시작 실패: ' + initRes.error, 'error');
                return false;
            }
            
            const sessionId = initRes.session_id;
            
            // 청크 업로드
            for(let i = 0; i < totalChunks; i++) {
                const start = i * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                
                const formData = new FormData();
                formData.append('index', i);
                formData.append('chunk', chunk);
                
                const chunkRes = await fetch('/upload/chunk/' + sessionId, {
                    method: 'POST',
                    body: formData
                }).then(r => r.json());
                
                if(!chunkRes.success) {
                    showToast('청크 업로드 실패', 'error');
                    await fetch('/upload/chunk/' + sessionId + '/cancel', {method: 'POST'});
                    return false;
                }
                
                // 진행률 업데이트
                const progress = Math.round(((i + 1) / totalChunks) * 100);
                document.getElementById('uploadProgressText').textContent = `${file.name}: ${progress}%`;
                document.getElementById('uploadProgressBar').style.width = progress + '%';
            }
            
            // 완료
            const completeRes = await fetch('/upload/chunk/' + sessionId + '/complete', {
                method: 'POST'
            }).then(r => r.json());
            
            if(completeRes.success) {
                showToast(`${file.name} 업로드 완료`, 'success');
                return true;
            } else {
                showToast('파일 병합 실패: ' + completeRes.error, 'error');
                return false;
            }
        }
        
        // ==========================================
        // v7.2: 키보드 단축키
        // ==========================================
        let selectedFileIndex = -1;
        let clipboardFiles = [];
        let clipboardAction = null; // 'copy' or 'cut'
        
        const KEYBOARD_SHORTCUTS = {
            '?': () => openModal('shortcutsModal'),
            'ArrowUp': () => selectFileByIndex(selectedFileIndex - 1),
            'ArrowDown': () => selectFileByIndex(selectedFileIndex + 1),
            'Enter': () => openSelectedFile(),
            'Delete': () => deleteSelectedItems(),
            'F2': () => renameSelectedItem(),
            'Escape': () => { closeAllModals(); clearSelection(); },
            'g': () => toggleView(),
            'd': () => toggleDarkMode(),
        };
        
        const CTRL_SHORTCUTS = {
            'a': (e) => { e.preventDefault(); selectAllItems(); },
            'c': () => copySelectedItems(),
            'x': () => cutSelectedItems(),
            'v': () => pasteItems(),
            'n': (e) => { e.preventDefault(); openModal('newFolderModal'); },
            'u': (e) => { e.preventDefault(); document.getElementById('fileInput')?.click(); },
            'f': (e) => { e.preventDefault(); document.querySelector('.search-box input')?.focus(); },
            't': (e) => { e.preventDefault(); createNewTab(); },
        };
        
        document.addEventListener('keydown', (e) => {
            // 입력 필드에서는 단축키 비활성화
            if(['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
            
            const key = e.key.toLowerCase();
            
            if(e.ctrlKey || e.metaKey) {
                if(CTRL_SHORTCUTS[key]) {
                    CTRL_SHORTCUTS[key](e);
                    return;
                }
            }
            
            if(KEYBOARD_SHORTCUTS[e.key]) {
                KEYBOARD_SHORTCUTS[e.key]();
            }
        });
        
        function selectFileByIndex(index) {
            const items = document.querySelectorAll('.file-item');
            if(items.length === 0) return;
            
            index = Math.max(0, Math.min(index, items.length - 1));
            items.forEach((item, i) => item.classList.remove('selected'));
            items[index]?.classList.add('selected');
            items[index]?.scrollIntoView({block: 'nearest'});
            selectedFileIndex = index;
        }
        
        function openSelectedFile() {
            const selected = document.querySelector('.file-item.selected');
            if(selected) selected.click();
        }
        
        function deleteSelectedItems() {
            const checked = document.querySelectorAll('.file-check:checked');
            if(checked.length > 0) {
                batchAction('delete');
            } else {
                const selected = document.querySelector('.file-item.selected');
                if(selected) {
                    const path = selected.dataset.path;
                    if(path && confirm('삭제하시겠습니까?')) {
                        fetch('/trash', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({path: path})
                        }).then(() => location.reload());
                    }
                }
            }
        }
        
        function renameSelectedItem() {
            const selected = document.querySelector('.file-item.selected');
            if(selected && selected.dataset.name) {
                const newName = prompt('새 이름:', selected.dataset.name);
                if(newName && newName !== selected.dataset.name) {
                    fetch('/rename/' + CURRENT_PATH, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({old_name: selected.dataset.name, new_name: newName})
                    }).then(() => location.reload());
                }
            }
        }
        
        function selectAllItems() {
            document.querySelectorAll('.file-check').forEach(cb => {
                cb.checked = true;
                toggleBatch(cb);
            });
        }
        
        function clearSelection() {
            document.querySelectorAll('.file-check').forEach(cb => {
                cb.checked = false;
            });
            document.querySelectorAll('.file-item').forEach(item => {
                item.classList.remove('selected');
            });
            selectedFileIndex = -1;
            updateBatchBar();
        }
        
        function copySelectedItems() {
            clipboardFiles = getSelectedFiles();
            clipboardAction = 'copy';
            if(clipboardFiles.length > 0) {
                showToast(`${clipboardFiles.length}개 항목 복사됨`, 'info');
            }
        }
        
        function cutSelectedItems() {
            clipboardFiles = getSelectedFiles();
            clipboardAction = 'cut';
            if(clipboardFiles.length > 0) {
                showToast(`${clipboardFiles.length}개 항목 잘라내기`, 'info');
            }
        }
        
        function pasteItems() {
            if(clipboardFiles.length === 0) return;
            
            const action = clipboardAction === 'cut' ? 'move' : 'copy';
            let completed = 0;
            
            clipboardFiles.forEach(file => {
                fetch('/' + action, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        source: file,
                        destination: CURRENT_PATH + '/' + file.split('/').pop()
                    })
                }).then(() => {
                    completed++;
                    if(completed === clipboardFiles.length) {
                        showToast(`${completed}개 항목 붙여넣기 완료`, 'success');
                        if(clipboardAction === 'cut') clipboardFiles = [];
                        location.reload();
                    }
                });
            });
        }
        
        function getSelectedFiles() {
            const files = [];
            document.querySelectorAll('.file-check:checked').forEach(cb => {
                const item = cb.closest('.file-item');
                if(item && item.dataset.path) {
                    files.push(item.dataset.path);
                }
            });
            return files;
        }
        
        function closeAllModals() {
            document.querySelectorAll('.overlay').forEach(m => m.style.display = 'none');
        }
        
        // ==========================================
        // v7.2: 드래그 앤 드롭 이동
        // ==========================================
        let draggedItem = null;
        
        function initDragDrop() {
            document.querySelectorAll('.file-item').forEach(item => {
                item.setAttribute('draggable', 'true');
                
                item.addEventListener('dragstart', (e) => {
                    draggedItem = item;
                    item.classList.add('dragging');
                    e.dataTransfer.setData('text/plain', item.dataset.path || '');
                    e.dataTransfer.effectAllowed = 'move';
                });
                
                item.addEventListener('dragend', () => {
                    item.classList.remove('dragging');
                    document.querySelectorAll('.file-item').forEach(i => i.classList.remove('drop-target'));
                    draggedItem = null;
                });
                
                // 폴더에만 드롭 허용
                if(item.dataset.isDir === 'true') {
                    item.addEventListener('dragover', (e) => {
                        if(draggedItem && draggedItem !== item) {
                            e.preventDefault();
                            e.dataTransfer.dropEffect = 'move';
                            item.classList.add('drop-target');
                        }
                    });
                    
                    item.addEventListener('dragleave', () => {
                        item.classList.remove('drop-target');
                    });
                    
                    item.addEventListener('drop', (e) => {
                        e.preventDefault();
                        item.classList.remove('drop-target');
                        
                        if(!draggedItem) return;
                        
                        const sourcePath = draggedItem.dataset.path;
                        const targetFolder = item.dataset.path;
                        const fileName = sourcePath.split('/').pop();
                        
                        fetch('/move', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                source: sourcePath,
                                destination: targetFolder + '/' + fileName
                            })
                        }).then(r => r.json()).then(d => {
                            if(d.success) {
                                showToast(`${fileName} 이동 완료`, 'success');
                                location.reload();
                            } else {
                                showToast(d.error || '이동 실패', 'error');
                            }
                        });
                    });
                }
            });
        }
        
        // ==========================================
        // v7.2: 다중 탭 지원
        // ==========================================
        let tabs = [{id: 0, path: CURRENT_PATH, title: '홈'}];
        let activeTabId = 0;
        let nextTabId = 1;
        
        function createNewTab(path = '') {
            const newTab = {
                id: nextTabId++,
                path: path,
                title: path ? path.split('/').pop() || '루트' : '새 탭'
            };
            tabs.push(newTab);
            renderTabs();
            switchTab(newTab.id);
        }
        
        function closeTab(tabId) {
            if(tabs.length <= 1) return;
            
            const index = tabs.findIndex(t => t.id === tabId);
            tabs.splice(index, 1);
            
            if(activeTabId === tabId) {
                activeTabId = tabs[Math.min(index, tabs.length - 1)].id;
            }
            renderTabs();
        }
        
        function switchTab(tabId) {
            activeTabId = tabId;
            const tab = tabs.find(t => t.id === tabId);
            if(tab) {
                // URL 변경 없이 AJAX로 폴더 내용 로드 (간소화 버전)
                // 실제로는 window.history.pushState 사용 가능
                if(tab.path !== CURRENT_PATH) {
                    window.location.href = '/browse/' + tab.path;
                }
            }
            renderTabs();
        }
        
        function renderTabs() {
            const container = document.getElementById('tabBar');
            if(!container) return;
            
            container.innerHTML = tabs.map(tab => `
                <div class="tab ${tab.id === activeTabId ? 'active' : ''}" onclick="switchTab(${tab.id})">
                    <span class="tab-title">${escapeHtml(tab.title)}</span>
                    ${tabs.length > 1 ? `<button class="tab-close" onclick="event.stopPropagation(); closeTab(${tab.id})">×</button>` : ''}
                </div>
            `).join('') + '<button id="newTabBtn" onclick="createNewTab()">+</button>';
        }
        
        // ==========================================
        // v7.2: PDF 미리보기
        // ==========================================
        async function previewPDF(path) {
            openModal('pdfPreviewModal');
            const viewer = document.getElementById('pdfViewer');
            viewer.innerHTML = '<p style="text-align:center; padding:40px;">PDF 로딩 중...</p>';
            
            try {
                // PDF.js 사용
                if(typeof pdfjsLib === 'undefined') {
                    viewer.innerHTML = '<iframe src="/download/' + path + '" style="width:100%; height:100%; border:none;"></iframe>';
                    return;
                }
                
                const pdf = await pdfjsLib.getDocument('/download/' + path).promise;
                viewer.innerHTML = '';
                
                for(let i = 1; i <= Math.min(pdf.numPages, 10); i++) {
                    const page = await pdf.getPage(i);
                    const scale = 1.5;
                    const viewport = page.getViewport({scale});
                    
                    const canvas = document.createElement('canvas');
                    canvas.width = viewport.width;
                    canvas.height = viewport.height;
                    canvas.style.display = 'block';
                    canvas.style.margin = '10px auto';
                    viewer.appendChild(canvas);
                    
                    await page.render({
                        canvasContext: canvas.getContext('2d'),
                        viewport
                    }).promise;
                }
                
                if(pdf.numPages > 10) {
                    viewer.innerHTML += '<p style="text-align:center;">... 더 많은 페이지가 있습니다. 전체 보기는 다운로드하세요.</p>';
                }
            } catch(e) {
                viewer.innerHTML = '<p style="color:var(--danger); text-align:center; padding:40px;">PDF 로드 실패: ' + e.message + '</p>';
            }
        }
        
        // ==========================================
        // v7.2: Markdown 미리보기 (확장)
        // ==========================================
        function previewMarkdown(path) {
            fetch('/get_content/' + path).then(r => r.json()).then(d => {
                if(d.error) {
                    showToast(d.error, 'error');
                    return;
                }
                
                openModal('editorModal');
                document.getElementById('editorModalTitle').textContent = path.split('/').pop();
                
                const preview = document.getElementById('markdownPreview');
                const editor = document.getElementById('editorArea');
                
                if(preview && typeof marked !== 'undefined') {
                    preview.innerHTML = marked.parse(d.content);
                    // 코드 하이라이팅
                    preview.querySelectorAll('pre code').forEach(block => {
                        if(typeof hljs !== 'undefined') hljs.highlightElement(block);
                    });
                }
                
                if(editor) {
                    editor.value = d.content;
                }
            });
        }
        
        // ==========================================
        // v7.2: 관리자 기능 - 감사 로그
        // ==========================================
        function openAuditLog() {
            openModal('auditLogModal');
            loadAuditLog();
        }
        
        function loadAuditLog(page = 1) {
            fetch(`/api/audit_log?page=${page}&per_page=50`).then(r => r.json()).then(d => {
                const container = document.getElementById('auditLogList');
                if(!container) return;
                
                if(d.logs.length === 0) {
                    container.innerHTML = '<p style="text-align:center; opacity:0.6; padding:20px;">감사 로그가 없습니다</p>';
                    return;
                }
                
                container.innerHTML = d.logs.map(log => `
                    <div style="padding:10px; border-bottom:1px solid var(--border); font-size:0.85rem;">
                        <div style="display:flex; justify-content:space-between;">
                            <span style="font-weight:500;">${escapeHtml(log.action)}</span>
                            <span style="opacity:0.6;">${log.timestamp.replace('T', ' ').substring(0, 19)}</span>
                        </div>
                        <div style="opacity:0.7; margin-top:4px;">
                            <span>${escapeHtml(log.user)}</span> · 
                            <span>${escapeHtml(log.target)}</span>
                            ${log.details ? ` · <span>${escapeHtml(log.details)}</span>` : ''}
                        </div>
                    </div>
                `).join('');
            });
        }
        
        // ==========================================
        // v7.2: 관리자 기능 - 중복 파일 검사
        // ==========================================
        function openDuplicatesModal() {
            openModal('duplicatesModal');
            checkDuplicateStatus();
        }
        
        function startDuplicateScan() {
            fetch('/api/duplicates/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({min_size: 1024})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('중복 파일 스캔 시작', 'info');
                    pollDuplicateProgress();
                } else {
                    showToast(d.error || '스캔 실패', 'error');
                }
            });
        }
        
        function pollDuplicateProgress() {
            const interval = setInterval(() => {
                fetch('/api/duplicates').then(r => r.json()).then(d => {
                    const progress = document.getElementById('duplicateProgress');
                    if(progress) {
                        progress.textContent = d.running ? 
                            `스캔 중... ${d.progress}/${d.total}` : 
                            `완료: ${d.results.length}개 중복 그룹 발견`;
                    }
                    
                    if(!d.running) {
                        clearInterval(interval);
                        renderDuplicates(d.results);
                    }
                });
            }, 1000);
        }
        
        function checkDuplicateStatus() {
            fetch('/api/duplicates').then(r => r.json()).then(d => {
                if(d.running) {
                    pollDuplicateProgress();
                } else if(d.results.length > 0) {
                    renderDuplicates(d.results);
                }
            });
        }
        
        function renderDuplicates(groups) {
            const container = document.getElementById('duplicatesList');
            if(!container) return;
            
            if(groups.length === 0) {
                container.innerHTML = '<p style="text-align:center; opacity:0.6; padding:20px;">중복 파일이 없습니다</p>';
                return;
            }
            
            container.innerHTML = groups.map((group, gi) => `
                <div style="margin-bottom:16px; padding:12px; background:var(--hover); border-radius:8px;">
                    <div style="font-weight:500; margin-bottom:8px;">그룹 ${gi + 1} (${group.length}개 파일, 각 ${formatBytes(group[0].size)})</div>
                    ${group.map((file, fi) => `
                        <div style="display:flex; align-items:center; gap:8px; padding:4px 0;">
                            <input type="checkbox" class="duplicate-check" data-path="${file.path}" ${fi > 0 ? 'checked' : ''}>
                            <span style="flex:1; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(file.path)}</span>
                        </div>
                    `).join('')}
                </div>
            `).join('');
        }
        
        function deleteSelectedDuplicates() {
            const files = [];
            document.querySelectorAll('.duplicate-check:checked').forEach(cb => {
                files.push(cb.dataset.path);
            });
            
            if(files.length === 0) {
                showToast('삭제할 파일을 선택하세요', 'warning');
                return;
            }
            
            if(!confirm(`${files.length}개 파일을 삭제하시겠습니까?`)) return;
            
            fetch('/api/duplicates/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({files})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast(`${d.deleted}개 파일 삭제됨`, 'success');
                    startDuplicateScan(); // 다시 스캔
                }
            });
        }
        
        function formatBytes(bytes) {
            if(bytes < 1024) return bytes + ' B';
            if(bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
            return (bytes/(1024*1024)).toFixed(1) + ' MB';
        }
        
        // ==========================================
        // v7.2: 관리자 기능 - 폴더 권한
        // ==========================================
        function openPermissionsModal() {
            openModal('permissionsModal');
            loadPermissions();
        }
        
        function loadPermissions() {
            fetch('/api/permissions').then(r => r.json()).then(d => {
                const container = document.getElementById('permissionsList');
                if(!container) return;
                
                const perms = Object.entries(d.permissions || {});
                if(perms.length === 0) {
                    container.innerHTML = '<p style="text-align:center; opacity:0.6; padding:20px;">설정된 권한이 없습니다</p>';
                    return;
                }
                
                container.innerHTML = perms.map(([path, perm]) => `
                    <div style="padding:12px; border-bottom:1px solid var(--border);">
                        <div style="font-weight:500; margin-bottom:8px;"><i class="fa-solid fa-folder"></i> ${escapeHtml(path)}</div>
                        <div style="display:flex; gap:12px; font-size:0.85rem; opacity:0.8;">
                            <span>📖 읽기: ${perm.read?.join(', ') || '*'}</span>
                            <span>✏️ 쓰기: ${perm.write?.join(', ') || '*'}</span>
                            <span>🗑️ 삭제: ${perm.delete?.join(', ') || 'admin'}</span>
                        </div>
                        <button class="btn btn-outline btn-icon" style="position:absolute; right:12px; top:12px;" 
                                onclick="deletePermission('${path}')">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                `).join('');
            });
        }
        
        function addPermission() {
            const path = prompt('폴더 경로 (예: documents/private):');
            if(!path) return;
            
            fetch('/api/permissions', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    path: path,
                    read: ['*'],
                    write: ['admin'],
                    delete: ['admin']
                })
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    showToast('권한 설정 완료', 'success');
                    loadPermissions();
                } else {
                    showToast(d.error || '설정 실패', 'error');
                }
            });
        }
        
        function deletePermission(path) {
            if(!confirm(`'${path}' 폴더의 권한 설정을 삭제하시겠습니까?`)) return;
            
            fetch('/api/permissions/' + path, {method: 'DELETE'})
                .then(r => r.json())
                .then(d => {
                    if(d.success) {
                        showToast('권한 삭제됨', 'success');
                        loadPermissions();
                    }
                });
        }
        
        // ==========================================
        // v7.2: 초기화
        // ==========================================
        document.addEventListener('DOMContentLoaded', () => {
            initDragDrop();
            renderTabs();
            
            // 파일 항목에 데이터 속성 추가 (이미 있을 수 있음)
            document.querySelectorAll('.file-item').forEach((item, index) => {
                item.addEventListener('click', () => {
                    document.querySelectorAll('.file-item').forEach(i => i.classList.remove('selected'));
                    item.classList.add('selected');
                    selectedFileIndex = index;
                });
            });
        });
    </script>
</body>
</html>
"""
