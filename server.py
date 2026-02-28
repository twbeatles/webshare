"""
WebShare Pro - Server Module
Flask ?쒕쾭 諛?ServerThread ?대옒??
"""

import threading
import logging
from flask import Flask
from werkzeug.serving import make_server

from config import conf, APP_TITLE
from utils.log_manager import logger


# Flask 濡쒓퉭 ?ㅼ젙 (肄섏넄 異쒕젰 ?듭젣)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


# ==========================================
# 二쇨린???뺣━ ?ㅼ?以꾨윭
# ==========================================
_cleanup_timer = None
_runtime_init_lock = threading.Lock()
_runtime_initialized = False


def ensure_runtime_initialized():
    """
    ?고????곗씠??濡쒕뱶/珥덇린??(以묐났 ?ㅽ뻾 諛⑹?)
    - 硫뷀??곗씠??
    - 媛먯궗 濡쒓렇
    - 沅뚰븳
    - ?대씪?곕뱶 ?ㅼ젙
    - 以묐났 ?ㅼ틪 寃곌낵
    """
    global _runtime_initialized
    with _runtime_init_lock:
        if _runtime_initialized:
            return

        from features.metadata import load_metadata
        from features.audit_log import load_audit_log
        from features.cloud_sync import load_cloud_config
        from features.share_links_store import load_share_links
        from security.permissions import load_permissions
        from features.duplicates import load_duplicate_results

        load_metadata()
        load_audit_log()
        load_share_links()
        load_permissions()
        load_cloud_config()
        load_duplicate_results()
        _runtime_initialized = True
        logger.add("?고???珥덇린???꾨즺")


def is_runtime_initialized() -> bool:
    """?고???珥덇린???꾨즺 ?щ?"""
    return _runtime_initialized


def start_periodic_cleanup():
    """v7.1: 5遺?媛꾧꺽 二쇨린???뺣━ ?쒖옉"""
    global _cleanup_timer
    
    def do_cleanup():
        global _cleanup_timer
        try:
            from features.trash import auto_cleanup_trash
            from utils.helpers import cleanup_expired_sessions, cleanup_expired_share_links, cleanup_expired_download_trackers
            from security.ip_blocker import cleanup_expired_login_attempts
            from features.audit_log import flush_audit_log_if_dirty
            
            # ?몄뀡 ?뺣━
            sessions_cleaned = cleanup_expired_sessions()
            
            # 怨듭쑀 留곹겕 ?뺣━
            links_cleaned = cleanup_expired_share_links()
            
            # ?낅줈???몄뀡 ?뺣━
            from routes.upload_routes import cleanup_expired_upload_sessions
            uploads_cleaned = cleanup_expired_upload_sessions()
            
            # ?몃옖?ㅼ퐫???몄뀡 ?뺣━ (v7.2.3)
            from features.transcoder import cleanup_sessions as cleanup_transcode_sessions
            cleanup_transcode_sessions()
            
            # ?댁????뺣━
            trash_cleaned = auto_cleanup_trash()
            
            # 濡쒓렇???쒕룄 湲곕줉 ?뺣━ (硫붾え由??꾩닔 諛⑹?)
            login_attempts_cleaned = cleanup_expired_login_attempts()
            
            # ?ㅼ슫濡쒕뱶 ?몃옒而??뺣━ (?꾨궇 ?곗씠????젣)
            download_trackers_cleaned = cleanup_expired_download_trackers()

            # 媛먯궗 濡쒓렇 flush (dirty ?곹깭???뚮쭔)
            flush_audit_log_if_dirty(force=False, min_interval_seconds=5)
            
            total = sessions_cleaned + links_cleaned + uploads_cleaned + trash_cleaned + login_attempts_cleaned + download_trackers_cleaned
            if total > 0:
                logger.add(f"二쇨린???뺣━ ?꾨즺: ?몄뀡 {sessions_cleaned}, 留곹겕 {links_cleaned}, ?낅줈??{uploads_cleaned}, ?댁???{trash_cleaned}, 濡쒓렇?몄떆??{login_attempts_cleaned}, ?ㅼ슫濡쒕뱶?몃옒而?{download_trackers_cleaned}")
        except Exception as e:
            logger.add(f"二쇨린???뺣━ ?ㅻ쪟: {e}", "ERROR")
        
        # 5遺????ㅼ떆 ?ㅽ뻾
        _cleanup_timer = threading.Timer(300, do_cleanup)
        _cleanup_timer.daemon = True
        _cleanup_timer.start()
    
    # 泥??ㅽ뻾: ?쒕쾭 ?쒖옉 1遺???
    _cleanup_timer = threading.Timer(60, do_cleanup)
    _cleanup_timer.daemon = True
    _cleanup_timer.start()
    logger.add("二쇨린???뺣━ ?ㅼ?以꾨윭 ?쒖옉??(5遺?媛꾧꺽)")


def stop_periodic_cleanup():
    """v7.1: 二쇨린???뺣━ 以묒?"""
    global _cleanup_timer
    if _cleanup_timer:
        _cleanup_timer.cancel()
        _cleanup_timer = None








# ==========================================
# Flask ???⑺넗由?
# ==========================================
def create_app():
    """Flask ???⑺넗由??⑥닔"""
    app = Flask(__name__, 
                static_folder='static',
                template_folder='templates')

    # ?좏깮 ?섏〈?? orjson ?ъ슜 ??JSON 吏곷젹??媛??
    try:
        import orjson
        from flask.json.provider import DefaultJSONProvider

        class OrjsonProvider(DefaultJSONProvider):
            def dumps(self, obj, **kwargs):
                option = 0
                if kwargs.get("sort_keys"):
                    option |= orjson.OPT_SORT_KEYS
                return orjson.dumps(obj, option=option).decode("utf-8")

            def loads(self, s, **kwargs):
                return orjson.loads(s)

        app.json = OrjsonProvider(app)
        logger.add("orjson JSON provider enabled")
    except Exception:
        pass
    
    # 蹂댁븞 ?ㅼ젙
    # secret_key: ?ㅼ젙?먯꽌 濡쒕뱶?섍굅???쒕뜡 ?앹꽦 (?ъ떆?????몄뀡 臾댄슚?붾맖)
    import os as _os
    app.secret_key = conf.get('secret_key') or _os.urandom(24).hex()
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB
    app.config['SESSION_COOKIE_SECURE'] = bool(conf.get('use_https', False))
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600

    # ?좏깮 ?섏〈?? gzip ?뺤텞 ?꾩넚
    try:
        from flask_compress import Compress

        app.config['COMPRESS_LEVEL'] = 5
        app.config['COMPRESS_MIN_SIZE'] = 1024
        Compress(app)
    except Exception:
        pass
    
    # CSRF ?좏겙 Jinja2 ?⑥닔 ?깅줉
    from security.csrf import generate_csrf_token
    app.jinja_env.globals['csrf_token'] = generate_csrf_token

    @app.before_request
    def _global_before_request():
        import time
        from datetime import datetime
        from flask import g, jsonify, request, session, redirect

        from config import STATS, ACTIVE_SESSIONS, session_lock, stats_lock
        from i18n import get_text
        from security.csrf import validate_csrf_token
        from security.ip_blocker import check_ip_blocked, check_ip_whitelist
        from utils.file_utils import get_real_ip
        from utils.request_policy import STATE_CHANGING_METHODS

        g.start_time = time.time()

        with stats_lock:
            STATS['requests'] += 1
            STATS['active_connections'] += 1

        client_ip = get_real_ip()

        if not check_ip_whitelist(client_ip):
            return jsonify({'error': get_text('ip_blocked')}), 403

        blocked, remaining = check_ip_blocked(client_ip)
        if blocked:
            return jsonify({'error': f'IP 李⑤떒??(?⑥? ?쒓컙: {remaining}遺?'}), 403

        if session.get('logged_in'):
            last_active = session.get('last_active')
            if last_active:
                timeout = conf.get('session_timeout') or 60
                if datetime.now().timestamp() - last_active > timeout * 60:
                    session.clear()
                    logger.add(f"?몄뀡 留뚮즺: {client_ip}")
                    is_ajax = request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                    if is_ajax or request.path.startswith('/api/'):
                        return jsonify({'error': '세션이 만료되었습니다.', 'redirect': '/'}), 401
                    return redirect('/')

            session['last_active'] = datetime.now().timestamp()
            sid = session.get('session_id')
            if sid:
                with session_lock:
                    if sid in ACTIVE_SESSIONS:
                        ACTIVE_SESSIONS[sid]['last_active'] = datetime.now()

        if request.method in STATE_CHANGING_METHODS and session.get('logged_in'):
            # 濡쒓렇??POST? 怨듭쑀 留곹겕 鍮꾨?踰덊샇 POST???명솚???꾪빐 ?쒖쇅
            endpoint = request.endpoint or ''
            if endpoint not in {'main.index', 'share.access_share_link'}:
                if not validate_csrf_token():
                    logger.add(f"CSRF 寃利??ㅽ뙣: {client_ip}", "WARN")
                    return jsonify({'error': 'CSRF ?좏겙 寃利??ㅽ뙣'}), 403

    @app.after_request
    def _global_after_request(response):
        from config import STATS, stats_lock

        with stats_lock:
            # bytes_sent??湲곕낯?곸쑝濡??묐떟 Content-Length 湲곕컲?쇰줈 ?⑥씪 吏묎퀎?쒕떎.
            # ZIP/HLS ??湲몄씠 誘몄젙 ?ㅽ듃由쇱? ?쇱슦?몄뿉???섎룞 吏묎퀎?쒕떎.
            if response.content_length:
                STATS['bytes_sent'] += response.content_length
            STATS['active_connections'] = max(0, STATS['active_connections'] - 1)
        return response
    
    # ?쇱슦???깅줉
    from routes import register_routes
    register_routes(app)
    
    return app


def build_composed_wsgi_app(flask_app=None):
    """
    Build the final WSGI app.
    - base: Flask app
    - optional: mount WebDAV at /webdav via DispatcherMiddleware
    """
    app = flask_app or create_app()
    wsgi_app = app

    try:
        from werkzeug.middleware.dispatcher import DispatcherMiddleware
        from features.webdav_server import create_webdav_app

        webdav_app = create_webdav_app()
        if webdav_app:
            wsgi_app = DispatcherMiddleware(app, {
                '/webdav': webdav_app
            })
            logger.add("WebDAV ?붾뱶?ъ씤??留덉슫?몃맖: /webdav")
    except ImportError:
        logger.add("WebDAV 紐⑤뱢??李얠쓣 ???놁뒿?덈떎 (WsgiDAV 誘몄꽕移?", "WARN")
    except Exception as e:
        logger.add(f"WebDAV 留덉슫???ㅽ뙣: {e}", "ERROR")

    return app, wsgi_app


# ==========================================
# ?쒕쾭 ?ㅻ젅??(Aggressive Shutdown)
# ==========================================
class ServerThread(threading.Thread):
    """Flask ?쒕쾭瑜?諛깃렇?쇱슫???ㅻ젅?쒖뿉???ㅽ뻾"""
    
    def __init__(self, use_https=False):
        threading.Thread.__init__(self)
        self.server = None
        self.daemon = True
        self.use_https = use_https
        self.port = int(conf.get('port', 5000))
        self._shutdown_event = threading.Event()
    
    def run(self):
        """?쒕쾭 ?쒖옉"""
        try:
            # HTTPS ?ㅼ젙
            ssl_ctx = None
            proto = "http"
            if self.use_https:
                try:
                    ssl_ctx = 'adhoc'
                    proto = "https"
                except Exception as e:
                    logger.add(f"HTTPS(adhoc) ?ㅼ젙 ?ㅽ뙣: {e}\nHTTP濡??꾪솚?⑸땲??", "ERROR")
                    self.use_https = False
                    ssl_ctx = None
                    proto = "http"
            
            # server creation (Flask app -> optional WebDAV wrap -> make_server)
            import werkzeug.serving
            if hasattr(werkzeug.serving, 'make_server'):
                host = conf.get('display_host', '0.0.0.0')
                self.app, self.wsgi_app = build_composed_wsgi_app()
                self.server = make_server(
                    host,
                    self.port,
                    self.wsgi_app,
                    threaded=True,
                    ssl_context=ssl_ctx
                )
            else:
                logger.add("Werkzeug 버전 호환성 경고: make_server를 찾을 수 없습니다.", "WARN")
                return

            logger.add(f"?쒕쾭 ?쒖옉: {proto}://{host}:{self.port}")

            # ?고????곗씠??珥덇린??以묐났 諛⑹?)
            ensure_runtime_initialized()

            # 寃???몃뜳??鍮뚮뱶 (v7.2.3)
            from features.search_indexer import indexer
            threading.Thread(target=indexer.build_index, args=(conf.get('folder'),), daemon=True).start()
            
            # 二쇨린???뺣━ ?쒖옉
            start_periodic_cleanup()
            
            # serve_forever ?ㅽ뻾 (shutdown ??socket error媛 ?????덉쑝誘濡??덉쇅 泥섎━)
            try:
                self.server.serve_forever()
            except OSError:
                pass  # ?쒕쾭 ?뚯폆??媛뺤젣 醫낅즺?섎㈃ 諛쒖깮?섎뒗 ?뺤긽?곸씤 ?꾩긽
            except Exception as e:
                logger.add(f"?쒕쾭 ?ㅽ뻾 以??ㅻ쪟: {e}", "ERROR")
            
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Address already in use
                logger.add(f"?ы듃 {self.port}媛 ?대? ?ъ슜 以묒엯?덈떎.", "ERROR")
            else:
                logger.add(f"?쒕쾭 ?쒖옉 ?ㅻ쪟: {e}", "ERROR")
        except Exception as e:
            logger.add(f"?쒕쾭 移섎챸???ㅻ쪟: {e}", "ERROR")
    
    def shutdown(self):
        """?쒕쾭 醫낅즺 (媛뺣젰??醫낅즺 濡쒖쭅)"""
        self._shutdown_event.set()
        
        # 二쇨린???뺣━ 以묒?
        stop_periodic_cleanup()
        
        # ?몃옖?ㅼ퐫??紐⑤몢 ?뺤? (v7.2.3)
        try:
            from features.transcoder import stop_all_transcoders
            stop_all_transcoders()
        except ImportError:
            pass
        
        if self.server:
            try:
                logger.add("?쒕쾭 醫낅즺 ?좏샇 ?꾩넚 以?..")
                
                # 1. 醫낅즺 ?뚮옒洹??ㅼ젙 (紐⑤뱺 媛?μ꽦 怨좊젮)
                if hasattr(self.server, '_BaseServer__shutdown_request'):
                    self.server._BaseServer__shutdown_request = True
                if hasattr(self.server, '_shutdown_request'):
                    self.server._shutdown_request = True
                
                # 2. ?뚯폆 媛뺤젣 醫낅즺 (釉붾줈???댁젣 ?듭떖)
                if hasattr(self.server, 'socket') and self.server.socket:
                    try:
                        import socket
                        self.server.socket.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        self.server.socket.close()
                    except Exception:
                        pass
                
                # 3. 怨듭떇 shutdown ?몄텧
                try:
                    self.server.shutdown()
                except Exception:
                    pass
                
                try:
                    self.server.server_close()
                except Exception:
                    pass
                
                logger.add("Server stopped cleanly")
            except Exception as e:
                logger.add(f"Exception during shutdown (ignored): {e}", "WARN")
            finally:
                try:
                    from features.audit_log import flush_audit_log_if_dirty
                    flush_audit_log_if_dirty(force=True)
                except Exception:
                    pass


# ?꾩뿭 ?쒕쾭 ?ㅻ젅??(GUI?먯꽌 李몄“)
server_thread = None


def start_server(use_https=False):
    """?쒕쾭 ?쒖옉 ?ы띁 ?⑥닔"""
    global server_thread
    if server_thread and server_thread.is_alive():
        logger.add("?쒕쾭媛 ?대? ?ㅽ뻾 以묒엯?덈떎", "WARN")
        return False
    
    server_thread = ServerThread(use_https)
    server_thread.start()
    return True


def stop_server(timeout=2.0):
    """?쒕쾭 醫낅즺 ?ы띁 ?⑥닔 (??꾩븘??吏??"""
    global server_thread
    if server_thread and server_thread.is_alive():
        server_thread.shutdown()
        server_thread.join(timeout=timeout)  # 理쒕? timeout珥??湲?
        server_thread = None
        return True
    return False


def is_server_running():
    """?쒕쾭 ?ㅽ뻾 ?곹깭 ?뺤씤"""
    return server_thread is not None and server_thread.is_alive()
