
"""
WebShare Pro - WebDAV Server (v7.2.3)
WsgiDAV를 이용한 WebDAV 기능 제공
"""

import os
from wsgidav.wsgidav_app import WsgiDAVApp
from wsgidav.dc.base_dc import BaseDomainController
from wsgidav.fs_dav_provider import FilesystemProvider

from ..config import conf
from ..utils.log_manager import logger

class WebShareDomainController(BaseDomainController):
    """WebShare 인증 정보를 사용하는 도메인 컨트롤러"""
    
    def __init__(self, wsgidav_app, config):
        super().__init__(wsgidav_app, config)

    def get_domain_realm(self, input_header, environ):
        return "WebShare Pro WebDAV"

    def require_authentication(self, realmname, environ):
        return True

    def basic_auth_user(self, realmname, username, password, environ):
        """인증 검증"""
        admin_pw = conf.get('admin_pw')
        guest_pw = conf.get('guest_pw')
        
        from ..security.auth import verify_password
        
        # 관리자
        if username == 'admin':
            if verify_password(admin_pw, password):
                environ['webshare.role'] = 'admin'
                return True
        
        # 게스트
        if username == 'guest':
            if verify_password(guest_pw, password):
                environ['webshare.role'] = 'guest'
                return True
                
        return False
        
    def supports_http_digest_auth(self):
        return False

    def get_permissions(self, realmname, user, environ, url):
        """권한 확인"""
        if user == 'admin':
            return True  # Full access
            
        if user == 'guest':
            # 게스트 권한 확인
            allow_upload = conf.get('allow_guest_upload')
            if allow_upload:
                return True
            else:
                # 읽기 전용 (WebDAV 권한)
                # WsgiDAV에서는 permissions 딕셔너리나 bool 반환
                # 하지만 여기서는 simple DC 로직을 따라가거나 
                # role 기반으로 처리.
                # WsgiDAV 3.x: return list of permissions like (True, True, False...) or preset strings
                # 간단하게: Write Method면 False 리턴
                method = environ.get('REQUEST_METHOD', 'GET')
                if method in ('PUT', 'POST', 'DELETE', 'MKCOL', 'MOVE', 'COPY', 'PROPPATCH', 'LOCK', 'UNLOCK'):
                    return False
                return True
                
        return False

def get_webdav_config(root_path):
    """WsgiDAV 설정 생성"""
    return {
        "provider_mapping": {"/": FilesystemProvider(root_path)},
        "user_mapping": {},  # DomainController에서 처리
        "middleware_stack": [
            "wsgidav.middleware.debug.DebugFilter",
            "wsgidav.error_printer.ErrorPrinter",
            "wsgidav.http_authenticator.HTTPAuthenticator",
            "wsgidav.dir_browser.DirBrowser",
        ],
        "simple_dc": {"user_mapping": {}},  # Placeholder
        "verbose": 1,
        "domain_controller": WebShareDomainController,
        "logging": {
            "enable": True,
            "enable_loggers": [], # 자체 로거 사용
        }
    }

def create_webdav_app():
    """WebDAV WSGI 앱 생성"""
    try:
        root_path = conf.get('folder')
        if not os.path.exists(root_path):
            os.makedirs(root_path, exist_ok=True)
            
        config = get_webdav_config(root_path)
        app = WsgiDAVApp(config)
        
        logger.add("WebDAV 앱이 초기화되었습니다.", "INFO")
        return app
    except Exception as e:
        logger.add(f"WebDAV 초기화 실패: {e}", "ERROR")
        return None
