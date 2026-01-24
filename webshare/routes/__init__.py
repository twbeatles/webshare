"""
WebShare Pro - Routes Package
Flask 라우트 등록
"""

from flask import Flask


def register_routes(app: Flask):
    """모든 라우트를 앱에 등록"""
    from .main_routes import main_bp
    from .file_routes import file_bp
    from .api_routes import api_bp
    from .root_api_routes import root_api_bp
    from .media_routes import media_bp
    from .share_routes import share_bp
    from .trash_routes import trash_bp
    from .metadata_routes import metadata_bp
    from .security_routes import security_bp
    from .admin_routes import admin_bp
    from .upload_routes import upload_bp
    from .duplicate_routes import duplicate_bp
    from .cloud_routes import cloud_bp
    
    # Blueprint 등록
    app.register_blueprint(main_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(root_api_bp)  # 루트 레벨 API (프론트엔드 호환)
    app.register_blueprint(media_bp)  # 미디어 스트리밍 및 미리보기
    app.register_blueprint(share_bp)  # 공유 링크
    app.register_blueprint(trash_bp)  # 휴지통
    app.register_blueprint(metadata_bp)  # 태그, 즐겨찾기, 메모
    app.register_blueprint(security_bp)  # 암호화/복호화
    app.register_blueprint(admin_bp)  # 관리자 기능
    app.register_blueprint(upload_bp)  # 청크 업로드
    app.register_blueprint(duplicate_bp)  # 중복 파일 검사
    app.register_blueprint(cloud_bp)  # 클라우드 동기화
    
    from .pwa_routes import pwa_bp
    app.register_blueprint(pwa_bp)  # PWA Manifest & Service Worker



