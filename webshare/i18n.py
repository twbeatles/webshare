"""
WebShare Pro - Internationalization (i18n)
다국어 지원
"""

I18N = {
    'ko': {
        'login': '접속하기',
        'logout': '로그아웃',
        'upload': '업로드',
        'download': '다운로드',
        'delete': '삭제',
        'rename': '이름 변경',
        'new_folder': '새 폴더',
        'search': '파일 검색...',
        'select_all': '전체 선택',
        'deselect_all': '선택 해제',
        'file_not_found': '파일을 찾을 수 없습니다',
        'permission_denied': '권한이 없습니다',
        'download_limit': '다운로드 제한에 도달했습니다',
        'ip_blocked': 'IP가 허용 목록에 없습니다',
        'admin': '관리자',
        'guest': '게스트',
        'save': '저장',
        'cancel': '취소',
        'close': '닫기',
        # v7.2.1: 레거시에서 추가된 키들
        'empty_folder': '폴더가 비어있습니다',
        'drag_hint': '파일을 드래그하거나 업로드 버튼을 클릭하세요',
        'recent_files': '최근 파일',
        'no_recent': '최근 파일이 없습니다',
        'settings': '설정',
        'server_status': '서버 상태',
        'active_users': '접속자',
        'disk_warning': '디스크 용량 경고!',
    },
    'en': {
        'login': 'Login',
        'logout': 'Logout',
        'upload': 'Upload',
        'download': 'Download',
        'delete': 'Delete',
        'rename': 'Rename',
        'new_folder': 'New Folder',
        'search': 'Search files...',
        'select_all': 'Select All',
        'deselect_all': 'Deselect All',
        'file_not_found': 'File not found',
        'permission_denied': 'Permission denied',
        'download_limit': 'Download limit exceeded',
        'ip_blocked': 'Your IP is not allowed',
        'admin': 'Admin',
        'guest': 'Guest',
        'save': 'Save',
        'cancel': 'Cancel',
        'close': 'Close',
        # v7.2.1: Added from legacy
        'empty_folder': 'Folder is empty',
        'drag_hint': 'Drag files here or click upload',
        'recent_files': 'Recent Files',
        'no_recent': 'No recent files',
        'settings': 'Settings',
        'server_status': 'Server Status',
        'active_users': 'Active Users',
        'disk_warning': 'Low disk space warning!',
    }
}

# 누락 키 경고 (개발 모드용)
_warned_keys = set()


def get_text(key: str, lang: str = None) -> str:
    """다국어 텍스트 반환"""
    from .config import conf
    if lang is None:
        lang = conf.get('language', 'ko')
    
    translations = I18N.get(lang, I18N['ko'])
    if key in translations:
        return translations[key]
    
    # 누락 키 경고 (한 번만)
    if key not in _warned_keys:
        _warned_keys.add(key)
        # 로거 순환 import 방지를 위해 print 사용
        print(f"[WARN] i18n: 누락된 번역 키 '{key}' (lang={lang})")
    
    return key
