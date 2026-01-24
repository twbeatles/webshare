"""
WebShare Pro - Internationalization (i18n)
다국어 지원 (v7.2.4 - 완전 번역 지원)
"""

I18N = {
    'ko': {
        # 기본 액션
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
        'save': '저장',
        'cancel': '취소',
        'close': '닫기',
        'confirm': '확인',
        'refresh': '새로고침',
        'copy': '복사',
        'cut': '잘라내기',
        'paste': '붙여넣기',
        'move': '이동',
        
        # 에러 메시지
        'file_not_found': '파일을 찾을 수 없습니다',
        'permission_denied': '권한이 없습니다',
        'download_limit': '다운로드 제한에 도달했습니다',
        'ip_blocked': 'IP가 허용 목록에 없습니다',
        'invalid_password': '비밀번호가 올바르지 않습니다',
        'session_expired': '세션이 만료되었습니다',
        'csrf_error': 'CSRF 토큰 검증 실패',
        'path_not_found': '경로를 찾을 수 없습니다',
        'access_denied': '접근 권한이 없습니다',
        
        # 역할
        'admin': '관리자',
        'guest': '게스트',
        'admin_badge': '👑 관리자',
        'guest_badge': '👤 게스트',
        
        # 로그인 페이지
        'secure_file_sharing': '안전한 파일 공유 시스템',
        'password': '비밀번호',
        'password_placeholder': '비밀번호 입력',
        'show_password': '비밀번호 표시',
        
        # 네비게이션/헤더
        'recent_files': '최근 파일',
        'bookmarks': '북마크',
        'clipboard': '클립보드',
        'admin_menu': '관리 메뉴',
        'trash': '휴지통',
        'share_links': '공유 링크',
        'active_sessions': '접속자 현황',
        'user_management': '사용자 관리',
        'access_dashboard': '접속 대시보드',
        'system_monitoring': '시스템 모니터링',
        'server_status': '서버 상태',
        'toggle_language': '한/영 전환',
        'toggle_theme': '테마 변경',
        'help': '도움말',
        
        # 툴바
        'sort_by_name': '이름순',
        'sort_by_size': '크기순',
        'sort_by_date': '날짜순',
        'items_selected': '개 선택됨',
        'batch_download': '일괄 다운로드',
        'batch_delete': '일괄 삭제',
        'toggle_view': '뷰 전환',
        'zip_download': 'ZIP 다운로드',
        'create_folder': '폴더 생성',
        
        # 파일 목록
        'parent_folder': '.. (상위 폴더)',
        'empty_folder': '폴더가 비어있습니다',
        'drag_hint': '파일을 드래그하거나 업로드 버튼을 클릭하세요',
        'no_recent': '최근 파일이 없습니다',
        'folder_path': '폴더 경로',
        'file_tools': '파일 도구',
        'file_list': '파일 목록',
        
        # 정렬/필터
        'sort_order': '정렬 방식',
        
        # 모달 - 새 폴더
        'create_new_folder': '새 폴더 만들기',
        'folder_name': '폴더 이름',
        'folder_name_placeholder': '새 폴더',
        'create': '생성',
        
        # 모달 - 파일 편집기
        'text_editor': '텍스트 편집',
        'preview': '미리보기',
        'edit': '편집하기',
        
        # 모달 - 업로드
        'upload_progress': '업로드 진행',
        'upload_complete': '업로드 완료!',
        'upload_failed': '업로드 실패',
        
        # 모달 - 공유 링크
        'create_share_link': '공유 링크 생성',
        'share_link': '공유 링크',
        'share_path': '공유 경로',
        'expiry_time': '만료 시간',
        'hours': '시간',
        'password_protection': '비밀번호 보호',
        'password_optional': '비밀번호 (선택)',
        'max_downloads': '최대 다운로드 횟수',
        'unlimited': '무제한',
        'copy_link': '링크 복사',
        'link_copied': '링크가 복사되었습니다!',
        'share_link_list': '공유 링크 목록',
        'no_share_links': '생성된 공유 링크가 없습니다',
        'download_count': '다운로드 횟수',
        'expires_at': '만료',
        
        # 모달 - 휴지통
        'trash_bin': '휴지통',
        'restore': '복원',
        'empty_trash': '비우기',
        'delete_permanently': '영구 삭제',
        'trash_empty': '휴지통이 비어있습니다',
        'deleted_at': '삭제일',
        'original_path': '원본 경로',
        
        # 모달 - 암호화
        'encrypt_file': '파일 암호화',
        'decrypt_file': '파일 복호화',
        'encryption_password': '암호화 비밀번호',
        'default_admin_password': '비밀번호 (기본: 관리자 암호)',
        'decryption_password': '암호화 시 사용한 비밀번호',
        'encrypt': '암호화',
        'decrypt': '복호화',
        'password_warning': '비밀번호를 잊으면 파일을 복구할 수 없습니다.',
        
        # 모달 - 즐겨찾기
        'favorites': '즐겨찾기 폴더',
        'add_to_favorites': '즐겨찾기 추가',
        'remove_from_favorites': '즐겨찾기 제거',
        
        # 모달 - 대시보드
        'access_log_dashboard': '접속 대시보드',
        'activity_stats': '활동별 통계',
        'blocked_ips': '차단된 IP',
        'recent_access_logs': '최근 접속 기록',
        'unblock': '차단 해제',
        
        # 모달 - 문서 미리보기
        'document_preview': '문서 미리보기',
        'pdf_preview': 'PDF 미리보기',
        
        # 모달 - 키보드 단축키
        'keyboard_shortcuts': '키보드 단축키',
        'file_select': '파일 선택',
        'open_download': '열기/다운로드',
        'new_tab': '새 탭',
        'view_switch': '뷰 전환',
        'dark_mode': '다크모드',
        'shortcut_help': '단축키 도움말',
        'close_cancel': '닫기/취소',
        
        # 모달 - 감사 로그
        'audit_log': '감사 로그',
        'csv_export': 'CSV 내보내기',
        
        # 모달 - 중복 파일
        'duplicate_files': '중복 파일 검사',
        'start_scan': '스캔 시작',
        'delete_selected': '선택 삭제',
        
        # 모달 - 폴더 권한
        'folder_permissions': '폴더 권한 관리',
        'add_permission': '권한 추가',
        
        # 모달 - 클라우드 동기화
        'cloud_sync': '클라우드 동기화',
        'api_key_required': 'API 키 설정이 필요합니다.',
        'connect': '연결',
        
        # 모달 - 시스템 모니터링
        'system_stats': '시스템 모니터링',
        'server_uptime': '서버 가동시간',
        'total_requests': '총 요청수',
        'data_sent': '전송된 데이터',
        'data_received': '수신된 데이터',
        'disk_usage': '디스크 사용량',
        'used': '사용',
        'free_space': '여유 공간',
        'loading': '로딩 중...',
        'system_info_error': '시스템 정보를 불러올 수 없습니다.',
        
        # 모달 - 통계
        'statistics': '통계',
        'uptime': '가동시간',
        'requests': '요청수',
        'sent': '전송',
        'received': '수신',
        
        # 모달 - 도움말
        'help_title': '도움말',
        
        # 모달 - 비디오 플레이어
        'video_player': '비디오 플레이어',
        
        # 모달 - 북마크
        'bookmark_list': '북마크 목록',
        'add_bookmark': '북마크 추가',
        'no_bookmarks': '북마크가 없습니다',
        
        # 모달 - 클립보드
        'clipboard_title': '클립보드',
        'clipboard_empty': '클립보드가 비어있습니다',
        'paste_here': '여기에 붙여넣기',
        
        # 모달 - 태그
        'manage_tags': '태그 관리',
        'add_tag': '태그 추가',
        'file_tags': '파일 태그',
        
        # 모달 - 메모
        'file_memo': '파일 메모',
        'memo_placeholder': '메모를 입력하세요...',
        
        # 모달 - 파일 정보
        'file_info': '파일 정보',
        'file_name': '파일명',
        'file_size': '크기',
        'modified_date': '수정일',
        'file_type': '파일 유형',
        
        # 모달 - 버전
        'file_versions': '파일 버전',
        'restore_version': '버전 복원',
        'no_versions': '저장된 버전이 없습니다',
        
        # 모달 - 사용자 관리
        'add_user': '사용자 추가',
        'edit_user': '사용자 수정',
        'delete_user': '사용자 삭제',
        'username': '사용자명',
        'role': '역할',
        
        # 컨텍스트 메뉴
        'open': '열기',
        'share': '공유',
        'info': '정보',
        'unzip': '압축 해제',
        'zip': '압축',
        
        # 토스트 메시지
        'saved': '저장되었습니다.',
        'deleted': '삭제되었습니다.',
        'copied': '복사되었습니다.',
        'moved': '이동되었습니다.',
        'renamed': '이름이 변경되었습니다.',
        'created': '생성되었습니다.',
        'restored': '복원되었습니다.',
        'encrypted': '암호화되었습니다.',
        'decrypted': '복호화되었습니다.',
        'language_changed_ko': '한국어로 변경되었습니다',
        'language_changed_en': 'Language changed to English',
        'dark_mode_on': '다크 모드 활성화',
        'light_mode_on': '라이트 모드 활성화',
        
        # 확인 메시지
        'confirm_delete': '정말 삭제하시겠습니까?',
        'confirm_delete_multiple': '개 항목을 삭제하시겠습니까?',
        'confirm_empty_trash': '휴지통을 비우시겠습니까?',
        'confirm_overwrite': '파일을 덮어쓰시겠습니까?',
        
        # 기타
        'settings': '설정',
        'active_users': '접속자',
        'disk_warning': '디스크 용량 경고!',
        'no_sessions': '현재 접속자가 없습니다',
        'minutes_ago': '분 전 활동',
        'connected': '명 접속 중',
        'main_menu': '메인 메뉴',
        
        # 도움말/가이드
        'help_usage_guide': '사용 가이드',
        'help_upload_title': '파일/폴더 업로드',
        'help_upload_desc': '- 드래그 앤 드롭으로 <b>폴더째 업로드</b> 가능<br>- \'업로드\' 버튼으로 파일 여러 개 선택',
        'help_preview_title': '미리보기 지원',
        'help_preview_desc': '- 이미지, 동영상, 오디오, <b>PDF</b>, 텍스트/코드',
        'help_code_viewer_title': '코드 뷰어',
        'help_code_viewer_desc': '- 구문 강조 및 Markdown 미리보기',
        'help_shortcuts_title': '키보드 단축키',
        'shortcut_upload': '파일 업로드',
        'shortcut_new_folder': '새 폴더 생성',
        'shortcut_select_all': '전체 선택',
        'shortcut_delete': '선택 항목 삭제',
        'shortcut_rename': '이름 변경',
        'shortcut_modal_close': '모달 닫기',
        
        # 하단/저장소
        'storage_status': '저장소 상태',
        'calculating': '계산 중...',
        'upload_drag_hint_footer': '폴더나 파일을 화면에 드래그하여 업로드하세요.',
    },
    'en': {
        # Basic actions
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
        'save': 'Save',
        'cancel': 'Cancel',
        'close': 'Close',
        'confirm': 'Confirm',
        'refresh': 'Refresh',
        'copy': 'Copy',
        'cut': 'Cut',
        'paste': 'Paste',
        'move': 'Move',
        
        # Error messages
        'file_not_found': 'File not found',
        'permission_denied': 'Permission denied',
        'download_limit': 'Download limit exceeded',
        'ip_blocked': 'Your IP is not allowed',
        'invalid_password': 'Invalid password',
        'session_expired': 'Session expired',
        'csrf_error': 'CSRF token validation failed',
        'path_not_found': 'Path not found',
        'access_denied': 'Access denied',
        
        # Roles
        'admin': 'Admin',
        'guest': 'Guest',
        'admin_badge': '👑 Admin',
        'guest_badge': '👤 Guest',
        
        # Login page
        'secure_file_sharing': 'Secure File Sharing System',
        'password': 'Password',
        'password_placeholder': 'Enter password',
        'show_password': 'Show password',
        
        # Navigation/Header
        'recent_files': 'Recent Files',
        'bookmarks': 'Bookmarks',
        'clipboard': 'Clipboard',
        'admin_menu': 'Admin Menu',
        'trash': 'Trash',
        'share_links': 'Share Links',
        'active_sessions': 'Active Sessions',
        'user_management': 'User Management',
        'access_dashboard': 'Access Dashboard',
        'system_monitoring': 'System Monitoring',
        'server_status': 'Server Status',
        'toggle_language': 'Toggle Language',
        'toggle_theme': 'Toggle Theme',
        'help': 'Help',
        
        # Toolbar
        'sort_by_name': 'Name',
        'sort_by_size': 'Size',
        'sort_by_date': 'Date',
        'items_selected': ' selected',
        'batch_download': 'Batch Download',
        'batch_delete': 'Batch Delete',
        'toggle_view': 'Toggle View',
        'zip_download': 'ZIP Download',
        'create_folder': 'Create Folder',
        
        # File list
        'parent_folder': '.. (Parent Folder)',
        'empty_folder': 'Folder is empty',
        'drag_hint': 'Drag files here or click upload',
        'no_recent': 'No recent files',
        'folder_path': 'Folder Path',
        'file_tools': 'File Tools',
        'file_list': 'File List',
        
        # Sort/Filter
        'sort_order': 'Sort Order',
        
        # Modal - New Folder
        'create_new_folder': 'Create New Folder',
        'folder_name': 'Folder Name',
        'folder_name_placeholder': 'New Folder',
        'create': 'Create',
        
        # Modal - File Editor
        'text_editor': 'Text Editor',
        'preview': 'Preview',
        'edit': 'Edit',
        
        # Modal - Upload
        'upload_progress': 'Upload Progress',
        'upload_complete': 'Upload Complete!',
        'upload_failed': 'Upload Failed',
        
        # Modal - Share Link
        'create_share_link': 'Create Share Link',
        'share_link': 'Share Link',
        'share_path': 'Share Path',
        'expiry_time': 'Expiry Time',
        'hours': 'Hours',
        'password_protection': 'Password Protection',
        'password_optional': 'Password (Optional)',
        'max_downloads': 'Max Downloads',
        'unlimited': 'Unlimited',
        'copy_link': 'Copy Link',
        'link_copied': 'Link copied!',
        'share_link_list': 'Share Links List',
        'no_share_links': 'No share links created',
        'download_count': 'Downloads',
        'expires_at': 'Expires',
        
        # Modal - Trash
        'trash_bin': 'Trash',
        'restore': 'Restore',
        'empty_trash': 'Empty',
        'delete_permanently': 'Delete Permanently',
        'trash_empty': 'Trash is empty',
        'deleted_at': 'Deleted',
        'original_path': 'Original Path',
        
        # Modal - Encryption
        'encrypt_file': 'Encrypt File',
        'decrypt_file': 'Decrypt File',
        'encryption_password': 'Encryption Password',
        'default_admin_password': 'Password (Default: Admin Password)',
        'decryption_password': 'Password used for encryption',
        'encrypt': 'Encrypt',
        'decrypt': 'Decrypt',
        'password_warning': 'If you forget the password, the file cannot be recovered.',
        
        # Modal - Favorites
        'favorites': 'Favorite Folders',
        'add_to_favorites': 'Add to Favorites',
        'remove_from_favorites': 'Remove from Favorites',
        
        # Modal - Dashboard
        'access_log_dashboard': 'Access Dashboard',
        'activity_stats': 'Activity Stats',
        'blocked_ips': 'Blocked IPs',
        'recent_access_logs': 'Recent Access Logs',
        'unblock': 'Unblock',
        
        # Modal - Document Preview
        'document_preview': 'Document Preview',
        'pdf_preview': 'PDF Preview',
        
        # Modal - Keyboard Shortcuts
        'keyboard_shortcuts': 'Keyboard Shortcuts',
        'file_select': 'Select File',
        'open_download': 'Open/Download',
        'new_tab': 'New Tab',
        'view_switch': 'Switch View',
        'dark_mode': 'Dark Mode',
        'shortcut_help': 'Shortcuts Help',
        'close_cancel': 'Close/Cancel',
        
        # Modal - Audit Log
        'audit_log': 'Audit Log',
        'csv_export': 'CSV Export',
        
        # Modal - Duplicate Files
        'duplicate_files': 'Duplicate File Scan',
        'start_scan': 'Start Scan',
        'delete_selected': 'Delete Selected',
        
        # Modal - Folder Permissions
        'folder_permissions': 'Folder Permissions',
        'add_permission': 'Add Permission',
        
        # Modal - Cloud Sync
        'cloud_sync': 'Cloud Sync',
        'api_key_required': 'API key configuration required.',
        'connect': 'Connect',
        
        # Modal - System Monitoring
        'system_stats': 'System Monitoring',
        'server_uptime': 'Server Uptime',
        'total_requests': 'Total Requests',
        'data_sent': 'Data Sent',
        'data_received': 'Data Received',
        'disk_usage': 'Disk Usage',
        'used': 'Used',
        'free_space': 'Free Space',
        'loading': 'Loading...',
        'system_info_error': 'Cannot load system info.',
        
        # Modal - Statistics
        'statistics': 'Statistics',
        'uptime': 'Uptime',
        'requests': 'Requests',
        'sent': 'Sent',
        'received': 'Received',
        
        # Modal - Help
        'help_title': 'Help',
        
        # Modal - Video Player
        'video_player': 'Video Player',
        
        # Modal - Bookmarks
        'bookmark_list': 'Bookmark List',
        'add_bookmark': 'Add Bookmark',
        'no_bookmarks': 'No bookmarks',
        
        # Modal - Clipboard
        'clipboard_title': 'Clipboard',
        'clipboard_empty': 'Clipboard is empty',
        'paste_here': 'Paste Here',
        
        # Modal - Tags
        'manage_tags': 'Manage Tags',
        'add_tag': 'Add Tag',
        'file_tags': 'File Tags',
        
        # Modal - Memo
        'file_memo': 'File Memo',
        'memo_placeholder': 'Enter memo...',
        
        # Modal - File Info
        'file_info': 'File Info',
        'file_name': 'File Name',
        'file_size': 'Size',
        'modified_date': 'Modified',
        'file_type': 'Type',
        
        # Modal - Versions
        'file_versions': 'File Versions',
        'restore_version': 'Restore Version',
        'no_versions': 'No saved versions',
        
        # Modal - User Management
        'add_user': 'Add User',
        'edit_user': 'Edit User',
        'delete_user': 'Delete User',
        'username': 'Username',
        'role': 'Role',
        
        # Context Menu
        'open': 'Open',
        'share': 'Share',
        'info': 'Info',
        'unzip': 'Extract',
        'zip': 'Compress',
        
        # Toast messages
        'saved': 'Saved successfully.',
        'deleted': 'Deleted successfully.',
        'copied': 'Copied successfully.',
        'moved': 'Moved successfully.',
        'renamed': 'Renamed successfully.',
        'created': 'Created successfully.',
        'restored': 'Restored successfully.',
        'encrypted': 'Encrypted successfully.',
        'decrypted': 'Decrypted successfully.',
        'language_changed_ko': '언어가 한국어로 변경되었습니다',
        'language_changed_en': 'Language changed to English',
        'dark_mode_on': 'Dark mode enabled',
        'light_mode_on': 'Light mode enabled',
        
        # Confirm messages
        'confirm_delete': 'Are you sure you want to delete?',
        'confirm_delete_multiple': ' items will be deleted. Proceed?',
        'confirm_empty_trash': 'Empty the trash?',
        'confirm_overwrite': 'Overwrite the file?',
        
        # Others
        'settings': 'Settings',
        'active_users': 'Active Users',
        'disk_warning': 'Low disk space warning!',
        'no_sessions': 'No active sessions',
        'minutes_ago': ' min ago',
        'connected': ' connected',
        'main_menu': 'Main Menu',
        
        # Help/Guide
        'help_usage_guide': 'User Guide',
        'help_upload_title': 'File/Folder Upload',
        'help_upload_desc': '- Upload folders via drag & drop<br>- Select multiple files via \'Upload\' button',
        'help_preview_title': 'Preview Support',
        'help_preview_desc': '- Image, Video, Audio, <b>PDF</b>, Text/Code',
        'help_code_viewer_title': 'Code Viewer',
        'help_code_viewer_desc': '- Syntax highlighting and Markdown preview',
        'help_shortcuts_title': 'Keyboard Shortcuts',
        'shortcut_upload': 'Upload File',
        'shortcut_new_folder': 'New Folder',
        'shortcut_select_all': 'Select All',
        'shortcut_delete': 'Delete Selected',
        'shortcut_rename': 'Rename',
        'shortcut_modal_close': 'Close Modal',
        
        # Footer/Storage
        'storage_status': 'Storage Status',
        'calculating': 'Calculating...',
        'upload_drag_hint_footer': 'Drag and drop files or folders here to upload.',
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


def get_all_translations(lang: str = None) -> dict:
    """모든 번역을 딕셔너리로 반환 (템플릿/JavaScript용)"""
    from .config import conf
    if lang is None:
        lang = conf.get('language', 'ko')
    
    return I18N.get(lang, I18N['ko']).copy()


def get_current_language() -> str:
    """현재 언어 코드 반환"""
    from .config import conf
    return conf.get('language', 'ko')
