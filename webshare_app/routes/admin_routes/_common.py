"""Shared blueprint and user-API state for admin routes."""

import threading
from flask import Blueprint


admin_bp = Blueprint('admin', __name__)

_users_file_lock = threading.Lock()
USER_API_NOTICE = "사용자 API는 현재 로그인 인증과 연동되지 않음"
USER_API_REASON = "현재 로그인 방식은 admin_pw/guest_pw(password-only)이며 별도 사용자 계정은 비활성화되어 있습니다."
USER_API_WARNING = USER_API_REASON
