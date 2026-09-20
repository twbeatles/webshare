"""Shared blueprint and clipboard store for file routes."""

import threading
from collections import OrderedDict
from flask import Blueprint


file_bp = Blueprint('file', __name__)

# 클립보드 저장소 (스레드 안전성을 위한 락 사용)
_clipboard_lock = threading.Lock()
_clipboard_store = OrderedDict()
MAX_CLIPBOARD_ENTRIES = 200
MAX_CLIPBOARD_CONTENT_BYTES = 256 * 1024
