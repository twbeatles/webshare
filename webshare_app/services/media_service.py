"""Media route cache state and helpers."""

from collections import OrderedDict

from flask import session

from utils.file_utils import get_real_ip
from utils.helpers import build_recent_owner_key


THUMBNAIL_CACHE = OrderedDict()
MAX_THUMBNAIL_CACHE = 200
MAX_TEXT_EDIT_SIZE = 10 * 1024 * 1024
MAX_DOCUMENT_PREVIEW_SIZE = 25 * 1024 * 1024


def _recent_owner_key() -> str:
    return build_recent_owner_key(
        session_id=session.get('session_id', '') or '',
        role=session.get('role', 'guest') or 'guest',
        ip=get_real_ip(),
    )


# ==========================================
# 미디어 스트리밍
