"""
WebShare Pro - Media Routes
미디어 스트리밍, 썸네일, 갤러리, 플레이리스트, 문서 미리보기

Split package (SRP): streaming, previews, and text editing each live in
their own module. Importing this package registers all media routes on
`media_bp`.
"""

from ._common import media_bp
from .streaming import stream_hls_playlist, stream_hls_segment, stream_media
from .previews import (
    document_preview,
    get_gallery,
    get_playlist,
    get_thumbnail,
    video_thumbnail,
)
from .editing import get_content, save_content
from utils.helpers import atomic_write_bytes
from webshare_app.services.media_service import MAX_TEXT_EDIT_SIZE

__all__ = [
    "MAX_TEXT_EDIT_SIZE",
    "atomic_write_bytes",
    "document_preview",
    "get_content",
    "get_gallery",
    "get_playlist",
    "get_thumbnail",
    "media_bp",
    "save_content",
    "stream_hls_playlist",
    "stream_hls_segment",
    "stream_media",
    "video_thumbnail",
]
