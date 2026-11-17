"""Shared blueprint for chunk-upload routes."""

from flask import Blueprint

from utils.file_utils import invalidate_folder_size_cache_hook

upload_bp = Blueprint("upload", __name__)

upload_bp.after_request(invalidate_folder_size_cache_hook)
