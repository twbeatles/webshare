"""
WebShare Pro - Share Links Persistence
공유 링크 영속 저장/로드
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime

from config import SHARE_LINKS, SHARE_LINKS_FILE, conf, share_links_lock
from utils.log_manager import logger


def _share_links_file_path() -> str:
    return os.path.join(conf.get("folder"), SHARE_LINKS_FILE)


def _serialize_share_info(info: dict) -> dict:
    serialized = dict(info or {})
    expires = serialized.get("expires")
    if isinstance(expires, datetime):
        serialized["expires"] = expires.isoformat()
    return serialized


def _deserialize_share_info(info: dict) -> dict | None:
    if not isinstance(info, dict):
        return None

    loaded = dict(info)
    expires_raw = loaded.get("expires")
    if isinstance(expires_raw, datetime):
        expires = expires_raw
    else:
        try:
            expires = datetime.fromisoformat(str(expires_raw))
        except Exception:
            return None
    loaded["expires"] = expires
    return loaded


def save_share_links():
    """공유 링크 파일 저장 (원자적 쓰기)"""
    file_path = _share_links_file_path()
    base_dir = conf.get("folder")

    with share_links_lock:
        payload = {
            "updated": datetime.now().isoformat(),
            "links": {
                token: _serialize_share_info(info)
                for token, info in SHARE_LINKS.items()
            },
        }

    try:
        fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix=".webshare_share_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            if os.path.exists(file_path):
                os.remove(file_path)
            os.rename(temp_path, file_path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
    except Exception as exc:
        logger.add(f"공유 링크 저장 실패: {exc}", "ERROR")


def load_share_links():
    """공유 링크 파일 로드"""
    file_path = _share_links_file_path()
    if not os.path.exists(file_path):
        return

    now = datetime.now()
    loaded_links = {}
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception as exc:
        logger.add(f"공유 링크 로드 실패: {exc}", "ERROR")
        return

    raw_links = raw.get("links", {}) if isinstance(raw, dict) else {}
    for token, info in raw_links.items():
        deserialized = _deserialize_share_info(info)
        if deserialized is None:
            continue
        if deserialized.get("expires") and deserialized["expires"] <= now:
            continue
        loaded_links[token] = deserialized

    with share_links_lock:
        SHARE_LINKS.clear()
        SHARE_LINKS.update(loaded_links)

    logger.add(f"공유 링크 로드 완료: {len(loaded_links)}개")


def cleanup_expired_share_links_persisted() -> int:
    """만료된 공유 링크 정리 후 필요 시 파일 갱신"""
    now = datetime.now()
    removed = 0

    with share_links_lock:
        expired_tokens = [
            token
            for token, info in SHARE_LINKS.items()
            if isinstance(info, dict) and info.get("expires") and info["expires"] <= now
        ]
        for token in expired_tokens:
            SHARE_LINKS.pop(token, None)
        removed = len(expired_tokens)

    if removed > 0:
        save_share_links()
    return removed
