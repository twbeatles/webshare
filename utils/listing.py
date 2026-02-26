"""
WebShare Pro - Directory Listing Utilities
고성능 디렉토리 목록/페이지네이션 공통 유틸리티
"""

from __future__ import annotations

import math
import os
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Tuple

from .file_utils import fmt_bytes, get_file_type, validate_path

try:
    from cachetools import TTLCache
except ImportError:  # pragma: no cover - optional dependency
    TTLCache = None


DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000
_LIST_CACHE_TTL_SECONDS = 2
_LIST_CACHE_MAXSIZE = 512

_list_cache_lock = threading.Lock()
if TTLCache is not None:
    _list_cache = TTLCache(maxsize=_LIST_CACHE_MAXSIZE, ttl=_LIST_CACHE_TTL_SECONDS)
else:
    _list_cache = {}


def _cache_get(key: Tuple[Any, ...]) -> Dict[str, Any] | None:
    with _list_cache_lock:
        if TTLCache is not None:
            cached = _list_cache.get(key)
            return dict(cached) if isinstance(cached, dict) else cached

        now = time.time()
        cached = _list_cache.get(key)
        if not cached:
            return None
        payload, expires_at = cached
        if now > expires_at:
            _list_cache.pop(key, None)
            return None
        return dict(payload)


def _cache_set(key: Tuple[Any, ...], payload: Dict[str, Any]) -> None:
    with _list_cache_lock:
        if TTLCache is not None:
            _list_cache[key] = dict(payload)
            return
        _list_cache[key] = (dict(payload), time.time() + _LIST_CACHE_TTL_SECONDS)
        # fallback cache bound
        if len(_list_cache) > _LIST_CACHE_MAXSIZE:
            oldest_key = next(iter(_list_cache))
            _list_cache.pop(oldest_key, None)


def _normalize_sort(sort_by: str) -> str:
    sort_by = (sort_by or "name").lower().strip()
    if sort_by not in {"name", "size", "date", "type"}:
        return "name"
    return sort_by


def _normalize_order(order: str) -> str:
    order = (order or "asc").lower().strip()
    return "desc" if order == "desc" else "asc"


def _normalize_page(page: int) -> int:
    if not isinstance(page, int):
        return 1
    return max(1, page)


def _normalize_page_size(page_size: int) -> int:
    if not isinstance(page_size, int):
        return DEFAULT_PAGE_SIZE
    return max(20, min(MAX_PAGE_SIZE, page_size))


def _item_sort_key(sort_by: str, item: Dict[str, Any]) -> Tuple[Any, ...]:
    if sort_by == "size":
        return (int(item["size"]), item["name_lower"])
    if sort_by == "date":
        return (float(item["mtime"]), item["name_lower"])
    if sort_by == "type":
        return (item["type"], item["name_lower"])
    return (item["name_lower"],)


def list_directory_page(
    base_dir: str,
    subpath: str = "",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    sort_by: str = "name",
    order: str = "asc",
    query: str = "",
    access_filter: Callable[[str, str], bool] | None = None,
    cache_scope: str = "",
) -> Dict[str, Any]:
    """
    디렉토리 목록을 os.scandir 기반으로 페이지네이션하여 반환.
    """
    page = _normalize_page(page)
    page_size = _normalize_page_size(page_size)
    sort_by = _normalize_sort(sort_by)
    order = _normalize_order(order)
    query = (query or "").strip().lower()

    valid, full_path, error = validate_path(base_dir, subpath)
    if not valid:
        return {"success": False, "status_code": 400, "error": error}
    if not os.path.exists(full_path):
        return {"success": False, "status_code": 404, "error": "경로를 찾을 수 없습니다"}
    if not os.path.isdir(full_path):
        return {"success": False, "status_code": 400, "error": "폴더가 아닙니다"}

    try:
        dir_mtime = os.path.getmtime(full_path)
    except OSError:
        dir_mtime = 0

    cache_key = (
        os.path.normcase(full_path),
        round(dir_mtime, 3),
        page,
        page_size,
        sort_by,
        order,
        query,
        cache_scope or "",
    )

    cached = _cache_get(cache_key)
    if cached:
        return cached

    items: List[Dict[str, Any]] = []
    try:
        with os.scandir(full_path) as scanner:
            for entry in scanner:
                name = entry.name
                # 숨김 파일/폴더 제외
                if name.startswith("."):
                    continue

                name_lower = name.lower()
                if query and query not in name_lower:
                    continue

                try:
                    stat = entry.stat(follow_symlinks=False)
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    continue

                ext = "" if is_dir else os.path.splitext(name)[1].lower()
                rel_path = os.path.join(subpath, name).replace("\\", "/")
                if access_filter is not None:
                    try:
                        if not access_filter(rel_path, "read"):
                            continue
                    except Exception:
                        continue
                mtime = stat.st_mtime if stat.st_mtime else 0
                size = 0 if is_dir else int(stat.st_size)
                item_type = "folder" if is_dir else get_file_type(ext)

                items.append(
                    {
                        "name": name,
                        "name_lower": name_lower,
                        "path": rel_path,
                        "is_dir": is_dir,
                        "type": item_type,
                        "size": size,
                        "mtime": float(mtime),
                        "ext": ext,
                    }
                )
    except PermissionError:
        return {"success": False, "status_code": 403, "error": "접근 권한이 없습니다"}
    except OSError as exc:
        return {"success": False, "status_code": 500, "error": str(exc)}

    # 폴더 우선 정렬은 항상 유지하고, 폴더/파일 내부 순서만 asc/desc 반영
    reverse = order == "desc"
    folder_items = [item for item in items if item["is_dir"]]
    file_items = [item for item in items if not item["is_dir"]]
    folder_items.sort(key=lambda item: _item_sort_key(sort_by, item), reverse=reverse)
    file_items.sort(key=lambda item: _item_sort_key(sort_by, item), reverse=reverse)
    items = folder_items + file_items

    total_count = len(items)
    total_pages = max(1, math.ceil(total_count / page_size))
    if page > total_pages:
        page = total_pages

    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]

    # 응답 크기 절약: 내부 정렬용 필드 제거
    for item in page_items:
        item.pop("name_lower", None)

    payload = {
        "success": True,
        "path": subpath,
        "items": page_items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_count": total_count,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        },
        "sort": {"by": sort_by, "order": order},
        "query": query,
    }
    _cache_set(cache_key, payload)
    return payload


def to_template_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    공통 목록 item 스키마를 기존 템플릿용 스키마로 변환.
    """
    converted: List[Dict[str, Any]] = []
    for item in items:
        mtime = float(item.get("mtime", 0) or 0)
        is_dir = bool(item.get("is_dir"))
        rel_path = item.get("path", "")
        converted.append(
            {
                "name": item.get("name", ""),
                "type": "folder" if is_dir else item.get("type", "file"),
                "is_dir": is_dir,
                "rel_path": rel_path,
                "href": f"/browse/{rel_path}" if is_dir else f"/download/{rel_path}",
                "size": "" if is_dir else fmt_bytes(int(item.get("size", 0) or 0)),
                "raw_size": int(item.get("size", 0) or 0),
                "raw_mtime": mtime,
                "mod_time": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M") if mtime > 0 else "",
                "ext": item.get("ext", ""),
            }
        )
    return converted
