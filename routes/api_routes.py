"""
WebShare Pro - API Routes
REST API 엔드포인트
"""

import os
from datetime import datetime

from flask import Blueprint, jsonify, request

from config import ACTIVE_SESSIONS, RECENT_FILES, conf, recent_files_lock, session_lock
from features.trash import auto_cleanup_trash
from security.auth import login_required
from security.ip_blocker import get_blocked_ips, unblock_ip
from utils.dashboard_service import (
    get_dashboard_summary_payload,
    get_disk_payload,
    get_metrics_payload,
)
from utils.file_utils import fmt_bytes, get_folder_size
from utils.listing import list_directory_page
from utils.log_manager import logger
from utils.request_policy import ensure_path_access

api_bp = Blueprint("api", __name__)


@api_bp.route("/metrics")
@login_required()
def metrics():
    """서버 통계"""
    return jsonify(get_metrics_payload())


@api_bp.route("/disk_info")
@login_required()
def disk_info():
    """디스크 정보"""
    try:
        disk = get_disk_payload()
        return jsonify(
            {
                "total": disk["total"],
                "used": disk["used"],
                "free": disk["free"],
                "percent": disk["percent"],
                "warning": disk["warning"],
                "total_fmt": disk["total_fmt"],
                "used_fmt": disk["used_fmt"],
                "free_fmt": disk["free_fmt"],
            }
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/disk_status")
@login_required()
def disk_status():
    """디스크 경고 상태"""
    try:
        disk = get_disk_payload()
        return jsonify(
            {
                "percent": disk["percent"],
                "free": disk["free"],
                "warning": disk["warning"],
                "threshold": disk["threshold"],
            }
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/dashboard/summary")
@login_required()
def dashboard_summary():
    """대시보드 통합 요약 (metrics + disk + status)"""
    try:
        return jsonify(get_dashboard_summary_payload())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/indexer/status")
@login_required("admin")
def indexer_status():
    """검색 인덱서 상태"""
    from features.search_indexer import indexer

    return jsonify(indexer.get_status())


@api_bp.route("/list/", defaults={"subpath": ""})
@api_bp.route("/list/<path:subpath>")
@login_required()
def list_directory(subpath: str):
    """페이지네이션 디렉토리 목록 API"""
    ok, message, status_code = ensure_path_access(subpath, "read")
    if not ok:
        return jsonify({"error": message}), status_code

    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=200, type=int)
    sort_by = request.args.get("sort", default="name", type=str)
    order = request.args.get("order", default="asc", type=str)
    query = request.args.get("q", default="", type=str)

    payload = list_directory_page(
        base_dir=conf.get("folder"),
        subpath=subpath,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        order=order,
        query=query,
    )
    if not payload.get("success"):
        return jsonify({"error": payload.get("error", "알 수 없는 오류")}), payload.get("status_code", 500)
    return jsonify(payload)


@api_bp.route("/active_sessions")
@login_required()
def active_sessions():
    """활성 세션 목록"""
    now = datetime.now()
    sessions = []

    with session_lock:
        for _, info in ACTIVE_SESSIONS.items():
            last_active = info.get("last_active", info.get("login_time"))
            if isinstance(last_active, str):
                try:
                    last_active = datetime.fromisoformat(last_active)
                except ValueError:
                    last_active = now

            idle_minutes = int((now - last_active).total_seconds() / 60)
            sessions.append(
                {
                    "ip": info.get("ip", "unknown"),
                    "role": info.get("role", "guest"),
                    "idle_minutes": idle_minutes,
                }
            )

    return jsonify({"count": len(sessions), "sessions": sessions})


@api_bp.route("/recent_files")
@login_required()
def recent_files():
    """최근 파일 목록"""
    with recent_files_lock:
        files = list(RECENT_FILES[:20])
    return jsonify({"files": files})


@api_bp.route("/blocked_ips")
@login_required("admin")
def blocked_ips():
    """차단된 IP 목록"""
    return jsonify({"blocked": get_blocked_ips()})


@api_bp.route("/unblock/<ip>", methods=["POST"])
@login_required("admin")
def unblock(ip):
    """IP 차단 해제"""
    success = unblock_ip(ip)
    if success:
        logger.add(f"IP 차단 해제: {ip}")
        return jsonify({"success": True})
    return jsonify({"error": "IP를 찾을 수 없습니다"}), 404


@api_bp.route("/folder_size/<path:folderpath>")
@login_required()
def folder_size(folderpath):
    """폴더 크기 계산"""
    from utils.file_utils import validate_path

    ok, message, status_code = ensure_path_access(folderpath, "read")
    if not ok:
        return jsonify({"error": message}), status_code

    base_dir = conf.get("folder")
    valid, full_path, error = validate_path(base_dir, folderpath)
    if not valid:
        return jsonify({"error": error}), 400
    if not os.path.isdir(full_path):
        return jsonify({"error": "폴더가 아닙니다"}), 400

    size = get_folder_size(full_path)
    return jsonify({"path": folderpath, "size": size, "size_fmt": fmt_bytes(size)})


@api_bp.route("/trash/cleanup", methods=["POST"])
@login_required("admin")
def trash_cleanup():
    """휴지통 정리"""
    deleted = auto_cleanup_trash()
    return jsonify({"success": True, "deleted": deleted})
