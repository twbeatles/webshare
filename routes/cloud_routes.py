"""
WebShare Pro - Cloud Routes
Google Drive OAuth + manual sync jobs, Dropbox placeholder.
"""

from __future__ import annotations

import os
import uuid

from flask import Blueprint, Response, jsonify, redirect, request, session, url_for

from config import CLOUD_SYNC_CONFIG, cloud_sync_lock, conf
from features.audit_log import log_audit
from features.cloud_sync import (
    CLOUD_SYNC_CONFLICT_POLICY,
    CloudSyncError,
    GoogleDriveClient,
    get_cloud_job,
    get_provider_last_job,
    start_google_drive_job,
    update_cloud_provider,
)
from security.auth import login_required
from utils.file_utils import get_real_ip, validate_path
from utils.request_policy import parse_json_body

cloud_bp = Blueprint("cloud", __name__)

GOOGLE_PROVIDER = "google_drive"
DROPBOX_PROVIDER = "dropbox"
GOOGLE_OAUTH_STATE_KEY = "cloud_google_drive_oauth_state"
DROPBOX_PLACEHOLDER_MESSAGE = "Dropbox integration is not implemented yet."


def _copy_cloud_config() -> dict:
    with cloud_sync_lock:
        return {provider: dict(cfg) for provider, cfg in CLOUD_SYNC_CONFIG.items()}


def _safe_provider_config(provider: str, cfg: dict) -> dict:
    if provider == GOOGLE_PROVIDER:
        return {
            "implementation": "google_drive",
            "supported": True,
            "visible": True,
            "conflict_policy": CLOUD_SYNC_CONFLICT_POLICY,
            "job_persisted": True,
            "enabled": bool(cfg.get("enabled", False)),
            "client_id": cfg.get("client_id", ""),
            "client_secret_configured": bool(cfg.get("client_secret")),
            "folder_id": cfg.get("folder_id", ""),
            "configured": bool(cfg.get("client_id")) and bool(cfg.get("client_secret")),
            "connected": isinstance(cfg.get("token"), dict) and bool(
                cfg.get("token", {}).get("access_token") or cfg.get("token", {}).get("refresh_token")
            ),
            "last_sync": cfg.get("last_sync"),
            "last_job_id": cfg.get("last_job_id", ""),
        }

    return {
        "implementation": "placeholder",
        "supported": False,
        "visible": False,
        "conflict_policy": CLOUD_SYNC_CONFLICT_POLICY,
        "job_persisted": True,
        "enabled": bool(cfg.get("enabled", False)),
        "app_key": cfg.get("app_key", ""),
        "app_secret_configured": bool(cfg.get("app_secret")),
        "folder_id": cfg.get("folder_id", ""),
        "configured": bool(cfg.get("app_key")) and bool(cfg.get("app_secret")),
        "connected": False,
        "last_sync": cfg.get("last_sync"),
        "last_job_id": cfg.get("last_job_id", ""),
        "message": DROPBOX_PLACEHOLDER_MESSAGE,
    }


def _provider_status(provider: str, cfg: dict) -> dict:
    safe = _safe_provider_config(provider, cfg)
    last_job_id = safe.get("last_job_id", "")
    last_job = get_cloud_job(last_job_id) if last_job_id else None
    if last_job is None:
        last_job = get_provider_last_job(provider)

    if provider == GOOGLE_PROVIDER:
        state = str(last_job.get("state", "idle")) if last_job else "idle"
        return {
            **safe,
            "provider": provider,
            "state": state,
            "last_job": last_job,
            "error": last_job.get("error") if last_job else None,
            "progress": int(last_job.get("progress", 0)) if last_job else 0,
        }

    return {
        **safe,
        "provider": provider,
        "state": "not_implemented",
        "last_job": last_job,
        "error": None,
        "progress": 0,
    }


def _google_redirect_uri() -> str:
    return url_for("cloud.google_drive_auth_callback", _external=True)


def _popup_result_page(success: bool, message: str) -> Response:
    escaped = (
        str(message or "")
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    status = "success" if success else "error"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WebShare Cloud</title>
</head>
<body style="font-family:sans-serif;padding:24px;">
  <p>{message}</p>
  <script>
    (function() {{
      try {{
        if (window.opener && !window.opener.closed) {{
          window.opener.postMessage({{ type: 'webshare-cloud-auth', provider: 'google_drive', status: '{status}', message: '{escaped}' }}, window.location.origin);
        }}
      }} catch (err) {{}}
      setTimeout(function() {{
        try {{ window.close(); }} catch (err) {{}}
      }}, 150);
    }})();
  </script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@cloud_bp.route("/api/cloud/config", methods=["GET", "POST"])
@login_required("admin")
def cloud_config():
    if request.method == "GET":
        config_snapshot = _copy_cloud_config()
        safe_config = {
            provider: _safe_provider_config(provider, cfg)
            for provider, cfg in config_snapshot.items()
        }
        return jsonify({"config": safe_config})

    data = parse_json_body(request)
    provider = str(data.get("provider", "") or "")
    if provider not in CLOUD_SYNC_CONFIG:
        return jsonify({"success": False, "error": "지원하지 않는 클라우드 서비스입니다."}), 400

    if provider == GOOGLE_PROVIDER:
        updates = {
            "enabled": bool(data.get("enabled", False)),
            "client_id": str(data.get("client_id", "") or "").strip(),
            "client_secret": str(data.get("client_secret", "") or "").strip(),
            "folder_id": str(data.get("folder_id", "") or "").strip(),
        }
    else:
        updates = {
            "enabled": bool(data.get("enabled", False)),
            "app_key": str(data.get("app_key", data.get("client_id", "")) or "").strip(),
            "app_secret": str(data.get("app_secret", data.get("client_secret", "")) or "").strip(),
            "folder_id": str(data.get("folder_id", "") or "").strip(),
        }

    snapshot = update_cloud_provider(provider, updates)
    log_audit(
        session.get("role", "admin"),
        "cloud_config",
        provider,
        "updated",
        ip=get_real_ip(),
    )
    return jsonify({"success": True, "config": _safe_provider_config(provider, snapshot)})


@cloud_bp.route("/api/cloud/status", methods=["GET"])
@login_required("admin")
def cloud_status():
    config_snapshot = _copy_cloud_config()
    status = {
        provider: _provider_status(provider, cfg)
        for provider, cfg in config_snapshot.items()
    }
    return jsonify({"status": status})


@cloud_bp.route("/api/cloud/google_drive/auth/start", methods=["GET"])
@login_required("admin")
def google_drive_auth_start():
    state = uuid.uuid4().hex
    session[GOOGLE_OAUTH_STATE_KEY] = state

    try:
        client = GoogleDriveClient()
        auth_url = client.build_auth_url(_google_redirect_uri(), state)
    except CloudSyncError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    return redirect(auth_url)


@cloud_bp.route("/api/cloud/google_drive/auth/callback", methods=["GET"])
@login_required("admin")
def google_drive_auth_callback():
    error = str(request.args.get("error", "") or "")
    if error:
        return _popup_result_page(False, f"Google Drive authorization failed: {error}")

    state = str(request.args.get("state", "") or "")
    expected = str(session.pop(GOOGLE_OAUTH_STATE_KEY, "") or "")
    if not state or state != expected:
        return _popup_result_page(False, "Google Drive authorization state mismatch.")

    code = str(request.args.get("code", "") or "")
    if not code:
        return _popup_result_page(False, "Google Drive authorization code is missing.")

    try:
        client = GoogleDriveClient()
        client.exchange_code(code, _google_redirect_uri())
        log_audit(
            session.get("role", "admin"),
            "cloud_connect",
            GOOGLE_PROVIDER,
            "connected",
            ip=get_real_ip(),
        )
        return _popup_result_page(True, "Google Drive connected successfully.")
    except CloudSyncError as exc:
        return _popup_result_page(False, str(exc))


@cloud_bp.route("/api/cloud/google_drive/disconnect", methods=["POST"])
@login_required("admin")
def google_drive_disconnect():
    try:
        GoogleDriveClient().disconnect()
    except CloudSyncError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    log_audit(
        session.get("role", "admin"),
        "cloud_disconnect",
        GOOGLE_PROVIDER,
        "disconnected",
        ip=get_real_ip(),
    )
    return jsonify({"success": True})


@cloud_bp.route("/api/cloud/jobs/<job_id>", methods=["GET"])
@login_required("admin")
def cloud_job_status(job_id):
    job = get_cloud_job(job_id)
    if not job:
        return jsonify({"success": False, "error": "작업을 찾을 수 없습니다."}), 404
    return jsonify({"success": True, "job": job})


@cloud_bp.route("/api/cloud/sync/<provider>", methods=["POST"])
@login_required("admin")
def cloud_sync(provider):
    if provider not in CLOUD_SYNC_CONFIG:
        return jsonify({"success": False, "error": "지원하지 않는 클라우드 서비스입니다."}), 400

    if provider == DROPBOX_PROVIDER:
        return (
            jsonify(
                {
                    "success": False,
                    "provider": provider,
                    "implementation": "placeholder",
                    "error": DROPBOX_PLACEHOLDER_MESSAGE,
                }
            ),
            501,
        )

    data = parse_json_body(request)
    sync_path = str(data.get("path", "") or "").strip("/")
    direction = str(data.get("direction", "upload") or "upload").strip().lower()
    if direction not in {"upload", "download"}:
        return jsonify({"success": False, "error": "direction은 upload 또는 download여야 합니다."}), 400

    valid, abs_path, error = validate_path(conf.get("folder"), sync_path)
    if not valid:
        return jsonify({"success": False, "error": error}), 400

    if direction == "upload" and not os.path.exists(abs_path):
        return jsonify({"success": False, "error": "동기화할 로컬 경로를 찾을 수 없습니다."}), 404

    if direction == "download" and os.path.exists(abs_path) and not os.path.isdir(abs_path):
        return jsonify({"success": False, "error": "다운로드 대상 경로는 디렉터리여야 합니다."}), 400

    try:
        job = start_google_drive_job(direction, abs_path, sync_path)
    except CloudSyncError as exc:
        return jsonify({"success": False, "error": str(exc)}), 409

    log_audit(
        session.get("role", "admin"),
        "cloud_sync",
        sync_path,
        f"{provider}:{direction}:{job['job_id']}",
        ip=get_real_ip(),
    )
    return jsonify({"success": True, "job": job}), 202
