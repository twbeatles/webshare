"""
WebShare Pro - Network Routes
Manual UPnP status/map/unmap endpoints.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, session

from config import conf
from features.audit_log import log_audit
from features.network import UPnPError, get_upnp_status, map_upnp_port, unmap_upnp_port
from security.auth import login_required
from utils.file_utils import get_real_ip


network_bp = Blueprint("network", __name__)


def _current_port() -> int:
    return int(conf.get("port", 5000) or 5000)


@network_bp.route("/api/network/upnp/status", methods=["GET"])
@login_required("admin")
def upnp_status():
    status = get_upnp_status(_current_port())
    return jsonify({"success": not status.get("error"), "upnp": status})


@network_bp.route("/api/network/upnp/map", methods=["POST"])
@login_required("admin")
def upnp_map():
    try:
        status = map_upnp_port(_current_port())
    except UPnPError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    log_audit(
        session.get("role", "admin"),
        "upnp_map",
        str(status.get("port", _current_port())),
        status.get("external_ip", ""),
        ip=get_real_ip(),
    )
    return jsonify({"success": True, "upnp": status})


@network_bp.route("/api/network/upnp/unmap", methods=["POST"])
@login_required("admin")
def upnp_unmap():
    try:
        status = unmap_upnp_port(_current_port())
    except UPnPError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    log_audit(
        session.get("role", "admin"),
        "upnp_unmap",
        str(_current_port()),
        "removed",
        ip=get_real_ip(),
    )
    return jsonify({"success": True, "upnp": status})
