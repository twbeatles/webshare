"""
WebShare Pro - Network Utilities
Manual UPnP status/map/unmap helpers.
"""

from __future__ import annotations

import importlib
import socket
from typing import Any

from utils.log_manager import logger


UPNP_PROTOCOL = "TCP"
UPNP_DESCRIPTION = "WebShare Pro"


class UPnPError(RuntimeError):
    """Recoverable UPnP error."""


def _load_miniupnpc():
    try:
        return importlib.import_module("miniupnpc")
    except ImportError:
        return None


def _build_status(
    *,
    port: int,
    available: bool,
    library_installed: bool,
    supported: bool,
    mapped: bool = False,
    external_ip: str = "",
    internal_ip: str = "",
    description: str = UPNP_DESCRIPTION,
    error: str = "",
) -> dict[str, Any]:
    return {
        "available": available,
        "library_installed": library_installed,
        "supported": supported,
        "mapped": mapped,
        "external_ip": external_ip,
        "internal_ip": internal_ip,
        "port": int(port),
        "protocol": UPNP_PROTOCOL,
        "description": description,
        "error": error,
    }


def _parse_mapping(mapping: Any) -> tuple[str, int, str]:
    if isinstance(mapping, dict):
        internal_ip = str(mapping.get("internalClient") or mapping.get("host") or "")
        try:
            internal_port = int(mapping.get("internalPort") or mapping.get("port") or 0)
        except (TypeError, ValueError):
            internal_port = 0
        description = str(mapping.get("description") or mapping.get("desc") or "")
        return internal_ip, internal_port, description

    if isinstance(mapping, (list, tuple)):
        internal_ip = str(mapping[0] if len(mapping) > 0 else "")
        try:
            internal_port = int(mapping[1] if len(mapping) > 1 else 0)
        except (TypeError, ValueError):
            internal_port = 0
        description = str(mapping[2] if len(mapping) > 2 else "")
        return internal_ip, internal_port, description

    return "", 0, ""


def _connect_upnp():
    miniupnpc = _load_miniupnpc()
    if miniupnpc is None:
        raise UPnPError("miniupnpc library not installed")

    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200
        found = int(upnp.discover() or 0)
        if found <= 0:
            raise UPnPError("No UPnP devices found")
        upnp.selectigd()
        return upnp
    except UPnPError:
        raise
    except Exception as exc:
        raise UPnPError(str(exc)) from exc


def get_local_ip():
    """로컬 IP 주소 반환"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        sock.close()


def get_upnp_status(port: int) -> dict[str, Any]:
    miniupnpc = _load_miniupnpc()
    if miniupnpc is None:
        return _build_status(
            port=port,
            available=False,
            library_installed=False,
            supported=False,
            error="miniupnpc library not installed",
        )

    try:
        upnp = _connect_upnp()
        external_ip = str(upnp.externalipaddress() or "")
        mapping = upnp.getspecificportmapping(int(port), UPNP_PROTOCOL)
        internal_ip, internal_port, description = _parse_mapping(mapping)
        return _build_status(
            port=internal_port or port,
            available=True,
            library_installed=True,
            supported=True,
            mapped=bool(mapping),
            external_ip=external_ip,
            internal_ip=internal_ip or str(getattr(upnp, "lanaddr", "") or ""),
            description=description or UPNP_DESCRIPTION,
        )
    except UPnPError as exc:
        return _build_status(
            port=port,
            available=False,
            library_installed=True,
            supported=False,
            error=str(exc),
        )


def map_upnp_port(port: int) -> dict[str, Any]:
    upnp = _connect_upnp()
    external_ip = str(upnp.externalipaddress() or "")
    try:
        added = upnp.addportmapping(int(port), UPNP_PROTOCOL, upnp.lanaddr, int(port), UPNP_DESCRIPTION, "")
    except Exception as exc:
        raise UPnPError(str(exc)) from exc

    if added is False:
        raise UPnPError("UPnP port mapping request was rejected")

    logger.add(f"UPnP 포트 매핑 완료: {external_ip}:{port} -> {upnp.lanaddr}:{port}")
    return get_upnp_status(int(port))


def unmap_upnp_port(port: int) -> dict[str, Any]:
    upnp = _connect_upnp()
    try:
        removed = upnp.deleteportmapping(int(port), UPNP_PROTOCOL)
    except Exception as exc:
        raise UPnPError(str(exc)) from exc

    if removed is False:
        raise UPnPError("UPnP port unmap request was rejected")

    logger.add(f"UPnP 포트 매핑 해제: {port}/{UPNP_PROTOCOL}")
    return get_upnp_status(int(port))


def setup_upnp(port):
    """Legacy compatibility wrapper for manual mapping."""
    try:
        status = map_upnp_port(int(port))
        return True, f"Port {status['port']} mapped successfully on {status.get('external_ip', '')}"
    except UPnPError as exc:
        logger.add(f"UPnP 설정 실패: {exc}", "ERROR")
        return False, str(exc)
