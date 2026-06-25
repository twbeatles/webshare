"""Cloud sync public config and secret persistence."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from config import CLOUD_SYNC_CONFIG, CLOUD_SYNC_FILE, cloud_sync_lock, conf
from utils.app_paths import atomic_write_json, get_app_config_dir
from utils.log_manager import logger

from .cloud_sync_constants import CLOUD_SECRET_KEYS, CloudSyncError


def _copy_provider_config(provider: str) -> dict[str, Any]:
    with cloud_sync_lock:
        return dict(CLOUD_SYNC_CONFIG.get(provider, {}))


def update_cloud_provider(provider: str, updates: dict[str, Any]) -> dict[str, Any]:
    with cloud_sync_lock:
        if provider not in CLOUD_SYNC_CONFIG:
            raise CloudSyncError("unsupported provider")
        CLOUD_SYNC_CONFIG[provider].update(updates)
        snapshot = dict(CLOUD_SYNC_CONFIG[provider])
    save_cloud_config()
    return snapshot


def get_cloud_secrets_path() -> str:
    return os.path.join(get_app_config_dir(), "secrets", "cloud_secrets.json")


def _split_cloud_config_payload(snapshot: dict[str, dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    public_payload: dict[str, dict[str, Any]] = {}
    secret_payload: dict[str, dict[str, Any]] = {}
    for provider, cfg in snapshot.items():
        public_payload[provider] = {
            key: value
            for key, value in cfg.items()
            if key not in CLOUD_SECRET_KEYS
        }
        secrets_for_provider = {
            key: value
            for key, value in cfg.items()
            if key in CLOUD_SECRET_KEYS and value
        }
        if secrets_for_provider:
            secret_payload[provider] = secrets_for_provider
    return public_payload, secret_payload


def _legacy_save_cloud_config():
    return save_cloud_config()
    """클라우드 설정 저장 (스레드 안전, 원자적 쓰기)."""
    base_dir = conf.get("folder")
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)

    with cloud_sync_lock:
        payload = {}
        for provider, cfg in CLOUD_SYNC_CONFIG.items():
            payload[provider] = dict(cfg)

    try:
        fd, temp_path = tempfile.mkstemp(dir=base_dir, prefix=".webshare_cloud_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            os.replace(temp_path, cloud_path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
    except Exception as exc:
        logger.add(f"클라우드 설정 저장 실패: {exc}", "ERROR")


def _legacy_shared_load_cloud_config():
    """클라우드 설정 로드 (스레드 안전)."""
    base_dir = conf.get("folder")
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)

    if not os.path.exists(cloud_path):
        return

    with cloud_sync_lock:
        try:
            with open(cloud_path, "r", encoding="utf-8") as handle:
                saved = json.load(handle)

            for provider, cfg in saved.items():
                if provider in CLOUD_SYNC_CONFIG and isinstance(cfg, dict):
                    CLOUD_SYNC_CONFIG[provider].update(cfg)

            logger.add("클라우드 설정 로드 완료")
        except Exception as exc:
            logger.add(f"클라우드 설정 로드 실패: {exc}", "ERROR")


def save_cloud_config():
    """Save public cloud state in the shared folder and secrets outside it."""
    base_dir = conf.get("folder")
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)
    secret_path = get_cloud_secrets_path()

    def _build_public_payload():
        snapshot = {provider: dict(cfg) for provider, cfg in CLOUD_SYNC_CONFIG.items()}
        public_payload, _secrets = _split_cloud_config_payload(snapshot)
        return public_payload

    def _build_secret_payload():
        snapshot = {provider: dict(cfg) for provider, cfg in CLOUD_SYNC_CONFIG.items()}
        _public, secret_payload = _split_cloud_config_payload(snapshot)
        return secret_payload

    try:
        from webshare_app.core.persistence import persist_json_snapshot

        persist_json_snapshot("cloud_config_public", cloud_path, cloud_sync_lock, _build_public_payload)
        persist_json_snapshot("cloud_config_secrets", secret_path, cloud_sync_lock, _build_secret_payload)
    except Exception as exc:
        logger.add(f"cloud config save failed: {exc}", "ERROR")


def load_cloud_config():
    """Load cloud config, migrating legacy shared-folder secrets when present."""
    base_dir = conf.get("folder")
    cloud_path = os.path.join(base_dir, CLOUD_SYNC_FILE)
    legacy_secrets_found = False
    try:
        if os.path.exists(cloud_path):
            with open(cloud_path, "r", encoding="utf-8") as handle:
                saved = json.load(handle)
            if isinstance(saved, dict):
                with cloud_sync_lock:
                    for provider, cfg in saved.items():
                        if provider in CLOUD_SYNC_CONFIG and isinstance(cfg, dict):
                            legacy_secrets_found = legacy_secrets_found or any(key in cfg for key in CLOUD_SECRET_KEYS)
                            CLOUD_SYNC_CONFIG[provider].update(dict(cfg))

        secret_path = get_cloud_secrets_path()
        if os.path.exists(secret_path):
            with open(secret_path, "r", encoding="utf-8") as handle:
                secrets_payload = json.load(handle)
            if isinstance(secrets_payload, dict):
                with cloud_sync_lock:
                    for provider, cfg in secrets_payload.items():
                        if provider in CLOUD_SYNC_CONFIG and isinstance(cfg, dict):
                            CLOUD_SYNC_CONFIG[provider].update({
                                key: value
                                for key, value in cfg.items()
                                if key in CLOUD_SECRET_KEYS
                            })

        if legacy_secrets_found:
            save_cloud_config()
        logger.add("cloud config loaded")
    except Exception as exc:
        logger.add(f"cloud config load failed: {exc}", "ERROR")
