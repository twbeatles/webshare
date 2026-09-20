"""OAuth connect, token storage, and refresh."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import urllib.error
from datetime import datetime, timedelta
from typing import Any
from ..cloud_sync_config import update_cloud_provider
from ..cloud_sync_constants import GOOGLE_DRIVE_SCOPE, GOOGLE_OAUTH_AUTHORIZE_URL, GOOGLE_OAUTH_TOKEN_URL, CloudSyncError, _utc_now


class GoogleDriveAuthMixin:
    def is_connected(self) -> bool:
        token = self._config().get("token")
        return isinstance(token, dict) and bool(token.get("access_token") or token.get("refresh_token"))

    def build_auth_url(self, redirect_uri: str, state: str) -> str:
        cfg = self._config()
        client_id = cfg.get("client_id", "")
        if not client_id:
            raise CloudSyncError("google_drive client_id is not configured")

        query = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": GOOGLE_DRIVE_SCOPE,
                "access_type": "offline",
                "prompt": "consent",
                "state": state,
            }
        )
        return f"{GOOGLE_OAUTH_AUTHORIZE_URL}?{query}"

    def exchange_code(self, code: str, redirect_uri: str) -> dict[str, Any]:
        cfg = self._config()
        client_id = cfg.get("client_id", "")
        client_secret = cfg.get("client_secret", "")
        if not client_id or not client_secret:
            raise CloudSyncError("google_drive credentials are incomplete")

        payload = urllib.parse.urlencode(
            {
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
        ).encode("utf-8")

        token = self._request_json(
            "POST",
            GOOGLE_OAUTH_TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            authenticated=False,
        )
        self._store_token_bundle(token)
        return token

    def disconnect(self):
        update_cloud_provider(self.provider, {"token": None, "last_job_id": ""})

    def _token(self) -> dict[str, Any]:
        cfg = self._config()
        token = cfg.get("token")
        if not isinstance(token, dict):
            raise CloudSyncError("google_drive is not connected")
        return dict(token)

    def _store_token_bundle(self, token_payload: dict[str, Any]):
        token = dict(token_payload)
        expires_in = int(token.get("expires_in", 3600) or 3600)
        token["expires_at"] = (_utc_now() + timedelta(seconds=expires_in - 30)).isoformat()

        old_token = self._config().get("token")
        if isinstance(old_token, dict) and not token.get("refresh_token"):
            token["refresh_token"] = old_token.get("refresh_token")

        update_cloud_provider(self.provider, {"token": token})

    def _ensure_access_token(self) -> str:
        token = self._token()
        expires_at = token.get("expires_at")
        if expires_at:
            try:
                expires_dt = datetime.fromisoformat(str(expires_at))
            except Exception:
                expires_dt = _utc_now() - timedelta(seconds=1)
            if expires_dt <= _utc_now():
                token = self._refresh_access_token(token)

        access_token = str(token.get("access_token", "") or "")
        if not access_token:
            raise CloudSyncError("google_drive access token is missing")
        return access_token

    def _refresh_access_token(self, token: dict[str, Any]) -> dict[str, Any]:
        refresh_token = str(token.get("refresh_token", "") or "")
        cfg = self._config()
        if not refresh_token:
            raise CloudSyncError("google_drive refresh token is missing")

        payload = urllib.parse.urlencode(
            {
                "client_id": cfg.get("client_id", ""),
                "client_secret": cfg.get("client_secret", ""),
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
        ).encode("utf-8")
        refreshed = self._request_json(
            "POST",
            GOOGLE_OAUTH_TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            authenticated=False,
        )
        if "refresh_token" not in refreshed:
            refreshed["refresh_token"] = refresh_token
        self._store_token_bundle(refreshed)
        return refreshed

