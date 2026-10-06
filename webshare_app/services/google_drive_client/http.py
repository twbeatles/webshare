"""Authenticated HTTP primitives and streaming transfers."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import http.client
import json
import os
import re
import tempfile
import time
import urllib.error
from typing import Any
from ..cloud_sync_constants import CLOUD_SYNC_RETRY_ATTEMPTS, CloudSyncCancelled, CloudSyncError


# 상태 코드 기반 재시도 분류: 429(rate-limit)와 일시적 408/5xx만 재시도하고,
# 그 외 4xx(잘못된 요청·인증 실패 등)는 즉시 실패한다.
RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 30.0


def _parse_retry_after(value) -> float | None:
    """Parse a Retry-After header value (delay seconds) if usable."""
    if value is None:
        return None
    parsed = str(value).strip()
    if not parsed:
        return None
    try:
        delay = float(parsed)
    except (TypeError, ValueError):
        try:
            from email.utils import parsedate_to_datetime

            retry_at = parsedate_to_datetime(parsed)
        except (TypeError, ValueError):
            return None
        try:
            from datetime import datetime, timezone

            delay = (retry_at - datetime.now(timezone.utc)).total_seconds()
        except Exception:
            return None
    if delay < 0:
        return None
    return min(delay, MAX_RETRY_AFTER_SECONDS)


def _status_from_message(message: str) -> int | None:
    """Legacy fallback: extract an HTTP status embedded in an error message."""
    match = re.search(r"\b([45]\d\d)\b", str(message or ""))
    if not match:
        return None
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return None


def _is_retryable_status(status) -> bool:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return code in RETRYABLE_STATUS_CODES


def _should_retry_error(exc: CloudSyncError) -> bool:
    """Decide retries by status code, not by message substring matching."""
    status = getattr(exc, "status", None)
    if status is None:
        status = _status_from_message(str(exc))
    if status is None:
        return True  # 상태 없는 네트워크 장애(URLError 등)는 일시적 장애로 간주
    return _is_retryable_status(status)


def _retry_delay_seconds(exc: CloudSyncError, attempt: int) -> float:
    """Honor Retry-After when present, else back off linearly."""
    retry_after = getattr(exc, "retry_after", None)
    if retry_after is not None:
        try:
            delay = float(retry_after)
            if delay >= 0:
                return min(delay, MAX_RETRY_AFTER_SECONDS)
        except (TypeError, ValueError):
            pass
    return 0.3 * attempt


class GoogleDriveHttpMixin:
    def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> dict[str, Any]:
        raw, _headers, _status = self._request_response(
            method,
            url,
            params=params,
            json_body=json_body,
            data=data,
            headers=headers,
            authenticated=authenticated,
        )
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _request_bytes(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> bytes:
        raw, _headers, _status = self._request_response(
            method,
            url,
            params=params,
            json_body=json_body,
            data=data,
            headers=headers,
            authenticated=authenticated,
        )
        return raw

    def _request_response(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> tuple[bytes, dict[str, str], int]:
        last_error: Exception | None = None
        for attempt in range(1, CLOUD_SYNC_RETRY_ATTEMPTS + 1):
            self._check_cancelled()
            try:
                return self._request_response_once(
                    method,
                    url,
                    params=params,
                    json_body=json_body,
                    data=data,
                    headers=headers,
                    authenticated=authenticated,
                )
            except CloudSyncCancelled:
                raise
            except CloudSyncError as exc:
                last_error = exc
                if attempt >= CLOUD_SYNC_RETRY_ATTEMPTS or not _should_retry_error(exc):
                    raise
                time.sleep(_retry_delay_seconds(exc, attempt))
        raise last_error or CloudSyncError("google_drive request failed")

    def _request_response_once(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> tuple[bytes, dict[str, str], int]:
        final_url = url
        if params:
            final_url = f"{url}?{urllib.parse.urlencode(params)}"

        request_headers = dict(headers or {})
        payload = data
        if json_body is not None:
            payload = json.dumps(json_body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json; charset=utf-8")

        if authenticated:
            request_headers["Authorization"] = f"Bearer {self._ensure_access_token()}"

        req = urllib.request.Request(final_url, data=payload, headers=request_headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read(), dict(response.headers.items()), int(getattr(response, "status", 200) or 200)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                detail = str(exc)
            raise CloudSyncError(
                f"google_drive request failed: {exc.code} {detail}",
                status=int(exc.code),
                retry_after=_parse_retry_after(exc.headers.get("Retry-After") if exc.headers else None),
            ) from exc
        except urllib.error.URLError as exc:
            raise CloudSyncError(f"google_drive request failed: {exc.reason}") from exc

    def _stream_upload_file(self, upload_url: str, local_path: str, mime_type: str, file_size: int) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(upload_url)
        if parsed.scheme not in {"http", "https"}:
            raise CloudSyncError("google_drive resumable upload url is invalid")

        connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"

        connection = connection_cls(host, port, timeout=120)
        try:
            connection.putrequest("PUT", target)
            connection.putheader("Authorization", f"Bearer {self._ensure_access_token()}")
            connection.putheader("Content-Length", str(max(0, int(file_size or 0))))
            connection.putheader("Content-Type", mime_type)
            connection.endheaders()

            with open(local_path, "rb") as handle:
                while True:
                    self._check_cancelled()
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    connection.send(chunk)

            response = connection.getresponse()
            body = response.read()
            if response.status not in {200, 201}:
                detail = body.decode("utf-8", errors="ignore") if body else ""
                raise CloudSyncError(
                f"google_drive upload failed: {response.status} {detail}".strip(),
                status=int(response.status),
            )
            return json.loads(body.decode("utf-8")) if body else {}
        except CloudSyncError:
            raise
        except Exception as exc:
            raise CloudSyncError(f"google_drive upload failed: {exc}") from exc
        finally:
            connection.close()

    def _stream_download_to_file(
        self,
        method: str,
        url: str,
        *,
        target_path: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> None:
        final_url = url
        if params:
            final_url = f"{url}?{urllib.parse.urlencode(params)}"

        request_headers = dict(headers or {})
        if authenticated:
            request_headers["Authorization"] = f"Bearer {self._ensure_access_token()}"

        directory = os.path.dirname(target_path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".webshare_dl_", suffix=".tmp")

        req = urllib.request.Request(final_url, headers=request_headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=120) as response, os.fdopen(fd, "wb") as handle:
                while True:
                    self._check_cancelled()
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
            os.replace(temp_path, target_path)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                detail = str(exc)
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise CloudSyncError(
                f"google_drive request failed: {exc.code} {detail}",
                status=int(exc.code),
                retry_after=_parse_retry_after(exc.headers.get("Retry-After") if exc.headers else None),
            ) from exc
        except urllib.error.URLError as exc:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise CloudSyncError(f"google_drive request failed: {exc.reason}") from exc
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

