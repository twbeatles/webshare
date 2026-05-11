"""Cloud sync constants, errors, and normalization helpers."""

from datetime import datetime, timezone

GOOGLE_DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"
GOOGLE_DRIVE_FILES_API = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files"
GOOGLE_OAUTH_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
CLOUD_SYNC_JOB_KIND = "cloud_sync"
CLOUD_SYNC_CONFLICT_POLICY = "skip"
CLOUD_SYNC_CONFLICT_POLICIES = {"skip", "rename", "overwrite", "dry_run"}
CLOUD_SYNC_RETRY_ATTEMPTS = 3
CLOUD_SECRET_KEYS = {"client_secret", "token", "app_secret"}


class CloudSyncError(RuntimeError):
    """Recoverable cloud sync error."""


class CloudSyncCancelled(CloudSyncError):
    """Cloud sync job was cancelled."""


def normalize_cloud_conflict_policy(value: str | None) -> str:
    policy = str(value or CLOUD_SYNC_CONFLICT_POLICY).strip().lower()
    return policy if policy in CLOUD_SYNC_CONFLICT_POLICIES else CLOUD_SYNC_CONFLICT_POLICY


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()
