"""Shared constructor/config/cancellation base for the Drive mixins."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
from typing import Any, Callable
from ..cloud_sync_config import _copy_provider_config
from ..cloud_sync_constants import CLOUD_SYNC_CONFLICT_POLICY, CloudSyncCancelled, normalize_cloud_conflict_policy


class GoogleDriveBase:
    def __init__(self, conflict_policy: str = CLOUD_SYNC_CONFLICT_POLICY, should_cancel: Callable[[], bool] | None = None):
        self.provider = "google_drive"
        self.conflict_policy = normalize_cloud_conflict_policy(conflict_policy)
        self.should_cancel = should_cancel or (lambda: False)

    def _config(self) -> dict[str, Any]:
        return _copy_provider_config(self.provider)

    def _check_cancelled(self):
        if self.should_cancel():
            raise CloudSyncCancelled("cloud sync cancelled")

