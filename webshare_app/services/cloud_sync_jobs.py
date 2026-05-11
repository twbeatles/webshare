"""Cloud sync job orchestration."""

from __future__ import annotations

import os
import threading
from typing import Any

from features.job_store import (
    create_job,
    get_active_job,
    get_job,
    get_last_job,
    load_jobs,
    mark_incomplete_jobs,
    reset_jobs_runtime_state,
    update_job,
)
from utils.log_manager import logger

from .cloud_sync_config import _copy_provider_config, update_cloud_provider
from .cloud_sync_constants import (
    CLOUD_SYNC_CONFLICT_POLICY,
    CLOUD_SYNC_JOB_KIND,
    CloudSyncCancelled,
    CloudSyncError,
    _utc_now_iso,
    normalize_cloud_conflict_policy,
)
from .google_drive_client import GoogleDriveClient


def load_cloud_runtime_state():
    load_jobs()
    mark_incomplete_jobs(
        kind=CLOUD_SYNC_JOB_KIND,
        state="failed",
        error="cloud sync interrupted by restart",
    )


def get_cloud_job(job_id: str) -> dict[str, Any] | None:
    job = get_job(job_id)
    if not job or job.get("kind") != CLOUD_SYNC_JOB_KIND:
        return None
    return job


def get_provider_last_job(provider: str) -> dict[str, Any] | None:
    return get_last_job(kind=CLOUD_SYNC_JOB_KIND, scope=provider)


def reset_cloud_sync_runtime_state():
    reset_jobs_runtime_state(kind=CLOUD_SYNC_JOB_KIND)


def _set_job_state(job_id: str, *, persist: bool = False, **updates: Any) -> dict[str, Any]:
    snapshot = update_job(job_id, persist=persist, **updates)
    if snapshot is None:
        raise CloudSyncError("job not found")
    return snapshot


def create_cloud_job(provider: str, direction: str, path: str, conflict_policy: str = CLOUD_SYNC_CONFLICT_POLICY) -> dict[str, Any]:
    active_job = get_active_job(kind=CLOUD_SYNC_JOB_KIND, scope=provider)
    if active_job and active_job.get("state") in {"accepted", "running"}:
        raise CloudSyncError("provider already has an active sync job")

    normalized_policy = normalize_cloud_conflict_policy(conflict_policy)
    job = create_job(
        CLOUD_SYNC_JOB_KIND,
        provider,
        provider=provider,
        path=path,
        direction=direction,
        state="accepted",
        progress=0,
        error=None,
        started_at=None,
        finished_at=None,
        supported=(provider == "google_drive"),
        visible=(provider == "google_drive"),
        conflict_policy=normalized_policy,
        cancel_requested=False,
        job_persisted=True,
        stats={"files": 0, "uploaded": 0, "downloaded": 0, "skipped": 0, "renamed": 0, "overwritten": 0, "dry_run": 0},
    )
    job_id = str(job.get("job_id", "") or "")
    update_cloud_provider(provider, {"last_job_id": job_id})
    return dict(job)


def _finish_cloud_job(job_id: str, provider: str, *, state: str, error: str | None = None, progress: int = 100, stats: dict[str, Any] | None = None):
    default_stats = {"files": 0, "uploaded": 0, "downloaded": 0, "skipped": 0, "renamed": 0, "overwritten": 0, "dry_run": 0}
    if stats:
        default_stats.update(stats)
    _set_job_state(
        job_id,
        persist=True,
        state=state,
        error=error,
        progress=max(0, min(100, int(progress))),
        finished_at=_utc_now_iso(),
        stats=default_stats,
    )
    updates = {"last_job_id": job_id}
    if state == "completed":
        updates["last_sync"] = _utc_now_iso()
    update_cloud_provider(provider, updates)


def cancel_cloud_job(job_id: str) -> dict[str, Any]:
    job = get_cloud_job(job_id)
    if not job:
        raise CloudSyncError("job not found")
    if job.get("state") not in {"accepted", "running"}:
        raise CloudSyncError("job is not running")
    updated = _set_job_state(job_id, persist=True, cancel_requested=True, phase="cancelling")
    return updated


def run_google_drive_job(job_id: str, direction: str, abs_path: str):
    provider = "google_drive"
    try:
        job_snapshot = get_cloud_job(job_id) or {}
        conflict_policy = normalize_cloud_conflict_policy(str(job_snapshot.get("conflict_policy", CLOUD_SYNC_CONFLICT_POLICY) or CLOUD_SYNC_CONFLICT_POLICY))

        def _should_cancel() -> bool:
            current = get_cloud_job(job_id) or {}
            return bool(current.get("cancel_requested", False))

        client = GoogleDriveClient(conflict_policy=conflict_policy, should_cancel=_should_cancel)
        cfg = _copy_provider_config(provider)
        folder_id = str(cfg.get("folder_id", "") or "")
        if not cfg.get("enabled", False):
            raise CloudSyncError("google_drive sync is disabled")
        if not folder_id:
            raise CloudSyncError("google_drive folder_id is not configured")
        if not client.is_connected():
            raise CloudSyncError("google_drive is not connected")

        _set_job_state(job_id, persist=True, state="running", started_at=_utc_now_iso(), progress=0, error=None, conflict_policy=conflict_policy)

        progress_state = {"persisted": -10}

        def _progress(current: int, total: int):
            total_items = max(1, int(total or 1))
            percent = int((max(0, current) / total_items) * 100)
            normalized = max(0, min(100, percent))
            should_persist = normalized in {0, 100} or normalized - progress_state["persisted"] >= 10
            if should_persist:
                progress_state["persisted"] = normalized
            _set_job_state(job_id, persist=should_persist, progress=normalized)

        if direction == "upload":
            stats = client.sync_upload(abs_path, folder_id, _progress)
        elif direction == "download":
            if os.path.exists(abs_path) and not os.path.isdir(abs_path):
                raise CloudSyncError("download target path must be a directory")
            stats = client.sync_download(abs_path, folder_id, _progress)
        else:
            raise CloudSyncError("unsupported sync direction")

        _finish_cloud_job(job_id, provider, state="completed", progress=100, stats=stats)
    except CloudSyncCancelled as exc:
        logger.add(f"Google Drive sync cancelled: {exc}", "WARN")
        _finish_cloud_job(job_id, provider, state="cancelled", error=str(exc), progress=0)
    except Exception as exc:
        logger.add(f"Google Drive sync failed: {exc}", "ERROR")
        _finish_cloud_job(job_id, provider, state="failed", error=str(exc), progress=0)


def start_google_drive_job(direction: str, abs_path: str, rel_path: str, conflict_policy: str = CLOUD_SYNC_CONFLICT_POLICY) -> dict[str, Any]:
    job = create_cloud_job("google_drive", direction, rel_path, conflict_policy=conflict_policy)
    thread = threading.Thread(target=run_google_drive_job, args=(job["job_id"], direction, abs_path), daemon=True)
    thread.start()
    return job
