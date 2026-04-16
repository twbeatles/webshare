"""
WebShare Pro - Persistent Job Store
Shared job ledger for long-running background work.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime
from typing import Any

from config import JOBS_FILE, conf
from utils.helpers import atomic_write_bytes
from utils.log_manager import logger


_jobs_lock = threading.Lock()
_jobs: dict[str, dict[str, Any]] = {}
MAX_PERSISTED_JOBS = 200


def _jobs_file_path() -> str:
    return os.path.join(conf.get("folder"), JOBS_FILE)


def _normalized_progress(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _sanitize_job(job: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(job or {})
    sanitized["job_id"] = str(sanitized.get("job_id", "") or "")
    sanitized["kind"] = str(sanitized.get("kind", "") or "")
    sanitized["scope"] = str(sanitized.get("scope", "") or "")
    sanitized["state"] = str(sanitized.get("state", "accepted") or "accepted")
    sanitized["progress"] = _normalized_progress(sanitized.get("progress", 0))
    sanitized["error"] = sanitized.get("error")
    sanitized["created_at"] = str(sanitized.get("created_at", "") or "")
    sanitized["updated_at"] = str(sanitized.get("updated_at", "") or "")
    return sanitized


def _trim_jobs_locked() -> None:
    if len(_jobs) <= MAX_PERSISTED_JOBS:
        return

    stale_ids = [
        item[0]
        for item in sorted(
            _jobs.items(),
            key=lambda item: str(item[1].get("created_at", "") or ""),
            reverse=True,
        )[MAX_PERSISTED_JOBS:]
    ]
    for job_id in stale_ids:
        _jobs.pop(job_id, None)


def _persist_jobs_locked() -> None:
    path = _jobs_file_path()
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    payload = {
        "updated": datetime.now().isoformat(),
        "jobs": sorted(
            [_sanitize_job(job) for job in _jobs.values()],
            key=lambda item: str(item.get("created_at", "") or ""),
            reverse=True,
        ),
    }
    atomic_write_bytes(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
    )


def load_jobs() -> None:
    path = _jobs_file_path()
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception as exc:
        logger.add(f"작업 ledger 로드 실패: {exc}", "ERROR")
        return

    loaded_jobs: dict[str, dict[str, Any]] = {}
    raw_jobs = raw.get("jobs", []) if isinstance(raw, dict) else []
    if isinstance(raw_jobs, dict):
        raw_jobs = list(raw_jobs.values())

    if not isinstance(raw_jobs, list):
        raw_jobs = []

    for item in raw_jobs:
        if not isinstance(item, dict):
            continue
        sanitized = _sanitize_job(item)
        job_id = sanitized.get("job_id", "")
        if not job_id:
            continue
        loaded_jobs[job_id] = sanitized

    with _jobs_lock:
        _jobs.clear()
        _jobs.update(loaded_jobs)
        _trim_jobs_locked()


def save_jobs() -> None:
    with _jobs_lock:
        _persist_jobs_locked()


def create_job(kind: str, scope: str, *, job_id: str | None = None, persist: bool = True, **fields: Any) -> dict[str, Any]:
    now_iso = datetime.now().isoformat()
    resolved_job_id = str(job_id or f"{kind}-{uuid.uuid4().hex[:12]}")
    job = _sanitize_job(
        {
            "job_id": resolved_job_id,
            "kind": str(kind or ""),
            "scope": str(scope or ""),
            "state": "accepted",
            "progress": 0,
            "error": None,
            "created_at": now_iso,
            "updated_at": now_iso,
            **fields,
        }
    )

    with _jobs_lock:
        _jobs[resolved_job_id] = job
        _trim_jobs_locked()
        if persist:
            _persist_jobs_locked()
        return dict(job)


def update_job(job_id: str, *, persist: bool = True, **updates: Any) -> dict[str, Any] | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not isinstance(job, dict):
            return None
        if "progress" in updates:
            updates["progress"] = _normalized_progress(updates.get("progress"))
        job.update(updates)
        job["updated_at"] = datetime.now().isoformat()
        job = _sanitize_job(job)
        _jobs[job_id] = job
        if persist:
            _persist_jobs_locked()
        return dict(job)


def get_job(job_id: str) -> dict[str, Any] | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        return dict(job) if isinstance(job, dict) else None


def get_last_job(*, kind: str | None = None, scope: str | None = None) -> dict[str, Any] | None:
    with _jobs_lock:
        candidates = []
        for job in _jobs.values():
            if kind and job.get("kind") != kind:
                continue
            if scope and job.get("scope") != scope:
                continue
            candidates.append(job)
        if not candidates:
            return None
        latest = max(candidates, key=lambda item: str(item.get("created_at", "") or ""))
        return dict(latest)


def get_active_job(*, kind: str | None = None, scope: str | None = None) -> dict[str, Any] | None:
    with _jobs_lock:
        candidates = []
        for job in _jobs.values():
            if kind and job.get("kind") != kind:
                continue
            if scope and job.get("scope") != scope:
                continue
            if job.get("state") not in {"accepted", "running"}:
                continue
            candidates.append(job)
        if not candidates:
            return None
        latest = max(candidates, key=lambda item: str(item.get("created_at", "") or ""))
        return dict(latest)


def mark_incomplete_jobs(
    *,
    kind: str | None = None,
    scope: str | None = None,
    state: str = "failed",
    error: str | None = None,
) -> int:
    changed = 0
    with _jobs_lock:
        for job_id, job in list(_jobs.items()):
            if kind and job.get("kind") != kind:
                continue
            if scope and job.get("scope") != scope:
                continue
            if job.get("state") not in {"accepted", "running"}:
                continue
            job["state"] = state
            job["error"] = error
            job["finished_at"] = datetime.now().isoformat()
            job["updated_at"] = datetime.now().isoformat()
            _jobs[job_id] = _sanitize_job(job)
            changed += 1
        if changed > 0:
            _persist_jobs_locked()
    return changed


def reset_jobs_runtime_state(*, kind: str | None = None) -> None:
    with _jobs_lock:
        if not kind:
            _jobs.clear()
            return

        stale_ids = [job_id for job_id, job in _jobs.items() if job.get("kind") == kind]
        for job_id in stale_ids:
            _jobs.pop(job_id, None)
