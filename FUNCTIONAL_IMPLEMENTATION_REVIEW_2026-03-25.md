# WebShare Pro Functional Implementation Review

Date: 2026-03-25

Scope
- Reviewed `README.md`, `WebSharePro.spec`, runtime entrypoints, major routes, core helper/feature modules, and existing automated tests.
- `CLAUDE.md` was not present in the project root, so it could not be included in the review basis.
- Validation at review time: `pytest -q` passed with `TEMP/TMP` redirected into the workspace (`54 passed, 1 skipped`).

## Implementation Follow-up Status (2026-03-25)

- The remediation plan from this review has now been implemented in the codebase.
- Current verification baseline after implementation:
  - `pytest -q --basetemp .pytest_tmp` -> `64 passed, 1 skipped`
- Packaging/docs alignment also updated:
  - `webshare.spec`, `WebSharePro.spec` include `routes.network_routes`
  - `.gitignore` now excludes `.pytest_tmp/`
  - `README.md`, `README_EN.md` reflect session-scoped recent files, Google Drive implementation, Dropbox placeholder status, manual UPnP, and readiness-gated GUI startup

### Implemented Resolution Summary

1. Daily bandwidth limit now checks projected bytes before transfer across direct download, ZIP, batch ZIP, share download, range streaming, and HLS traffic.
2. Recent files are now session-scoped and filtered by read permission before being returned.
3. Guest mutation support now follows `allow_guest_upload` plus folder permissions across rename/move/copy/delete/unzip/batch delete/chunk upload/mkdir/upload paths.
4. Text editor saves now validate payload size first and write atomically via temp file + `os.replace(...)`; version backup filenames include microseconds.
5. GUI/Tk start flow now waits for confirmed bind/readiness before showing a running state.
6. Search now falls back to filesystem scan while indexing and returns `indexing` plus `search_mode`.
7. Cloud/network integration is now end-to-end for Google Drive OAuth/manual jobs and manual UPnP map/unmap/status. Dropbox intentionally remains a placeholder by product decision.
8. Duplicate scan persistence now uses the same temp-file + `os.replace(...)` atomic-write pattern.

## High Priority Findings

### 1. Daily bandwidth limit can be exceeded by one large download
- Evidence:
  - `utils/helpers.py:226-246` checks `tracker["bytes"] >= limit` before transfer, but does not compare `current_bytes + next_download_size`.
  - Direct download and share download call the check before `track_download(...)`: `routes/file_routes.py:122-130`, `routes/share_routes.py:316-360`.
  - ZIP download does a second check after ZIP creation, but the helper still only checks current usage: `routes/file_routes.py:575-591`, `routes/file_routes.py:735-742`.
- Impact:
  - If the daily bandwidth limit is `100MB` and the client already used `95MB`, a `50MB` file can still start and finish, ending at `145MB`.
  - This affects normal downloads, ZIP downloads, shared links, and HLS playlist/segment traffic.
- Recommendation:
  - Change `check_download_limit(...)` to accept an optional projected byte size and reject when `tracker["bytes"] + projected_bytes > limit`.
  - Apply the projected check at every call site that already knows the outgoing size.

### 2. Recent files are globally shared and returned without permission filtering
- Evidence:
  - Recent accesses are stored in one global list: `utils/helpers.py:17-36`.
  - `/recent_files` returns that list as-is: `routes/root_api_routes.py:152-156`.
  - `/api/recent_files` does the same: `routes/api_routes.py:161-165`.
- Impact:
  - One user's accesses become visible to another logged-in user.
  - A guest can potentially see paths/names recently opened by an admin, including restricted content.
  - Shared-link traffic also pollutes the same list because share downloads call `add_recent_file(...)`.
- Recommendation:
  - At minimum, filter `RECENT_FILES` by `ensure_path_access(path, "read")` before returning.
  - Prefer moving recent-file history to per-session or per-role storage.

### 3. Folder permission model is only partially implemented for non-admin users
- Evidence:
  - `README.md:62` advertises folder-level `read/write/delete` permissions.
  - Permission logic itself supports `read/write/delete`: `security/permissions.py:16-49`.
  - Guest-capable write routes exist for upload and mkdir: `routes/file_routes.py:153-157`, `routes/file_routes.py:251-254`, `routes/upload_routes.py:151-154`.
  - But major mutating routes are hard-admin-only regardless of folder permission: `routes/file_routes.py:301-302` (delete), `337-338` (rename), `406-407` (copy), `464-465` (move), `606-607` (unzip), `765` (batch delete).
- Impact:
  - Even if guest write/delete permission is configured on a folder, the guest still cannot perform most file-management actions.
  - In practice, the permission model behaves closer to "admin full access, guest upload-only" than the README implies.
- Recommendation:
  - Decide whether guest write/delete is a real product requirement.
  - If yes, remove hard admin decorators from the relevant routes and rely on `ensure_path_access(...)`.
  - If no, narrow the README and UI wording so operators do not assume finer-grained guest write/delete support exists.

### 4. Text editor saves are not atomic, and version backups can silently collide
- Evidence:
  - The editor writes directly to the live file with `open(..., 'w')`: `routes/media_routes.py:424-453`.
  - A version backup is created before validation completes: `routes/media_routes.py:438`.
  - Version filenames only use second-level timestamps: `utils/helpers.py:52`.
  - The backup write is a plain `shutil.copy2(...)` to that computed filename: `utils/helpers.py:57`.
- Impact:
  - A crash or process interruption during save can leave the original file truncated or partially rewritten.
  - Multiple saves within the same second can overwrite the same version backup, reducing recovery history without warning.
  - Rejected oversized saves still perform a version-backup attempt first, creating unnecessary churn.
- Recommendation:
  - Save to a temp file in the same directory and finish with `os.replace(...)`.
  - Move size validation ahead of `create_file_version(...)`.
  - Increase version filename uniqueness to microseconds or append a random suffix.

### 5. GUI/Tk start flow reports success before bind/startup actually succeeds
- Evidence:
  - `start_server(...)` only creates a thread and returns immediately: `server.py:477-485`.
  - The PyQt GUI marks the server as running immediately after that return value: `gui/pyqt_gui.py:774-775`.
  - The Tk fallback also shows a success dialog immediately: `main.py:91-94`.
- Impact:
  - If the port is already in use or startup fails later inside `ServerThread.run()`, the UI can still show a running state or success message.
  - This creates false-positive operator feedback exactly in the failure path that most needs accurate feedback.
- Recommendation:
  - Introduce a startup handshake/event from `ServerThread` after `make_server(...)` succeeds and the server is ready.
  - Update the GUI only from that confirmed-ready signal, and surface bind failures explicitly.

## Medium Priority Findings

### 6. "Real-time filename search" is currently eventual, not real-time
- Evidence:
  - README advertises real-time search: `README.md:40`.
  - Initial indexing is started in a background thread after server start: `server.py:394`.
  - Search uses only the in-memory index: `routes/file_routes.py:520-532`.
  - The index starts with `last_indexed = None`: `features/search_indexer.py:31`.
  - File changes trigger a debounced rebuild after 5 seconds: `features/search_indexer.py:216`.
- Impact:
  - Immediately after startup, search can return empty results even though files exist.
  - Immediately after upload/delete/rename, results can lag for at least 5 seconds plus rebuild time.
  - From a user perspective, this can look like a broken search feature rather than a still-indexing state.
- Recommendation:
  - Expose indexing state in the search response, or fall back to a direct filesystem search until the first index is ready.
  - If the product keeps the current design, adjust the README/UI text from "real-time" to "indexed search" or "near-real-time search".

### 7. Cloud Sync and network utilities are still product-surface placeholders
- Evidence:
  - The Cloud Sync modal only shows disabled connect buttons: `templates/index.html:2428-2444`.
  - Cloud Sync APIs explicitly run in mock mode: `routes/cloud_routes.py:22-122`.
  - UPnP/network utility code exists, but only as helper functions with no visible integration path in the reviewed runtime/UI flow: `features/network.py:20-37`.
- Impact:
  - The project surface suggests functionality that is not yet operational end-to-end.
  - This is not a hidden code bug, but it is a gap between visible feature presence and actual deliverable behavior.
- Recommendation:
  - Either hide these placeholders from the default UI until implemented, or complete the end-to-end integration and operator settings flow.

## Low Priority Findings

### 8. Duplicate-scan persistence is not using the same atomic-write pattern as other stores
- Evidence:
  - Duplicate result persistence writes directly with `open(..., 'w')`: `features/duplicates.py:23-40`.
  - README states atomic `os.replace()` writes were standardized for persisted stores: `README.md:431`.
- Impact:
  - If the process is interrupted during duplicate-result save, `.webshare_duplicates.json` can be left partially written or corrupted.
- Recommendation:
  - Align duplicate-result persistence with the atomic temp-file + `os.replace(...)` pattern already used by config/metadata/permissions/share-links/cloud/audit stores.

## Recommended Next Actions

1. Fix the bandwidth-limit check first.
2. Filter or isolate recent-file history before exposing it to non-admin users.
3. Decide the actual scope of guest write/delete support, then align routes, UI, and README together.
4. Make editor saves atomic and harden version naming.
5. Add a confirmed-ready startup signal for GUI/Tk flows.
6. Clarify or complete search/cloud/network feature surfaces so operators do not misread placeholder behavior as production-ready.
