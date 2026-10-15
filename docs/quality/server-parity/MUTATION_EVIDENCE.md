# Mutation Evidence (Phase 4)

Generated: 2026-10-15T15:42:25 via `python scripts/run_mutation_check.py`
Detector file: `tests/quality/test_mutation_detection.py` (live 127.0.0.1 servers)

| ID | Mutant | Target | Baseline | Under mutant | After restore | Verdict |
|---|---|---|---|---|---|---|
| M1 | chunk index range validation removed (upload_chunk) | `webshare_app/routes/upload_routes/chunk_transfer.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M2 | COMPLETING merge/cancel guard removed (complete_chunk_upload) | `webshare_app/routes/upload_routes/chunk_finalize.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M3 | merge writes nothing yet reports success (copyfileobj dropped) | `webshare_app/routes/upload_routes/chunk_finalize.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M4 | root path validation detached (commonpath check neutered) | `webshare_app/utils/file_utils.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M5 | download-count reservation detached (quota never refuses) | `webshare_app/services/share_service.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M6 | trash restore reports success without moving bytes | `webshare_app/features/trash.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M7 | rename collision overwrites the destination | `webshare_app/routes/file_routes/mutation_handlers.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M8 | unknown upload session treated as valid (None deref/500) | `webshare_app/routes/upload_routes/chunk_finalize.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M9 | corrupt config silently replaced by defaults (no backup) | `webshare_app/core/config/manager.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |
| M10 | ZIP member traversal check bypassed | `webshare_app/routes/file_routes/mutation_handlers.py` | GREEN(rc=0) | RED(rc=1) | yes | **KILLED** |

Working tree after the run: clean for all target files.

## Per-mutant logs (tail)

### M1 -- chunk index range validation removed (upload_chunk)

File SHA (pre-mutant): `4caf28b65623`

Under mutant:
```
[2026-10-15 15:41:15] [INFO] orjson JSON provider enabled
---------------------------- Captured stdout call -----------------------------
[2026-10-15 15:41:17] [INFO] 관리자 로그인: 127.0.0.1
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m1_chunk_index_range_rejected
1 failed in 3.45s
```
After restore:
```
.                                                                        [100%]
1 passed in 1.02s
```

### M2 -- COMPLETING merge/cancel guard removed (complete_chunk_upload)

File SHA (pre-mutant): `2ab06f32d50f`

Under mutant:
```
---------------------------- Captured stdout call -----------------------------
[2026-10-15 15:41:26] [INFO] 관리자 로그인: 127.0.0.1
[2026-10-15 15:41:26] [INFO] Chunk upload complete: m2.bin
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m2_completing_guard_rejects_reentry
1 failed in 1.27s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.96s
```

### M3 -- merge writes nothing yet reports success (copyfileobj dropped)

File SHA (pre-mutant): `2ab06f32d50f`

Under mutant:
```
[2026-10-15 15:41:34] [INFO] orjson JSON provider enabled
---------------------------- Captured stdout call -----------------------------
[2026-10-15 15:41:34] [INFO] 관리자 로그인: 127.0.0.1
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m3_complete_writes_real_bytes
1 failed in 1.46s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.65s
```

### M4 -- root path validation detached (commonpath check neutered)

File SHA (pre-mutant): `ed578fcd1e5f`

Under mutant:
```
---------------------------- Captured stdout call -----------------------------
[2026-10-15 15:41:42] [INFO] 관리자 로그인: 127.0.0.1
[2026-10-15 15:41:42] [INFO] 다운로드: C:\Users\soulb\AppData\Local\Temp\pytest-of-soulb\pytest-313\test_m4_absolute_path_escape_b0\m4_secret.txt
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m4_absolute_path_escape_blocked
1 failed in 1.34s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.62s
```

### M5 -- download-count reservation detached (quota never refuses)

File SHA (pre-mutant): `ce23623cc124`

Under mutant:
```
[2026-10-15 15:41:48] [INFO] 관리자 로그인: 127.0.0.1
[2026-10-15 15:41:49] [INFO] 업로드: m5.bin
[2026-10-15 15:41:49] [INFO] 공유 링크 생성: m5.bin (24시간) [최대 1회]
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m5_share_quota_atomic_under_burst
1 failed in 1.01s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.85s
```

### M6 -- trash restore reports success without moving bytes

File SHA (pre-mutant): `e1b167859135`

Under mutant:
```
[2026-10-15 15:41:55] [INFO] 휴지통 이동: m6.txt
[2026-10-15 15:41:55] [INFO] 휴지통 이동: m6.txt
[2026-10-15 15:41:55] [INFO] 휴지통 복원: m6.txt
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m6_restore_returns_original_bytes
1 failed in 0.72s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.62s
```

### M7 -- rename collision overwrites the destination

File SHA (pre-mutant): `b529ce1b782e`

Under mutant:
```
---------------------------- Captured stdout call -----------------------------
[2026-10-15 15:42:00] [INFO] 관리자 로그인: 127.0.0.1
[2026-10-15 15:42:00] [ERROR] 이름 변경 오류: [WinError 183] 파일이 이미 있으므로 만들 수 없습니다: 'C:\\Users\\soulb\\AppData\\Local\\Temp\\pytest-of-soulb\\pytest-319\\test_m7_rename_collision_refus0\\live\\shared\\m7a.txt' -> 'C:\\Users\\soulb\\AppData\\Local\\Temp\\pytest-of-soulb\\pytest-319\\test_m7_rename_collision_refus0\\live\\shared\\m7b.txt'
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m7_rename_collision_refused_victim_intact
1 failed in 0.76s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.82s
```

### M8 -- unknown upload session treated as valid (None deref/500)

File SHA (pre-mutant): `2ab06f32d50f`

Under mutant:
```
[2026-10-15 15:42:09] [INFO] orjson JSON provider enabled
[2026-10-15 15:42:09] [INFO] 관리자 로그인: 127.0.0.1
[2026-10-15 15:42:09] [ERROR] Unhandled exception: 'NoneType' object has no attribute 'get'
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m8_stale_upload_session_invalid_after_restart
1 failed in 2.54s
```
After restore:
```
.                                                                        [100%]
1 passed in 1.00s
```

### M9 -- corrupt config silently replaced by defaults (no backup)

File SHA (pre-mutant): `67c67f0cdda1`

Under mutant:
```
---------------------------- Captured stdout call -----------------------------
[2026-10-15 15:42:15] [ERROR] 설정 로드 실패: 'utf-8' codec can't decode byte 0xff in position 10: invalid start byte
[2026-10-15 15:42:15] [ERROR] 손상된 설정 파일 백업: C:\Users\soulb\AppData\Local\Temp\pytest-of-soulb\pytest-323\test_m9_corrupt_config_leaves_0\live\config\webshare_config.json.corrupt-20261015_154215
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m9_corrupt_config_leaves_backup
1 failed in 0.74s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.48s
```

### M10 -- ZIP member traversal check bypassed

File SHA (pre-mutant): `b529ce1b782e`

Under mutant:
```
[2026-10-15 15:42:21] [INFO] 관리자 로그인: 127.0.0.1
[2026-10-15 15:42:22] [INFO] 업로드: m10.zip
[2026-10-15 15:42:22] [INFO] 압축해제: m10.zip
=========================== short test summary info ===========================
FAILED tests/quality/test_mutation_detection.py::test_m10_zip_slip_member_blocked
1 failed in 0.74s
```
After restore:
```
.                                                                        [100%]
1 passed in 0.64s
```
