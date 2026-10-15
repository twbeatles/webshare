#!/usr/bin/env python3
"""Phase 4 mutation check: prove each M-detector kills its mutant.

For every mutant: back up the target file, apply ONE contiguous semantic
edit, run its detector (must FAIL = killed), restore the file byte-for-byte
(verified by SHA-256), re-run the detector (must PASS = green again).

Never commits anything; refuses to finish while any target file still
differs from HEAD. Evidence is written to
docs/quality/server-parity/MUTATION_EVIDENCE.md.

Usage:
    python scripts/run_mutation_check.py [--only M1,M3] [--keep-going]
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/quality/server-parity/MUTATION_EVIDENCE.md"
DETECTOR_FILE = "tests/quality/test_mutation_detection.py"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_pytest(node: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", f"{DETECTOR_FILE}::{node}",
         "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    return proc.returncode, "\n".join(tail[-6:])


MUTANTS: list[dict] = [
    {
        "id": "M1", "node": "test_m1_chunk_index_range_rejected",
        "file": "webshare_app/routes/upload_routes/chunk_transfer.py",
        "desc": "chunk index range validation removed (upload_chunk)",
        "find": "    if total_chunks > 0 and chunk_index >= total_chunks:\n"
                "        return jsonify({'success': False, 'error': 'chunk index out of range'}), 400",
        "replace": "    if False:  # MUTANT-M1\n"
                   "        return jsonify({'success': False, 'error': 'chunk index out of range'}), 400",
    },
    {
        "id": "M2", "node": "test_m2_completing_guard_rejects_reentry",
        "file": "webshare_app/routes/upload_routes/chunk_finalize.py",
        "desc": "COMPLETING merge/cancel guard removed (complete_chunk_upload)",
        "find": "        if status == UPLOAD_STATUS_COMPLETING:\n"
                "            return jsonify({'success': False, 'error': 'upload already completing'}), 409",
        "replace": "        if False:  # MUTANT-M2\n"
                   "            return jsonify({'success': False, 'error': 'upload already completing'}), 409",
    },
    {
        "id": "M3", "node": "test_m3_complete_writes_real_bytes",
        "file": "webshare_app/routes/upload_routes/chunk_finalize.py",
        "desc": "merge writes nothing yet reports success (copyfileobj dropped)",
        "find": "                with open(chunk_path, 'rb') as chunk_file:\n"
                "                    shutil.copyfileobj(chunk_file, output_file, length=SAVE_IO_CHUNK_SIZE)",
        "replace": "                with open(chunk_path, 'rb') as chunk_file:\n"
                   "                    pass  # MUTANT-M3",
    },
    {
        "id": "M4", "node": "test_m4_absolute_path_escape_blocked",
        "file": "webshare_app/utils/file_utils.py",
        "desc": "root path validation detached (commonpath check neutered)",
        "find": "    if common != base_dir_real:\n"
                "        return False, \"\"",
        "replace": "    if False:  # MUTANT-M4\n"
                   "        return False, \"\"",
    },
    {
        "id": "M5", "node": "test_m5_share_quota_atomic_under_burst",
        "file": "webshare_app/services/share_service.py",
        "desc": "download-count reservation detached (quota never refuses)",
        "find": "        if max_downloads > 0 and current >= max_downloads:",
        "replace": "        if False:  # MUTANT-M5",
    },
    {
        "id": "M6", "node": "test_m6_restore_returns_original_bytes",
        "file": "webshare_app/features/trash.py",
        "desc": "trash restore reports success without moving bytes",
        "find": "        shutil.move(trash_path, restore_path)",
        "replace": "        pass  # MUTANT-M6",
    },
    {
        "id": "M7", "node": "test_m7_rename_collision_refused_victim_intact",
        "file": "webshare_app/routes/file_routes/mutation_handlers.py",
        "desc": "rename collision overwrites the destination",
        "find": "    if os.path.exists(new_path):\n"
                "        return jsonify({'error':",
        "replace": "    if False:  # MUTANT-M7\n"
                   "        return jsonify({'error':",
    },
    {
        "id": "M8", "node": "test_m8_stale_upload_session_invalid_after_restart",
        "file": "webshare_app/routes/upload_routes/chunk_finalize.py",
        "desc": "unknown upload session treated as valid (None deref/500)",
        "find": "        upload_session = UPLOAD_SESSIONS.get(session_id)\n"
                "        if not upload_session:\n"
                "            return jsonify({'success': False, 'error': 'invalid upload session'}), 400",
        "replace": "        upload_session = UPLOAD_SESSIONS.get(session_id)\n"
                   "        if False:  # MUTANT-M8\n"
                   "            return jsonify({'success': False, 'error': 'invalid upload session'}), 400",
    },
    {
        "id": "M9", "node": "test_m9_corrupt_config_leaves_backup",
        "file": "webshare_app/core/config/manager.py",
        "desc": "corrupt config silently replaced by defaults (no backup)",
        "find": "            shutil.copy2(CONFIG_FILE, backup_path)",
        "replace": "            pass  # MUTANT-M9",
    },
    {
        "id": "M10", "node": "test_m10_zip_slip_member_blocked",
        "file": "webshare_app/routes/file_routes/mutation_handlers.py",
        "desc": "ZIP member traversal check bypassed",
        "find": "                if not os.path.abspath(member_path).startswith(extract_to_abs + os.sep) and \\\n"
                "                   os.path.abspath(member_path) != extract_to_abs:",
        "replace": "                if False:  # MUTANT-M10\n"
                   "                    pass",
    },
]


def git_clean(paths: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(
        ["git", "status", "--short", "--", *paths],
        cwd=ROOT, capture_output=True, text=True,
    )
    return proc.stdout.strip() == "", proc.stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="e.g. M1,M3")
    ap.add_argument("--keep-going", action="store_true")
    args = ap.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    mutants = [m for m in MUTANTS if not only or m["id"] in only]
    if not mutants:
        print("no mutants selected")
        return 2

    # safety: working tree must be clean for every target file
    ok, dirty = git_clean([m["file"] for m in mutants])
    if not ok:
        print("refusing: target files already dirty:\n" + dirty)
        return 2

    rows: list[dict] = []
    failures = 0
    for m in mutants:
        target = ROOT / m["file"]
        original = target.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = target.read_text(encoding="utf-8")  # universal newlines
        count = text.count(m["find"])
        row = {"id": m["id"], "desc": m["desc"], "file": m["file"],
               "sha": digest[:12], "baseline": "?", "mutant": "?",
               "restored": "?", "verdict": "?"}
        if count != 1:
            row.update(baseline="N/A", mutant="NO-APPLY",
                       restored="yes", verdict="BLOCKED")
            print(f"[{m['id']}] pattern found {count}x, BLOCKED")
            rows.append(row)
            failures += 1
            continue
        target.write_text(text.replace(m["find"], m["replace"]), encoding="utf-8")
        code, tail = run_pytest(m["node"])
        killed = code != 0 and "failed" in tail
        row["mutant"] = f"RED(rc={code})" if killed else f"GREEN?!(rc={code})"
        row["mutant_log"] = tail
        target.write_bytes(original)  # restore
        if sha(target) != digest:
            row.update(restored="NO", verdict="BLOCKED-DIRTY")
            print(f"[{m['id']}] RESTORE MISMATCH -- STOPPING")
            rows.append(row)
            return 3
        row["restored"] = "yes"
        code2, tail2 = run_pytest(m["node"])
        row["baseline"] = f"GREEN(rc={code2})" if code2 == 0 else f"RED?!(rc={code2})"
        row["restored_log"] = tail2
        if killed and code2 == 0:
            row["verdict"] = "KILLED"
        elif not killed:
            row["verdict"] = "SURVIVED"
            failures += 1
        else:
            row["verdict"] = "RESTORE-FAIL"
            failures += 1
        print(f"[{m['id']}] mutant={row['mutant']} restored-green={row['baseline']} -> {row['verdict']}")
        rows.append(row)
        if failures and not args.keep_going and row["verdict"] != "KILLED":
            break

    ok, dirty = git_clean([m["file"] for m in mutants])
    now = datetime.datetime.now().isoformat(timespec="seconds")
    lines = [
        "# Mutation Evidence (Phase 4)",
        "",
        f"Generated: {now} via `python scripts/run_mutation_check.py`",
        f"Detector file: `{DETECTOR_FILE}` (live 127.0.0.1 servers)",
        "",
        "| ID | Mutant | Target | Baseline | Under mutant | After restore | Verdict |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['id']} | {r['desc']} | `{r['file']}` | {r['baseline']} | "
            f"{r['mutant']} | {r['restored']} | **{r['verdict']}** |"
        )
    lines += [
        "",
        "Working tree after the run: "
        + ("clean for all target files." if ok else "DIRTY -- investigate!"),
        "" if ok else "```\n" + dirty + "\n```",
        "## Per-mutant logs (tail)",
        "",
    ]
    for r in rows:
        lines += [
            f"### {r['id']} -- {r['desc']}",
            "",
            f"File SHA (pre-mutant): `{r['sha']}`",
            "",
            "Under mutant:",
            "```",
            r.get("mutant_log", "(not run)"),
            "```",
            "After restore:",
            "```",
            r.get("restored_log", "(not run)"),
            "```",
            "",
        ]
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text("\n".join(lines), encoding="utf-8")
    print(f"evidence -> {EVIDENCE}")
    print(f"killed={sum(1 for r in rows if r['verdict']=='KILLED')}/{len(rows)}")
    if not ok:
        return 3
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
