"""Fail fast when a PyInstaller spec references a missing build artifact.

Regression guard for the v7.3.0 release failure: ``webshare.spec`` bundles
``go-core/webshare-core.exe``, which is gitignored and therefore absent from
a fresh checkout unless the Go build runs first. This check runs in CI on
every push (after ``go build``) so a broken bundle surfaces long before the
release workflow gets there.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECS = [REPO_ROOT / "webshare.spec", REPO_ROOT / "WebSharePro.spec"]


def spec_binaries(spec: Path) -> list[str]:
    tree = ast.parse(spec.read_text(encoding="utf-8"), filename=str(spec))
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.keyword) or node.arg != "binaries":
            continue
        entries = ast.literal_eval(node.value)
        for entry in entries:
            src = entry[0] if isinstance(entry, (list, tuple)) else entry
            found.append(str(src))
    return found


def main() -> int:
    failures: list[str] = []
    for spec in SPECS:
        if not spec.is_file():
            failures.append(f"{spec.name}: spec file missing")
            continue
        for src in spec_binaries(spec):
            candidate = (REPO_ROOT / src).resolve()
            if not candidate.is_file():
                failures.append(f"{spec.name}: missing binaries entry: {src}")
            else:
                print(f"{spec.name}: ok: {src} ({candidate.stat().st_size} bytes)")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
