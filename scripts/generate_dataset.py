#!/usr/bin/env python3
"""
Generate synthetic file tree for performance testing.
"""

import argparse
import os
import random
import string
from pathlib import Path


def random_name(length: int = 10) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def create_dataset(base_dir: Path, dirs: int, files_per_dir: int, file_size: int) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    payload = ("x" * file_size).encode("utf-8")

    for i in range(dirs):
        folder = base_dir / f"set_{i:05d}"
        folder.mkdir(parents=True, exist_ok=True)
        for j in range(files_per_dir):
            name = f"{random_name(12)}_{j:04d}.txt"
            (folder / name).write_bytes(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic files for benchmark")
    parser.add_argument("--base-dir", required=True, help="Output directory path")
    parser.add_argument("--dirs", type=int, default=100)
    parser.add_argument("--files-per-dir", type=int, default=100)
    parser.add_argument("--file-size", type=int, default=256, help="Single file size in bytes")
    args = parser.parse_args()

    target = Path(args.base_dir)
    create_dataset(target, args.dirs, args.files_per_dir, args.file_size)
    total = args.dirs * args.files_per_dir
    print(f"generated files: {total}")
    print(f"root: {target}")


if __name__ == "__main__":
    main()
