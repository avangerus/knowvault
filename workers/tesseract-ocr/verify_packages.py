#!/usr/bin/env python3
"""Verify the package archive and installed-package lock during image build."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess


LOCK = Path("/opt/ocr/debian-packages.lock.json")
ARCHIVE_DIR = Path("/var/cache/apt/archives")


def main() -> int:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    if lock.get("architecture") != "amd64" or lock.get("suite") != "bookworm":
        raise SystemExit("unexpected Debian lock target")
    packages = lock.get("packages")
    if not isinstance(packages, list) or len(packages) != 56:
        raise SystemExit("unexpected Debian package closure")
    seen: set[str] = set()
    for item in packages:
        if not isinstance(item, dict):
            raise SystemExit("malformed package lock item")
        package = item["package"]
        if package in seen:
            raise SystemExit(f"duplicate package {package}")
        seen.add(package)
        actual = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Version}\t${Architecture}", package],
            text=True,
        ).strip().split("\t")
        if actual != [item["version"], item["architecture"]]:
            raise SystemExit(f"{package}: installed {actual!r}, locked {item!r}")
        archive = ARCHIVE_DIR / item["archive"]
        if not archive.is_file():
            raise SystemExit(f"{package}: missing archive {archive}")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != item["sha256"]:
            raise SystemExit(f"{package}: archive digest mismatch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
