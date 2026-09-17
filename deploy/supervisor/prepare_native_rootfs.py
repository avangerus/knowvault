#!/usr/bin/env python3
"""Offline packaging of the already pinned OCI archive; never starts a runtime."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import tarfile

from native_ingest_supervisor import (
    PINNED, ROOTFS_SCHEMA, SupervisorFailure, require,
    rootfs_tree_sha256, verify_oci_archive, verify_prepared_rootfs,
)


def apply_layer(stream, root: pathlib.Path, budget: list[int]) -> None:
    """Apply this qualified image's regular-file/directory/relative-link subset.

    Reject unsupported OCI whiteouts, devices and hardlinks instead of guessing
    their semantics. Never traverse an extracted symlink while writing a layer.
    """
    with tarfile.open(fileobj=stream, mode="r|*") as layer:
        seen = set()
        for member in layer:
            pure = pathlib.PurePosixPath(member.name)
            require(not pure.is_absolute() and ".." not in pure.parts and bool(pure.parts), "LAYER_PATH_INVALID")
            require(not any(part.startswith(".wh.") for part in pure.parts), "LAYER_WHITEOUT_UNSUPPORTED")
            relative = str(pure)
            require(relative not in seen, "LAYER_DUPLICATE_PATH")
            seen.add(relative)
            budget[0] += 1
            require(budget[0] <= 200_000, "LAYER_ENTRY_LIMIT")
            require(0 <= member.uid <= 2**31-1 and 0 <= member.gid <= 2**31-1, "LAYER_OWNER_INVALID")
            parent = root
            for component in pure.parts[:-1]:
                parent = parent / component
                if not parent.exists() and not parent.is_symlink():
                    parent.mkdir(mode=0o755)
                require(stat.S_ISDIR(parent.lstat().st_mode), "LAYER_PARENT_UNSAFE")
            target = root / relative
            require(not target.is_symlink(), "LAYER_OVERWRITES_LINK")
            if member.isdir():
                if not target.exists():
                    target.mkdir(mode=0o755)
                require(stat.S_ISDIR(target.lstat().st_mode), "LAYER_TYPE_CHANGED")
            elif member.issym():
                link = pathlib.PurePosixPath(member.linkname)
                require(member.linkname and not link.is_absolute(), "LAYER_LINK_INVALID")
                depth = len(pure.parts)-1
                for component in link.parts:
                    depth += -1 if component == ".." else 0 if component == "." else 1
                    require(depth >= 0, "LAYER_LINK_ESCAPE")
                require(not target.exists(), "LAYER_TYPE_CHANGED")
                target.symlink_to(member.linkname)
                os.chown(target, member.uid, member.gid, follow_symlinks=False)
                continue
            else:
                require(member.isfile() and 0 <= member.size <= 1024**3, "LAYER_TYPE_UNSUPPORTED")
                budget[1] += member.size
                require(budget[1] <= 2*1024**3, "LAYER_SIZE_LIMIT")
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
                fd = os.open(target, flags, 0o600)
                with os.fdopen(fd, "wb") as dest, layer.extractfile(member) as source:
                    remaining = member.size
                    while remaining:
                        block = source.read(min(remaining, 1024*1024))
                        require(bool(block), "LAYER_TRUNCATED")
                        dest.write(block)
                        remaining -= len(block)
            os.chown(target, member.uid, member.gid, follow_symlinks=False)
            os.chmod(target, member.mode & 0o7777, follow_symlinks=False)


def prepare_mountpoints(root: pathlib.Path) -> None:
    """Materialize only empty runtime mount targets in the offline tree identity."""
    for relative in ("proc", "dev", "tmp", "run", "run/knowvault"):
        target = root / relative
        if not target.exists() and not target.is_symlink():
            target.mkdir(mode=0o755)
            target.chmod(0o755)
        info = target.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o755, "ROOTFS_MOUNTPOINT_UNSAFE")
        require(not list(target.iterdir()), "ROOTFS_MOUNTPOINT_NOT_EMPTY")


def prepare(archive: str, output: str) -> dict:
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    # Verify every image pin before creating output or interpreting any layer.
    verify_oci_archive(archive)
    target = pathlib.Path(output)
    require(target.is_absolute() and target.resolve() == target and not target.exists(), "OUTPUT_MUST_BE_FRESH")
    parent_info = target.parent.stat()
    require(parent_info.st_uid == 0 and (stat.S_IMODE(parent_info.st_mode) & 0o022) == 0, "OUTPUT_PARENT_UNSAFE")
    target.mkdir(mode=0o700)
    root = target / "rootfs"
    root.mkdir(mode=0o755)
    budget = [0, 0]
    with tarfile.open(archive, "r:*") as image:
        for digest in PINNED["layers"]:
            with image.extractfile("blobs/sha256/" + digest.removeprefix("sha256:")) as layer:
                apply_layer(layer, root, budget)
    prepare_mountpoints(root)
    identity = {"schema_version": ROOTFS_SCHEMA,
                **{key: PINNED[key] for key in ("oci_archive_sha256", "oci_manifest_digest", "oci_config_digest", "artifact_hash")},
                "rootfs_tree_sha256": rootfs_tree_sha256(str(root))}
    identity_path = target / "rootfs.identity.json"
    identity_path.write_text(json.dumps(identity, sort_keys=True, indent=2) + "\n", encoding="ascii")
    identity_path.chmod(0o444)
    verify_prepared_rootfs(str(root), str(identity_path))
    return {"identity": identity, "identity_sha256": hashlib.sha256(identity_path.read_bytes()).hexdigest(),
            "layer_entries": budget[0], "layer_file_bytes": budget[1], "runtime_started": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.archive, args.output_dir), sort_keys=True))
    except (SupervisorFailure, OSError, tarfile.TarError) as exc:
        raise SystemExit("ROOTFS_PREPARATION_FAILED: " + str(exc)) from exc
