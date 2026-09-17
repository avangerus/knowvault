#!/usr/bin/env python3
"""Root-owned, fail-closed host supervisor for the inactive parser-v3 candidate.

This service owns only runc lifecycle metadata, pidfds, dedicated cgroups, and
the parser registration socket directories. It never opens parser input, a
database, application credentials, or source directories.
"""

from __future__ import annotations

import array
import datetime as dt
import errno
import hashlib
import json
import os
import pathlib
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from typing import Any, Callable

try:
    import fcntl
except ImportError:  # The module is importable for local, non-Linux contract tests.
    fcntl = None  # type: ignore[assignment]


STATUS_SCHEMA = "sandbox-dispatcher-status-v1"
CONFIG_SCHEMA = "native-ingest-supervisor-config-v1"
ROOTFS_SCHEMA = "knowvault-native-parser-rootfs-v1"
STATUS_LIMIT = 4096
FRAME_LIMIT = 64 * 1024
# Process exit and the dispatcher's fresh REAPED publication are not atomic.
# Waiting permits no cleanup, new handoff, result acceptance, or lease extension.
REAP_STATUS_GRACE_SECONDS = 5.0
HANDOFF_KIND = 14
HANDOFF_ACCEPTED_KIND = 15
HANDOFF_ACCEPTED_BODY = b"sandbox-supervisor-handoff-accepted-v1"
HANDOFF_SCHEMA = "sandbox-supervisor-handoff-v1"
HANDOFF_ACCEPTED_SCHEMA = "sandbox-supervisor-handoff-accepted-v1"
STATUS_STATES = {"running", "red", "stopping"}
ROLE_STATES = {"empty", "handed_off", "ready", "busy", "reaped", "red"}
ROLE_HANDOFF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{31,127}$")
EPOCH_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)

PINNED = {
    "oci_archive_sha256": "024b7e44021154a024af07caf246917b93913686a19f25a1d47a9351c75be16d",
    "oci_manifest_digest": "sha256:bf1e580938eb62a05de1efe2cdf24d7fc8ab9339e5224be238f3794a0c9e0855",
    "oci_config_digest": "sha256:8006f7ddf504af8aee59afea5fcc719f673d7df80f6717c2ffced6b428c8d467",
    "artifact_hash": "sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414",
    "runc_sha256": "96553ef9a475e9f50caceea99b18ec32c242cf77bc33e63fa2db669cdec44a52",
    "worker_jar_sha256": "b110e603535e2c07d58918d123a3d5bae77e0ea4d09ee65a8ce1876e4ff65a4d",
    "rootfs_tree_sha256": "57f844763873eb9bd9896938ba89beaad459da1eb62fbf154c30602f983c5e7d",
    "sandbox_profile_revision": "document-parser-sandbox-v3",
    "working_dir": "/app",
    "layers": [
        "sha256:88a11acca421df58865f88d823431f52bda8175d5e6fd1692f2a487cc08f4c70",
        "sha256:17c02ca28da47e5a67ba1947fd042307e2285f94bf2d25bc0409f58337b05faf",
        "sha256:63c13e8ea6c10b81562d53428ece2363c7bb062d5d9747c2f87bbaeea22963a0",
        "sha256:36940d4560923835ac9eeccc0143ca747fe22821bc818faef116a68b7d522889",
        "sha256:6497328e1d8bf7f489b5284b656625833be2bea7f0709bb4447810c65845465a",
        "sha256:77ab5ba073fde3c4a0b3a17426a495c37713063bb59a0816dd90b3dc86a01cd2",
        "sha256:bdc0761c2529d7d054fc5c57ac1571244b5ec959f764161d846600211af80818",
        "sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1",
    ],
    "entrypoint": [
        "/opt/jre/bin/java",
        "-XX:ActiveProcessorCount=1",
        "-XX:MaxRAMPercentage=75.0",
        "-XX:+ExitOnOutOfMemoryError",
        "-Dlog4j2.loggerContextFactory=org.apache.logging.log4j.simple.SimpleLoggerContextFactory",
        "-Dlog4j2.simplelogLevel=OFF",
        "-Dlog4j2.defaultStatusLevel=OFF",
        "-Dlog4j2.status.entries=0",
        "-Djava.awt.headless=true",
        "-Dfile.encoding=UTF-8",
        "-Djava.io.tmpdir=/tmp",
        "-Duser.language=en",
        "-Duser.country=US",
        "-cp",
        "/app/document-parser-worker.jar:/app/lib/*",
        "local.knowvault.docparser.Main",
    ],
}

DEFAULT_CONFIG: dict[str, Any] = {
    "schema_version": CONFIG_SCHEMA,
    "dispatcher": {
        "handoff_socket": "/run/knowvault/sandbox/supervisor/handoff.sock",
        "status_file": "/run/knowvault/sandbox/supervisor/status.json",
        "office_register_socket": "/run/knowvault/sandbox/office/register.sock",
        "pdf_register_socket": "/run/knowvault/sandbox/pdf/register.sock",
        "uid": 0,
        "gid": 0,
    },
    "runtime": {
        "runc_path": "/usr/bin/runc",
        "runtime_dir": "/run/knowvault-native-ingest-supervisor",
        "runc_state_root": "/run/knowvault-native-ingest-supervisor/runc-state",
        "bundle_root": "/run/knowvault-native-ingest-supervisor/bundles",
        "cgroup_root": "/sys/fs/cgroup/knowvault_native.slice/knowvault-native-supervisor.service/parsers",
        "oci_archive": "/opt/knowvault/native-ingest-v3/parser.oci.tar",
        "rootfs": "/opt/knowvault/native-ingest-v3/rootfs",
        "rootfs_identity": "/opt/knowvault/native-ingest-v3/rootfs.identity.json",
        "handoff_timeout_seconds": 5,
        "ready_timeout_seconds": 45,
        "status_poll_seconds": 0.25,
        "shutdown_grace_seconds": 120,
        "handoff_lifetime_seconds": 120,
    },
    "image": {
        "oci_archive_sha256": PINNED["oci_archive_sha256"],
        "oci_manifest_digest": PINNED["oci_manifest_digest"],
        "oci_config_digest": PINNED["oci_config_digest"],
        "artifact_hash": PINNED["artifact_hash"],
        "sandbox_profile_revision": PINNED["sandbox_profile_revision"],
        "working_dir": PINNED["working_dir"],
        "runc_sha256": PINNED["runc_sha256"],
        "worker_jar_sha256": PINNED["worker_jar_sha256"],
        "rootfs_tree_sha256": PINNED["rootfs_tree_sha256"],
        "layers": PINNED["layers"],
        "entrypoint": PINNED["entrypoint"],
    },
    "roles": [
        {
            "parser_type": "OFFICE",
            "uid": 65532,
            "gid": 65532,
            "observation_profile_revision": "office-obs-v1",
            "registration_socket": "/run/knowvault/sandbox/office/register.sock",
        },
        {
            "parser_type": "PDF",
            "uid": 65533,
            "gid": 65533,
            "observation_profile_revision": "pdf-obs-v1",
            "registration_socket": "/run/knowvault/sandbox/pdf/register.sock",
        },
    ],
}


class SupervisorFailure(Exception):
    """Content-free supervisor failure code; messages never include paths/data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise SupervisorFailure(code)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SupervisorFailure("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def strict_json_loads(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_object_without_duplicates)
    except SupervisorFailure:
        raise
    except Exception as exc:
        raise SupervisorFailure("JSON_INVALID") from exc


def parse_utc_timestamp(value: Any) -> dt.datetime:
    require(isinstance(value, str) and UTC_TIMESTAMP_RE.fullmatch(value) is not None, "STATUS_TIMESTAMP_INVALID")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SupervisorFailure("STATUS_TIMESTAMP_INVALID") from exc
    return parsed.astimezone(dt.timezone.utc)


def validate_status_document(document: Any, now: dt.datetime) -> dict[str, Any]:
    require(isinstance(document, dict), "STATUS_INVALID")
    require(
        set(document) == {
            "schema_version",
            "dispatcher_epoch",
            "sequence",
            "written_at",
            "valid_until",
            "dispatcher_state",
            "roles",
        },
        "STATUS_FIELDS_INVALID",
    )
    require(document["schema_version"] == STATUS_SCHEMA, "STATUS_SCHEMA_INVALID")
    require(isinstance(document["dispatcher_epoch"], str) and EPOCH_RE.fullmatch(document["dispatcher_epoch"]) is not None, "STATUS_EPOCH_INVALID")
    sequence = document["sequence"]
    require(isinstance(sequence, int) and not isinstance(sequence, bool) and sequence > 0, "STATUS_SEQUENCE_INVALID")
    dispatcher_state = document["dispatcher_state"]
    require(isinstance(dispatcher_state, str) and dispatcher_state in STATUS_STATES, "STATUS_STATE_INVALID")
    written_at = parse_utc_timestamp(document["written_at"])
    valid_until = parse_utc_timestamp(document["valid_until"])
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    now = now.astimezone(dt.timezone.utc)
    require(written_at <= now + dt.timedelta(seconds=1), "STATUS_FROM_FUTURE")
    require(valid_until - written_at == dt.timedelta(seconds=5), "STATUS_VALIDITY_INVALID")
    require(valid_until > now, "STATUS_STALE")
    roles = document["roles"]
    require(isinstance(roles, dict) and set(roles) == {"OFFICE", "PDF"}, "STATUS_ROLES_INVALID")
    for role_name, role in roles.items():
        require(isinstance(role, dict), "STATUS_ROLE_INVALID")
        require("state" in role and "handoff_id" in role, "STATUS_ROLE_FIELDS_INVALID")
        state = role["state"]
        require(isinstance(state, str) and state in ROLE_STATES, "STATUS_ROLE_STATE_INVALID")
        expected_fields = {"state", "handoff_id"}
        if state == "busy":
            expected_fields.add("lease_deadline")
        require(set(role) == expected_fields, "STATUS_ROLE_FIELDS_INVALID")
        handoff_id = role["handoff_id"]
        if state == "empty":
            require(handoff_id is None, "STATUS_ROLE_ID_INVALID")
        elif handoff_id is not None:
            require(isinstance(handoff_id, str) and ROLE_HANDOFF_RE.fullmatch(handoff_id) is not None, "STATUS_ROLE_ID_INVALID")
        if state in {"handed_off", "ready", "busy", "reaped"}:
            require(isinstance(handoff_id, str) and ROLE_HANDOFF_RE.fullmatch(handoff_id) is not None, "STATUS_ROLE_ID_INVALID")
        if state == "busy":
            deadline = parse_utc_timestamp(role["lease_deadline"])
            require(deadline > written_at, "STATUS_LEASE_INVALID")
        if state == "red":
            require(dispatcher_state == "red", "STATUS_RED_MISMATCH")
    if dispatcher_state == "red":
        require(all(role["state"] == "red" for role in roles.values()), "STATUS_RED_MISMATCH")
    return document


class StatusSequence:
    """Pins one dispatcher epoch and rejects rollback or same-sequence rewrites."""

    def __init__(self) -> None:
        self.epoch: str | None = None
        self.sequence = 0
        self.last_document: dict[str, Any] | None = None

    def accept(self, document: dict[str, Any]) -> None:
        epoch = document["dispatcher_epoch"]
        sequence = document["sequence"]
        if self.epoch is None:
            self.epoch = epoch
        require(epoch == self.epoch, "STATUS_EPOCH_CHANGED")
        require(sequence >= self.sequence, "STATUS_SEQUENCE_ROLLBACK")
        if sequence == self.sequence and self.last_document is not None:
            require(document == self.last_document, "STATUS_SEQUENCE_REWRITTEN")
        self.sequence = sequence
        self.last_document = document


def _open_dir_component(parent_fd: int, component: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise SupervisorFailure("STATUS_PATH_UNAVAILABLE") from exc


def _open_absolute_directory(path: str) -> int:
    pure = pathlib.PurePosixPath(path)
    require(pure.is_absolute() and ".." not in pure.parts and str(pure) == path, "PATH_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open("/", flags)
    except OSError as exc:
        raise SupervisorFailure("PATH_UNAVAILABLE") from exc
    try:
        for component in pure.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=fd)
            except OSError as exc:
                raise SupervisorFailure("PATH_UNAVAILABLE") from exc
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_absolute_regular(path: str) -> int:
    pure = pathlib.PurePosixPath(path)
    require(pure.is_absolute() and ".." not in pure.parts and str(pure) == path and len(pure.parts) > 1, "PATH_INVALID")
    parent = str(pure.parent)
    directory_fd = _open_absolute_directory(parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            return os.open(pure.name, flags, dir_fd=directory_fd)
        except OSError as exc:
            raise SupervisorFailure("PATH_UNAVAILABLE") from exc
    finally:
        os.close(directory_fd)


def _secure_status_parent(path: str) -> int:
    require(path == "/run/knowvault/sandbox/supervisor/status.json", "STATUS_PATH_INVALID")
    parts = pathlib.PurePosixPath(path).parts
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        for part in parts[1:-1]:
            next_fd = _open_dir_component(fd, part)
            info = os.fstat(next_fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and (stat.S_IMODE(info.st_mode) & 0o022) == 0, "STATUS_PATH_UNAVAILABLE")
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "STATUS_PATH_UNAVAILABLE")
        return fd
    except BaseException:
        os.close(fd)
        raise


def prepare_status_directory(path: str) -> None:
    """Create only the canonical, root-owned status directory before dispatcher start."""
    require(path == "/run/knowvault/sandbox/supervisor/status.json", "STATUS_PATH_INVALID")
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    parts = pathlib.PurePosixPath(path).parts[1:-1]
    try:
        for index, component in enumerate(parts):
            is_leaf = index == len(parts) - 1
            if is_leaf:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                next_fd = _open_dir_component(fd, component)
            except SupervisorFailure:
                raise SupervisorFailure("STATUS_PATH_UNAVAILABLE")
            info = os.fstat(next_fd)
            mode = stat.S_IMODE(info.st_mode)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, "STATUS_PATH_UNAVAILABLE")
            if is_leaf:
                require(mode == 0o700, "STATUS_PATH_UNAVAILABLE")
            else:
                require((mode & 0o022) == 0, "STATUS_PATH_UNAVAILABLE")
            os.close(fd)
            fd = next_fd
        try:
            status_info = os.stat("status.json", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        require(
            stat.S_ISREG(status_info.st_mode)
            and status_info.st_uid == 0
            and stat.S_IMODE(status_info.st_mode) == 0o600
            and status_info.st_nlink == 1,
            "STATUS_FILE_UNSAFE",
        )
    finally:
        os.close(fd)


PREPARED_DIRECTORY_MODES = {
    "/run/knowvault": 0o755,
    "/run/knowvault/sandbox": 0o755,
    "/run/knowvault/sandbox/submit": 0o711,
    "/run/knowvault/sandbox/supervisor": 0o700,
    "/run/knowvault/sandbox/office": 0o711,
    "/run/knowvault/sandbox/pdf": 0o711,
}


def _open_prepared_directory_child(
    parent_fd: int,
    component: str,
    expected_mode: int | None,
    create: bool,
) -> int:
    if create:
        require(expected_mode is not None, "SOCKET_DIRECTORY_POLICY_INVALID")
        try:
            os.mkdir(component, expected_mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SupervisorFailure("SOCKET_DIRECTORY_UNAVAILABLE") from exc
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise SupervisorFailure("SOCKET_DIRECTORY_UNAVAILABLE") from exc
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    safe = stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
    if expected_mode is None:
        safe = safe and (mode & 0o022) == 0
    else:
        safe = safe and mode == expected_mode
    if not safe:
        os.close(fd)
        raise SupervisorFailure("SOCKET_DIRECTORY_UNSAFE")
    return fd


def verify_prepared_host_directories(
    config: dict[str, Any],
    expected_identities: dict[str, tuple[int, int]] | None = None,
) -> dict[str, tuple[int, int]]:
    validate_config(config)
    identities: dict[str, tuple[int, int]] = {}
    for path, expected_mode in PREPARED_DIRECTORY_MODES.items():
        fd = _open_absolute_directory(path)
        try:
            info = os.fstat(fd)
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == expected_mode,
                "SOCKET_DIRECTORY_UNSAFE",
            )
            identity = (info.st_dev, info.st_ino)
            if expected_identities is not None:
                require(expected_identities.get(path) == identity, "SOCKET_DIRECTORY_CHANGED")
            identities[path] = identity
        finally:
            os.close(fd)

    supervisor_fd = _open_absolute_directory("/run/knowvault/sandbox/supervisor")
    try:
        try:
            status_info = os.stat("status.json", dir_fd=supervisor_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(
                stat.S_ISREG(status_info.st_mode)
                and status_info.st_uid == 0
                and status_info.st_gid == 0
                and stat.S_IMODE(status_info.st_mode) == 0o600
                and status_info.st_nlink == 1,
                "STATUS_FILE_UNSAFE",
            )
    finally:
        os.close(supervisor_fd)
    return identities


def prepare_host_directories(config: dict[str, Any]) -> dict[str, tuple[int, int]]:
    """Create only the fixed dispatcher directories; never repair unsafe existing paths."""
    validate_config(config)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open("/", flags)
    current = "/"
    try:
        for path, mode in PREPARED_DIRECTORY_MODES.items():
            parts = pathlib.PurePosixPath(path).parts[1:]
            for component in parts:
                current = current.rstrip("/") + "/" + component
                target_mode = PREPARED_DIRECTORY_MODES.get(current)
                next_fd = _open_prepared_directory_child(
                    root_fd,
                    component,
                    target_mode,
                    create=target_mode is not None,
                )
                os.close(root_fd)
                root_fd = next_fd
            os.close(root_fd)
            root_fd = os.open("/", flags)
            current = "/"
    finally:
        os.close(root_fd)
    prepare_status_directory(config["dispatcher"]["status_file"])
    return verify_prepared_host_directories(config)


class StatusReader:
    def __init__(self, path: str):
        self.directory_fd = _secure_status_parent(path)
        self.sequence = StatusSequence()

    def close(self) -> None:
        if self.directory_fd >= 0:
            os.close(self.directory_fd)
            self.directory_fd = -1

    def read(self, now: dt.datetime | None = None, initial_running: bool = False) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open("status.json", flags, dir_fd=self.directory_fd)
        except OSError as exc:
            raise SupervisorFailure("STATUS_UNAVAILABLE") from exc
        try:
            info = os.fstat(fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1,
                "STATUS_FILE_UNSAFE",
            )
            data = os.read(fd, STATUS_LIMIT + 1)
            require(0 < len(data) <= STATUS_LIMIT, "STATUS_SIZE_INVALID")
        finally:
            os.close(fd)
        document = validate_status_document(strict_json_loads(data), now or dt.datetime.now(dt.timezone.utc))
        if initial_running and self.sequence.epoch is None:
            require(document["dispatcher_state"] != "red", "DISPATCHER_RED")
            require(document["dispatcher_state"] == "running", "DISPATCHER_NOT_RUNNING")
        self.sequence.accept(document)
        return document


def cleanup_authorized(
    status: dict[str, Any],
    role: str,
    epoch: str,
    handoff_id: str,
    pidfd_exited: bool,
    cgroup_empty: bool,
) -> bool:
    if not pidfd_exited or not cgroup_empty or status["dispatcher_state"] == "red":
        return False
    if status["dispatcher_epoch"] != epoch:
        return False
    role_status = status["roles"].get(role)
    return bool(role_status and role_status["state"] == "reaped" and role_status["handoff_id"] == handoff_id)


def release_exec_after_handoff(
    send_handoff_and_receive_ack: Callable[[], None],
    wait_for_matching_handed_off_status: Callable[[], None],
    start: Callable[[], None],
) -> None:
    """The only production path to `runc start`: ACK and fresh status precede it."""
    send_handoff_and_receive_ack()
    wait_for_matching_handed_off_status()
    start()


def _safe_path(path: str) -> bool:
    pure = pathlib.PurePosixPath(path)
    return pure.is_absolute() and ".." not in pure.parts and str(pure) == path


def validate_config(value: Any) -> dict[str, Any]:
    require(value == DEFAULT_CONFIG, "CONFIG_PIN_MISMATCH")
    for key in ("handoff_socket", "status_file", "office_register_socket", "pdf_register_socket"):
        require(_safe_path(value["dispatcher"][key]), "CONFIG_PATH_INVALID")
    for key in ("runc_path", "runtime_dir", "runc_state_root", "bundle_root", "cgroup_root", "oci_archive", "rootfs", "rootfs_identity"):
        require(_safe_path(value["runtime"][key]), "CONFIG_PATH_INVALID")
    return value


def load_config(path: str = "/etc/knowvault/native-ingest-supervisor.json") -> dict[str, Any]:
    require(sys.platform == "linux", "LINUX_REQUIRED")
    try:
        fd = _open_absolute_regular(path)
    except SupervisorFailure as exc:
        raise SupervisorFailure("CONFIG_UNAVAILABLE") from exc
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "CONFIG_FILE_UNSAFE")
        raw = os.read(fd, 64 * 1024 + 1)
        require(0 < len(raw) <= 64 * 1024, "CONFIG_SIZE_INVALID")
    finally:
        os.close(fd)
    return validate_config(strict_json_loads(raw))


def _sha256_fd(fd: int) -> str:
    before = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    after = os.fstat(fd)
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        "PINNED_FILE_CHANGED",
    )
    return digest.hexdigest()


def _open_pinned_regular(path: str) -> int:
    try:
        fd = _open_absolute_regular(path)
    except SupervisorFailure as exc:
        raise SupervisorFailure("PINNED_FILE_UNAVAILABLE") from exc
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or (stat.S_IMODE(info.st_mode) & 0o022) != 0:
        os.close(fd)
        raise SupervisorFailure("PINNED_FILE_UNSAFE")
    return fd


def _open_verified_runc(
    path: str,
    expected_sha256: str,
    expected_identity: tuple[int, int, int, int] | None = None,
) -> tuple[int, tuple[int, int, int, int]]:
    fd = _open_pinned_regular(path)
    try:
        before = os.fstat(fd)
        digest = _sha256_fd(fd)
        after = os.fstat(fd)
        identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == identity
            and digest == expected_sha256,
            "RUNC_DIGEST_MISMATCH",
        )
        if expected_identity is not None:
            require(identity == expected_identity, "RUNC_IDENTITY_CHANGED")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def _read_tar_member(archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str, cap: int) -> bytes:
    member = members.get(name)
    require(member is not None and member.isfile() and member.size <= cap, "OCI_MEMBER_INVALID")
    file_obj = archive.extractfile(member)
    require(file_obj is not None, "OCI_MEMBER_INVALID")
    with file_obj:
        data = file_obj.read(cap + 1)
    require(len(data) == member.size and len(data) <= cap, "OCI_MEMBER_INVALID")
    return data


def _hash_tar_member(archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str, expected: str) -> None:
    member = members.get(name)
    require(member is not None and member.isfile(), "OCI_MEMBER_INVALID")
    file_obj = archive.extractfile(member)
    require(file_obj is not None, "OCI_MEMBER_INVALID")
    digest = hashlib.sha256()
    length = 0
    with file_obj:
        while True:
            block = file_obj.read(1024 * 1024)
            if not block:
                break
            length += len(block)
            digest.update(block)
    require(length == member.size and digest.hexdigest() == expected, "OCI_BLOB_DIGEST_MISMATCH")


def verify_oci_archive(path: str, pins: dict[str, Any] = PINNED) -> list[str]:
    fd = _open_pinned_regular(path)
    try:
        require(_sha256_fd(fd) == pins["oci_archive_sha256"], "OCI_ARCHIVE_DIGEST_MISMATCH")
        os.lseek(fd, 0, os.SEEK_SET)
        duplicate = os.dup(fd)
        with os.fdopen(duplicate, "rb", closefd=True) as stream:
            try:
                archive = tarfile.open(fileobj=stream, mode="r:*")
            except (tarfile.TarError, OSError) as exc:
                raise SupervisorFailure("OCI_ARCHIVE_INVALID") from exc
            with archive:
                infos = archive.getmembers()
                require(0 < len(infos) <= 4096, "OCI_ARCHIVE_MEMBERS_INVALID")
                members: dict[str, tarfile.TarInfo] = {}
                for info in infos:
                    name = info.name.rstrip("/")
                    pure = pathlib.PurePosixPath(name)
                    require(name and not pure.is_absolute() and ".." not in pure.parts, "OCI_ARCHIVE_PATH_INVALID")
                    require(name not in members and (info.isfile() or info.isdir()), "OCI_ARCHIVE_MEMBER_UNSAFE")
                    members[name] = info
                layout = strict_json_loads(_read_tar_member(archive, members, "oci-layout", 4096))
                require(layout == {"imageLayoutVersion": "1.0.0"}, "OCI_LAYOUT_INVALID")
                index = strict_json_loads(_read_tar_member(archive, members, "index.json", 64 * 1024))
                require(isinstance(index, dict) and index.get("schemaVersion") == 2 and isinstance(index.get("manifests"), list), "OCI_INDEX_INVALID")
                require(len(index["manifests"]) == 1, "OCI_INDEX_INVALID")
                descriptor = index["manifests"][0]
                require(
                    isinstance(descriptor, dict)
                    and descriptor.get("digest") == pins["oci_manifest_digest"]
                    and descriptor.get("platform") == {"architecture": "amd64", "os": "linux"},
                    "OCI_MANIFEST_PIN_MISMATCH",
                )
                manifest_digest = pins["oci_manifest_digest"].removeprefix("sha256:")
                manifest_name = "blobs/sha256/" + manifest_digest
                manifest_body = _read_tar_member(archive, members, manifest_name, 1024 * 1024)
                require(hashlib.sha256(manifest_body).hexdigest() == manifest_digest, "OCI_MANIFEST_DIGEST_MISMATCH")
                manifest = strict_json_loads(manifest_body)
                require(isinstance(manifest, dict) and manifest.get("schemaVersion") == 2, "OCI_MANIFEST_INVALID")
                config_desc = manifest.get("config")
                require(isinstance(config_desc, dict) and config_desc.get("digest") == pins["oci_config_digest"], "OCI_CONFIG_PIN_MISMATCH")
                layers = manifest.get("layers")
                require(isinstance(layers, list) and [layer.get("digest") for layer in layers if isinstance(layer, dict)] == pins["layers"], "OCI_LAYERS_PIN_MISMATCH")
                config_digest = pins["oci_config_digest"].removeprefix("sha256:")
                config_name = "blobs/sha256/" + config_digest
                config_body = _read_tar_member(archive, members, config_name, 1024 * 1024)
                require(hashlib.sha256(config_body).hexdigest() == config_digest, "OCI_CONFIG_DIGEST_MISMATCH")
                image_config = strict_json_loads(config_body)
                process_config = image_config.get("config") if isinstance(image_config, dict) else None
                require(
                    isinstance(image_config, dict)
                    and image_config.get("architecture") == "amd64"
                    and image_config.get("os") == "linux"
                    and isinstance(process_config, dict)
                    and process_config.get("Entrypoint") == pins["entrypoint"]
                    and process_config.get("WorkingDir") == pins["working_dir"]
                    and process_config.get("Cmd") in (None, []),
                    "OCI_PROCESS_CONFIG_MISMATCH",
                )
                environment = process_config.get("Env", [])
                require(isinstance(environment, list) and all(isinstance(item, str) and "=" in item for item in environment), "OCI_ENV_INVALID")
                forbidden = ("password", "secret", "token", "credential", "database", "source")
                for item in environment:
                    name = item.split("=", 1)[0].lower()
                    require(not any(word in name for word in forbidden), "OCI_ENV_FORBIDDEN")
                require(image_config.get("rootfs", {}).get("type") == "layers", "OCI_ROOTFS_INVALID")
                for layer in pins["layers"]:
                    _hash_tar_member(archive, members, "blobs/sha256/" + layer.removeprefix("sha256:"), layer.removeprefix("sha256:"))
                return list(environment)
    finally:
        os.close(fd)


def rootfs_tree_sha256(root: str, max_entries: int = 200_000, max_bytes: int = 2 * 1024 * 1024 * 1024) -> str:
    root_fd = _open_absolute_directory(root)
    root_info = os.fstat(root_fd)
    require(stat.S_ISDIR(root_info.st_mode), "ROOTFS_UNSAFE")
    records: list[dict[str, Any]] = []
    total_bytes = 0
    entries = 0

    def visit(directory_fd: int, parent: str) -> None:
        nonlocal entries, total_bytes
        before_directory = os.fstat(directory_fd)
        for name in sorted(os.listdir(directory_fd)):
            relative = name if not parent else parent + "/" + name
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            entries += 1
            require(entries <= max_entries, "ROOTFS_ENTRY_LIMIT")
            record: dict[str, Any] = {
                "path": relative,
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
            }
            if stat.S_ISLNK(info.st_mode):
                record["type"] = "symlink"
                record["target"] = os.readlink(name, dir_fd=directory_fd)
            elif stat.S_ISDIR(info.st_mode):
                record["type"] = "directory"
                child_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child_fd)
                    require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino) and stat.S_ISDIR(opened.st_mode), "ROOTFS_CHANGED")
                    visit(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                record["type"] = "file"
                digest = hashlib.sha256()
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                file_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(file_fd)
                    require(
                        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                        == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                        and stat.S_ISREG(opened.st_mode),
                        "ROOTFS_CHANGED",
                    )
                    file_bytes = 0
                    while True:
                        block = os.read(file_fd, 1024 * 1024)
                        if not block:
                            break
                        file_bytes += len(block)
                        total_bytes += len(block)
                        require(total_bytes <= max_bytes, "ROOTFS_SIZE_LIMIT")
                        digest.update(block)
                    after = os.fstat(file_fd)
                    require(
                        file_bytes == info.st_size
                        and (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                        "ROOTFS_CHANGED",
                    )
                finally:
                    os.close(file_fd)
                record["size"] = file_bytes
                record["sha256"] = digest.hexdigest()
            else:
                raise SupervisorFailure("ROOTFS_ENTRY_UNSAFE")
            records.append(record)

        after_directory = os.fstat(directory_fd)
        require(
            (before_directory.st_dev, before_directory.st_ino, before_directory.st_mtime_ns)
            == (after_directory.st_dev, after_directory.st_ino, after_directory.st_mtime_ns),
            "ROOTFS_CHANGED",
        )

    try:
        visit(root_fd, "")
    finally:
        os.close(root_fd)
    records.sort(key=lambda record: record["path"].encode("utf-8", "surrogateescape"))
    digest = hashlib.sha256()
    for record in records:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


def _read_file_secure(path: str, max_bytes: int, mode: int | None = None) -> bytes:
    fd = _open_pinned_regular(path)
    try:
        info = os.fstat(fd)
        if mode is not None:
            require(stat.S_IMODE(info.st_mode) == mode, "PINNED_FILE_UNSAFE")
        raw = os.read(fd, max_bytes + 1)
        require(len(raw) <= max_bytes, "PINNED_FILE_SIZE_INVALID")
        return raw
    finally:
        os.close(fd)


def _rootfs_file_path(root: str, relative: str) -> str:
    components = pathlib.PurePosixPath(relative).parts
    require(components and not pathlib.PurePosixPath(relative).is_absolute() and ".." not in components, "ROOTFS_PATH_INVALID")
    return str(pathlib.PurePosixPath(root).joinpath(*components))


def _open_rootfs_file(root: str, relative: str) -> int:
    components = pathlib.PurePosixPath(relative).parts
    require(components and not pathlib.PurePosixPath(relative).is_absolute() and ".." not in components, "ROOTFS_PATH_INVALID")
    current_fd = _open_absolute_directory(root)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for component in components[:-1]:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise SupervisorFailure("ROOTFS_PATH_UNSAFE") from exc
            os.close(current_fd)
            current_fd = next_fd
        try:
            fd = os.open(components[-1], flags, dir_fd=current_fd)
        except OSError as exc:
            raise SupervisorFailure("ROOTFS_FILE_UNAVAILABLE") from exc
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise SupervisorFailure("ROOTFS_FILE_INVALID")
        return fd
    finally:
        os.close(current_fd)


def _hash_rootfs_file(root: str, relative: str, cap: int) -> str:
    fd = _open_rootfs_file(root, relative)
    try:
        before = os.fstat(fd)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= cap, "ROOTFS_FILE_SIZE_INVALID")
            digest.update(block)
        after = os.fstat(fd)
        require(total == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "ROOTFS_CHANGED")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _read_rootfs_file(root: str, relative: str, cap: int) -> bytes:
    fd = _open_rootfs_file(root, relative)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "ROOTFS_FILE_INVALID")
        raw = os.read(fd, cap + 1)
        require(len(raw) <= cap and len(raw) == info.st_size, "ROOTFS_FILE_SIZE_INVALID")
        return raw
    finally:
        os.close(fd)


def verify_prepared_rootfs(root: str, identity_path: str, pins: dict[str, Any] = PINNED) -> str:
    root_info = os.lstat(root)
    require(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == 0 and (stat.S_IMODE(root_info.st_mode) & 0o022) == 0, "ROOTFS_UNSAFE")
    identity = strict_json_loads(_read_file_secure(identity_path, 4096, 0o444))
    required = {
        "schema_version",
        "oci_archive_sha256",
        "oci_manifest_digest",
        "oci_config_digest",
        "artifact_hash",
        "rootfs_tree_sha256",
    }
    require(isinstance(identity, dict) and set(identity) == required, "ROOTFS_IDENTITY_INVALID")
    require(
        identity["schema_version"] == ROOTFS_SCHEMA
        and identity["oci_archive_sha256"] == pins["oci_archive_sha256"]
        and identity["oci_manifest_digest"] == pins["oci_manifest_digest"]
        and identity["oci_config_digest"] == pins["oci_config_digest"]
        and identity["artifact_hash"] == pins["artifact_hash"],
        "ROOTFS_IDENTITY_MISMATCH",
    )
    require(isinstance(identity["rootfs_tree_sha256"], str) and SHA256_RE.fullmatch(identity["rootfs_tree_sha256"]) is not None, "ROOTFS_IDENTITY_INVALID")
    require(identity["rootfs_tree_sha256"] == pins["rootfs_tree_sha256"], "ROOTFS_IDENTITY_MISMATCH")
    require(rootfs_tree_sha256(root) == identity["rootfs_tree_sha256"], "ROOTFS_TREE_MISMATCH")
    artifact = _read_rootfs_file(root, "app/artifact.sha256", 256).decode("ascii", "strict").strip()
    require(artifact == pins["artifact_hash"], "WORKER_ARTIFACT_MISMATCH")
    require(_hash_rootfs_file(root, "app/document-parser-worker.jar", 512 * 1024 * 1024) == pins["worker_jar_sha256"], "WORKER_JAR_MISMATCH")
    java_fd = _open_rootfs_file(root, "opt/jre/bin/java")
    try:
        java_info = os.fstat(java_fd)
        require((java_info.st_mode & 0o111) != 0, "WORKER_ENTRYPOINT_UNAVAILABLE")
    finally:
        os.close(java_fd)
    return identity["rootfs_tree_sha256"]


def build_oci_spec(
    rootfs: str,
    registration_socket_dir: str,
    parser_type: str,
    uid: int,
    gid: int,
    entrypoint: list[str],
    environment: list[str],
    container_id: str,
    handoff_id: str,
    cgroup_path: str,
) -> dict[str, Any]:
    require(parser_type in {"OFFICE", "PDF"}, "ROLE_INVALID")
    expected_uid = 65532 if parser_type == "OFFICE" else 65533
    expected_registration_dir = "/run/knowvault/sandbox/office" if parser_type == "OFFICE" else "/run/knowvault/sandbox/pdf"
    require(uid == expected_uid and gid == expected_uid, "ROLE_IDENTITY_INVALID")
    require(registration_socket_dir == expected_registration_dir, "REGISTRATION_PATH_INVALID")
    require(ROLE_HANDOFF_RE.fullmatch(handoff_id) is not None, "HANDOFF_ID_INVALID")
    require(re.fullmatch(r"kvp-" + parser_type.lower() + r"-[0-9a-f]{32}", container_id) is not None, "RUNTIME_ID_INVALID")
    require(cgroup_path == "/knowvault_native.slice/knowvault-native-supervisor.service/parsers/" + container_id, "CGROUP_PATH_INVALID")
    require(entrypoint == PINNED["entrypoint"], "ENTRYPOINT_PIN_MISMATCH")
    args = list(entrypoint) + [
        "--mode=dispatcher-once",
        "--socket=unix:///run/knowvault/register.sock",
        "--worker-id=" + container_id,
        "--parser-type=" + parser_type,
        "--supervisor-handoff-id=" + handoff_id,
    ]
    return {
        "ociVersion": "1.1.0",
        "root": {"path": rootfs, "readonly": True},
        "process": {
            "terminal": False,
            "user": {"uid": uid, "gid": gid},
            "args": args,
            "env": list(environment),
            "cwd": PINNED["working_dir"],
            "noNewPrivileges": True,
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
        },
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "noexec", "size=67108864", "mode=1777"]},
            {
                "destination": "/run/knowvault",
                "type": "bind",
                "source": registration_socket_dir,
                "options": ["rbind", "ro", "nosuid", "nodev", "noexec"],
            },
        ],
        "linux": {
            "namespaces": [{"type": kind} for kind in ("pid", "network", "mount", "ipc", "uts")],
            "cgroupsPath": cgroup_path,
            "resources": {
                "memory": {"limit": 64 * 1024 * 1024},
                "cpu": {"quota": 10_000, "period": 100_000},
                "pids": {"limit": 16},
            },
            "rootfsPropagation": "private",
        },
    }


@dataclass
class RoleSpec:
    parser_type: str
    uid: int
    gid: int
    observation_profile_revision: str
    registration_socket: str


@dataclass
class OwnedRun:
    role: str
    container_id: str
    handoff_id: str
    cgroup_name: str
    cgroup_path: str
    epoch: str
    pid: int
    pidfd: int
    parent_cgroup_fd: int
    cgroup_fd: int
    parent_identity: tuple[int, int]
    cgroup_identity: tuple[int, int]
    bundle_path: str
    started: bool = False
    reap_status_deadline: float | None = None


def _read_at(dir_fd: int, name: str, limit: int = 1024) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        raw = os.read(fd, limit + 1)
        require(len(raw) <= limit, "CGROUP_FILE_TOO_LARGE")
        return raw.decode("ascii", "strict").strip()
    finally:
        os.close(fd)


def validate_empty_cgroup_parent(children: list[tuple[str, int]]) -> None:
    """Reject every child object except the regular virtual cgroup-v2 files."""
    require(all(stat.S_ISREG(mode) for _name, mode in children), "CGROUP_PARENT_NOT_EMPTY")


def _file_identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _read_fdinfo_pid(pidfd: int) -> int:
    try:
        with open(f"/proc/self/fdinfo/{pidfd}", "rt", encoding="ascii") as source:
            for line in source:
                if line.startswith("Pid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError) as exc:
        raise SupervisorFailure("PIDFD_UNAVAILABLE") from exc
    raise SupervisorFailure("PIDFD_UNAVAILABLE")


def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _recv_exact_no_fds(conn: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        data, ancillary, flags, _ = conn.recvmsg(remaining, socket.CMSG_SPACE(256))
        if ancillary:
            for level, kind, payload in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors = array.array("i")
                    usable = len(payload) - (len(payload) % descriptors.itemsize)
                    descriptors.frombytes(payload[:usable])
                    for descriptor in descriptors:
                        os.close(descriptor)
            raise SupervisorFailure("HANDOFF_ACK_ANCILLARY_INVALID")
        if flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)) or not data:
            raise SupervisorFailure("HANDOFF_ACK_INVALID")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def send_handoff_and_wait_ack(path: str, metadata: dict[str, Any], pidfd: int, timeout: float) -> None:
    raw = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    require(0 < len(raw) <= FRAME_LIMIT, "HANDOFF_SIZE_INVALID")
    header = bytes((HANDOFF_KIND,)) + struct.pack(">I", len(raw))
    info = os.lstat(path)
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600, "HANDOFF_SOCKET_UNSAFE")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
    client.settimeout(timeout)
    try:
        client.connect(path)
        connected = os.lstat(path)
        require(_file_identity(connected) == _file_identity(info) and stat.S_ISSOCK(connected.st_mode), "HANDOFF_SOCKET_CHANGED")
        peer = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, gid = struct.unpack("3i", peer)
        require(uid == 0 and gid == 0, "HANDOFF_PEER_INVALID")
        sent = client.sendmsg([header], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [pidfd]))])
        require(sent > 0, "HANDOFF_SEND_FAILED")
        if sent < len(header):
            client.sendall(header[sent:])
        client.sendall(raw)
        response_header = _recv_exact_no_fds(client, 5)
        kind = response_header[0]
        length = struct.unpack(">I", response_header[1:])[0]
        require(kind == HANDOFF_ACCEPTED_KIND and length == len(HANDOFF_ACCEPTED_BODY), "HANDOFF_ACK_INVALID")
        body = _recv_exact_no_fds(client, length)
        require(body == HANDOFF_ACCEPTED_BODY, "HANDOFF_ACK_INVALID")
    except SupervisorFailure:
        raise
    except OSError as exc:
        raise SupervisorFailure("HANDOFF_UNAVAILABLE") from exc
    finally:
        client.close()


def _status_roles(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return snapshot["roles"]


class NativeSupervisor:
    def __init__(self, config: dict[str, Any], stop_event: Any | None = None):
        self.config = validate_config(config)
        self.stop_requested = False
        self.stop_event = stop_event
        self.status: StatusReader | None = None
        self.epoch: str | None = None
        self.directory_identities: dict[str, tuple[int, int]] | None = None
        self.active: dict[str, OwnedRun] = {}
        self.runtime = self.config["runtime"]
        self.dispatcher = self.config["dispatcher"]
        self.roles = {
            role["parser_type"]: RoleSpec(
                role["parser_type"], role["uid"], role["gid"],
                role["observation_profile_revision"], role["registration_socket"],
            )
            for role in self.config["roles"]
        }
        self._runtime_dir_fd = -1
        self._bundle_root_fd = -1
        self._runc_state_fd = -1
        self._lock_fd = -1
        self._cgroup_root_fd = -1
        self._environment: list[str] = []
        self._runc_identity: tuple[int, int, int, int] | None = None
        self._shutdown_deadline: float | None = None

    def _log(self, code: str, role: str | None = None) -> None:
        if role is None:
            print(json.dumps({"component": "native-ingest-supervisor", "code": code}, separators=(",", ":")), file=sys.stderr, flush=True)
        else:
            print(json.dumps({"component": "native-ingest-supervisor", "code": code, "role": role}, separators=(",", ":")), file=sys.stderr, flush=True)

    def _open_owned_dir(self, path: str, mode: int = 0o700) -> int:
        try:
            fd = _open_absolute_directory(path)
        except SupervisorFailure as exc:
            raise SupervisorFailure("DIRECTORY_UNAVAILABLE") from exc
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
            os.close(fd)
            raise SupervisorFailure("DIRECTORY_UNSAFE")
        return fd

    def _prepare_runtime_directories(self) -> None:
        self._runtime_dir_fd = self._open_owned_dir(self.runtime["runtime_dir"])
        require(fcntl is not None, "LINUX_FLOCK_UNAVAILABLE")
        self._lock_fd = os.open("supervisor.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=self._runtime_dir_fd)
        lock_info = os.fstat(self._lock_fd)
        require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 0 and stat.S_IMODE(lock_info.st_mode) == 0o600 and lock_info.st_nlink == 1, "SUPERVISOR_LOCK_UNSAFE")
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise SupervisorFailure("SUPERVISOR_ALREADY_RUNNING") from exc
        for name in ("runc-state", "bundles"):
            try:
                os.mkdir(name, 0o700, dir_fd=self._runtime_dir_fd)
            except FileExistsError:
                pass
            fd = _open_dir_component(self._runtime_dir_fd, name)
            info = os.fstat(fd)
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "RUNTIME_DIRECTORY_UNSAFE")
            if name == "runc-state":
                self._runc_state_fd = fd
                self._runc_state_empty_at_startup()
            else:
                self._bundle_root_fd = fd
                require(os.listdir(fd) == [], "STALE_RUNTIME_BUNDLE")

    def _runc_state_empty_at_startup(self) -> None:
        require(os.listdir(self._runc_state_fd) == [], "STALE_RUNC_STATE")

    def _verify_runtime_binary(self) -> None:
        fd, identity = _open_verified_runc(
            self.runtime["runc_path"],
            self.config["image"]["runc_sha256"],
        )
        try:
            self._runc_identity = identity
        finally:
            os.close(fd)

    def _verify_offline_image(self) -> None:
        self._environment = verify_oci_archive(self.runtime["oci_archive"], self.config["image"])
        verify_prepared_rootfs(self.runtime["rootfs"], self.runtime["rootfs_identity"], self.config["image"])

    def _verify_dispatcher_sockets(self) -> None:
        require(self.directory_identities is not None, "SOCKET_DIRECTORY_UNVERIFIED")
        verify_prepared_host_directories(self.config, self.directory_identities)
        self._verify_unix_socket(self.dispatcher["handoff_socket"], 0, 0)
        for role in self.roles.values():
            self._verify_unix_socket(role.registration_socket, role.uid, role.gid)

    @staticmethod
    def _verify_unix_socket(path: str, uid: int, gid: int) -> None:
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise SupervisorFailure("DISPATCHER_SOCKET_UNAVAILABLE") from exc
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == uid and info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o600, "DISPATCHER_SOCKET_UNSAFE")

    def _prepare_cgroup_parent(self) -> None:
        # systemd owns the slice and unit cgroup. DelegateSubgroup keeps this
        # service in a leaf; only the delegated tree beneath the unit is ours.
        unit_path = str(pathlib.PurePosixPath(self.runtime["cgroup_root"]).parent)
        unit_fd = self._open_owned_dir(unit_path, 0o755)
        try:
            with open("/proc/self/cgroup", "rt", encoding="ascii") as current:
                require(current.read().strip() == "0::" + unit_path.removeprefix("/sys/fs/cgroup") + "/supervisor", "SUPERVISOR_CGROUP_INVALID")
            require(_read_at(unit_fd, "cgroup.procs") == "", "CGROUP_PARENT_HAS_PROCESS")
            self._enable_delegated_controllers(unit_fd)
            try:
                os.mkdir("parsers", 0o755, dir_fd=unit_fd)
            except FileExistsError:
                pass
        finally:
            os.close(unit_fd)
        self._cgroup_root_fd = self._open_owned_dir(self.runtime["cgroup_root"], 0o755)
        require(_read_at(self._cgroup_root_fd, "cgroup.procs") == "", "CGROUP_PARENT_HAS_PROCESS")
        validate_empty_cgroup_parent(
            [
                (name, os.stat(name, dir_fd=self._cgroup_root_fd, follow_symlinks=False).st_mode)
                for name in os.listdir(self._cgroup_root_fd)
            ]
        )
        self._enable_delegated_controllers(self._cgroup_root_fd)

    @staticmethod
    def _enable_delegated_controllers(fd: int) -> None:
        controllers = {"cpu", "memory", "pids"}
        require(controllers.issubset(set(_read_at(fd, "cgroup.controllers").split())), "CGROUP_CONTROLLERS_UNAVAILABLE")
        if not controllers.issubset(set(_read_at(fd, "cgroup.subtree_control").split())):
            control = os.open("cgroup.subtree_control", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            try:
                command = b"+cpu +memory +pids"
                require(os.write(control, command) == len(command), "CGROUP_CONTROLLERS_NOT_ENABLED")
            finally:
                os.close(control)
        require(controllers.issubset(set(_read_at(fd, "cgroup.subtree_control").split())), "CGROUP_CONTROLLERS_NOT_ENABLED")

    def _read_current_status(self) -> dict[str, Any]:
        require(self.directory_identities is not None, "SOCKET_DIRECTORY_UNVERIFIED")
        verify_prepared_host_directories(self.config, self.directory_identities)
        require(self.status is not None, "STATUS_READER_UNAVAILABLE")
        snapshot = self.status.read(initial_running=self.epoch is None)
        if self.epoch is None:
            self.epoch = snapshot["dispatcher_epoch"]
        require(snapshot["dispatcher_epoch"] == self.epoch, "STATUS_EPOCH_CHANGED")
        require(snapshot["dispatcher_state"] != "red", "DISPATCHER_RED")
        return snapshot

    def _wait_for_dispatcher(self) -> dict[str, Any]:
        deadline = time.monotonic() + self.runtime["ready_timeout_seconds"]
        last_error: SupervisorFailure | None = None
        while time.monotonic() < deadline:
            if self.stop_requested:
                raise SupervisorFailure("STOP_REQUESTED")
            try:
                if self.status is None:
                    self.status = StatusReader(self.dispatcher["status_file"])
                snapshot = self._read_current_status()
                require(snapshot["dispatcher_state"] == "running", "DISPATCHER_NOT_RUNNING")
                self._verify_dispatcher_sockets()
                return snapshot
            except SupervisorFailure as exc:
                last_error = exc
                if exc.code in {"STATUS_EPOCH_CHANGED", "DISPATCHER_RED", "STATUS_FROM_FUTURE", "STATUS_SEQUENCE_ROLLBACK"}:
                    raise
                time.sleep(self.runtime["status_poll_seconds"])
        raise last_error or SupervisorFailure("DISPATCHER_START_TIMEOUT")

    def _create_cgroup(self, role: RoleSpec, container_id: str) -> tuple[int, int, str, tuple[int, int], tuple[int, int]]:
        cgroup_name = container_id
        try:
            os.mkdir(cgroup_name, 0o755, dir_fd=self._cgroup_root_fd)
        except OSError as exc:
            raise SupervisorFailure("CGROUP_CREATE_FAILED") from exc
        parent_fd = os.dup(self._cgroup_root_fd)
        try:
            fd = _open_dir_component(parent_fd, cgroup_name)
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, "CGROUP_DIRECTORY_UNSAFE")
            cgroup_path = self.runtime["cgroup_root"].removeprefix("/sys/fs/cgroup") + "/" + cgroup_name
            identity = _file_identity(info)
            parent_identity = _file_identity(os.fstat(parent_fd))
            return parent_fd, fd, cgroup_path, parent_identity, identity
        except BaseException:
            os.close(parent_fd)
            raise

    def _new_container_id(self, role: str) -> str:
        return "kvp-" + role.lower() + "-" + os.urandom(16).hex()

    def _new_handoff_id(self) -> str:
        return os.urandom(32).hex()

    def _create_bundle(self, container_id: str, spec: dict[str, Any]) -> str:
        try:
            os.mkdir(container_id, 0o700, dir_fd=self._bundle_root_fd)
        except OSError as exc:
            raise SupervisorFailure("BUNDLE_CREATE_FAILED") from exc
        bundle_path = self.runtime["bundle_root"] + "/" + container_id
        bundle_fd = _open_dir_component(self._bundle_root_fd, container_id)
        try:
            info = os.fstat(bundle_fd)
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "BUNDLE_UNSAFE")
            body = json.dumps(spec, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            fd = os.open("config.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=bundle_fd)
            try:
                view = memoryview(body)
                while view:
                    count = os.write(fd, view)
                    require(count > 0, "BUNDLE_CONFIG_WRITE_FAILED")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(bundle_fd)
        return bundle_path

    def _run_runc(self, *args: str, timeout: float = 15) -> bytes:
        if self._runc_identity is None:
            self._verify_runtime_binary()
        runc_fd, _current_identity = _open_verified_runc(
            self.runtime["runc_path"],
            self.config["image"]["runc_sha256"],
            self._runc_identity,
        )
        argv = [
            f"/proc/self/fd/{runc_fd}",
            "--root",
            self.runtime["runc_state_root"],
            *args,
        ]
        try:
            result = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                # create's stopped init inherits stdio. A PIPE would keep
                # communicate() waiting for its EOF before the handoff can
                # authorize start. Only the short-lived state query has JSON.
                stdout=subprocess.PIPE if args and args[0] == "state" else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout,
                shell=False,
                close_fds=True,
                pass_fds=(runc_fd,),
                umask=0o077,
                env={"PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C"},
            )
        except subprocess.TimeoutExpired as exc:
            raise SupervisorFailure("RUNC_TIMEOUT") from exc
        except OSError as exc:
            raise SupervisorFailure("RUNC_UNAVAILABLE") from exc
        finally:
            os.close(runc_fd)
        require(result.returncode == 0, "RUNC_COMMAND_FAILED")
        return result.stdout or b""

    def _verify_runc_state(self, run: OwnedRun, pid_file: str) -> None:
        try:
            fd = _open_pinned_regular(pid_file)
        except SupervisorFailure:
            raise SupervisorFailure("RUNC_PIDFILE_UNSAFE")
        try:
            info = os.fstat(fd)
            require(stat.S_IMODE(info.st_mode) == 0o600, "RUNC_PIDFILE_UNSAFE")
            pid_raw = os.read(fd, 32)
        finally:
            os.close(fd)
        require(re.fullmatch(rb"[1-9][0-9]{0,9}\n?", pid_raw) is not None, "RUNC_PID_INVALID")
        pid = int(pid_raw.strip())
        state_raw = self._run_runc("state", run.container_id, timeout=5)
        state = strict_json_loads(state_raw)
        require(
            isinstance(state, dict)
            and state.get("id") == run.container_id
            and state.get("status") == "created"
            and state.get("pid") == pid
            and state.get("bundle") == run.bundle_path,
            "RUNC_STATE_MISMATCH",
        )
        try:
            pidfd = os.pidfd_open(pid, 0)
        except OSError as exc:
            raise SupervisorFailure("PIDFD_OPEN_FAILED") from exc
        os.set_inheritable(pidfd, False)
        if _read_fdinfo_pid(pidfd) != pid:
            os.close(pidfd)
            raise SupervisorFailure("PIDFD_IDENTITY_MISMATCH")
        try:
            namespace_inode = os.stat(f"/proc/{pid}/ns/pid").st_ino
            with open(f"/proc/{pid}/cgroup", "rt", encoding="ascii") as source:
                cgroup_lines = source.read(4096).splitlines()
            expected_cgroup = "0::" + run.cgroup_path
            require(cgroup_lines == [expected_cgroup], "PID_CGROUP_MISMATCH")
            with open(f"/proc/{pid}/status", "rt", encoding="ascii") as source:
                status_lines = source.read(8192).splitlines()
            uid_line = next(line for line in status_lines if line.startswith("Uid:"))
            gid_line = next(line for line in status_lines if line.startswith("Gid:"))
            uid_values = [int(value) for value in uid_line.split()[1:5]]
            gid_values = [int(value) for value in gid_line.split()[1:5]]
            role = self.roles[run.role]
            require(uid_values == [role.uid] * 4 and gid_values == [role.gid] * 4, "PID_IDENTITY_MISMATCH")
            require(_read_fdinfo_pid(pidfd) == pid, "PIDFD_IDENTITY_MISMATCH")
            cgroup_procs = _read_at(run.cgroup_fd, "cgroup.procs").split()
            require(cgroup_procs == [str(pid)], "CGROUP_PEER_MISMATCH")
            require(_read_at(run.cgroup_fd, "cpu.max") == "10000 100000", "CGROUP_CPU_LIMIT_MISMATCH")
            require(_read_at(run.cgroup_fd, "memory.max") == str(64 * 1024 * 1024), "CGROUP_MEMORY_LIMIT_MISMATCH")
            require(_read_at(run.cgroup_fd, "pids.max") == "16", "CGROUP_PIDS_LIMIT_MISMATCH")
            events = dict(
                item.split()
                for item in _read_at(run.cgroup_fd, "cgroup.events").splitlines()
                if len(item.split()) == 2
            )
            require(events.get("populated") == "1", "CGROUP_NOT_POPULATED")
        except BaseException:
            os.close(pidfd)
            raise
        run.pid = pid
        run.pidfd = pidfd
        run.namespace_inode = str(namespace_inode)

    def _build_handoff(self, run: OwnedRun, role: RoleSpec) -> dict[str, Any]:
        now = dt.datetime.now(dt.timezone.utc)
        lifetime = self.runtime["handoff_lifetime_seconds"]
        issued = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
        expires = (now + dt.timedelta(seconds=lifetime)).isoformat(timespec="microseconds").replace("+00:00", "Z")
        return {
            "schema_version": HANDOFF_SCHEMA,
            "handoff_id": run.handoff_id,
            "parser_type": role.parser_type,
            "artifact_hash": self.config["image"]["artifact_hash"],
            "sandbox_profile_revision": self.config["image"]["sandbox_profile_revision"],
            "observation_profile_revision": role.observation_profile_revision,
            "pidfd_transport": "SCM_RIGHTS",
            "pid_namespace_inode": run.namespace_inode,
            "cgroup_path": run.cgroup_path,
            "expected_worker_uid": role.uid,
            "expected_worker_gid": role.gid,
            "issued_at": issued,
            "expires_at": expires,
            "one_shot": True,
            "max_leases": 1,
        }

    def _wait_status_role(self, role: str, handoff_id: str, expected_state: str, epoch: str, timeout: float, min_sequence: int) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.stop_requested:
                raise SupervisorFailure("STOP_REQUESTED")
            snapshot = self._read_current_status()
            if snapshot["dispatcher_state"] == "stopping":
                self.request_stop()
                raise SupervisorFailure("STOP_REQUESTED")
            require(snapshot["dispatcher_epoch"] == epoch, "STATUS_EPOCH_CHANGED")
            role_status = _status_roles(snapshot)[role]
            if role_status["state"] == "red":
                raise SupervisorFailure("DISPATCHER_RED")
            if role_status["state"] not in {"empty", "reaped"} or (
                expected_state == "ready" and role_status["state"] == "reaped" and role_status["handoff_id"] == handoff_id
            ):
                require(role_status["handoff_id"] == handoff_id, "STATUS_HANDOFF_MISMATCH")
                # Admission may consume READY before the next status poll.
                # BUSY/REAPED for this handoff prove registration already
                # happened; neither can release a pre-exec handoff barrier.
                observed = role_status["state"] == expected_state or (
                    expected_state == "ready" and role_status["state"] in {"busy", "reaped"}
                )
                if observed and snapshot["sequence"] > min_sequence:
                    return snapshot
            time.sleep(self.runtime["status_poll_seconds"])
        raise SupervisorFailure("STATUS_TRANSITION_TIMEOUT")

    def _launch_role(self, role_name: str, baseline: dict[str, Any]) -> OwnedRun:
        if self.stop_requested or baseline["dispatcher_state"] == "stopping":
            self.request_stop()
            raise SupervisorFailure("STOP_REQUESTED")
        require(self.directory_identities is not None, "SOCKET_DIRECTORY_UNVERIFIED")
        verify_prepared_host_directories(self.config, self.directory_identities)
        require(baseline["dispatcher_state"] == "running", "DISPATCHER_NOT_RUNNING")
        role_status = baseline["roles"][role_name]
        require(role_status["state"] in {"empty", "reaped"}, "ROLE_ALREADY_OWNED")
        role = self.roles[role_name]
        container_id = self._new_container_id(role_name)
        handoff_id = self._new_handoff_id()
        parent_fd, cgroup_fd, cgroup_path, parent_identity, cgroup_identity = self._create_cgroup(role, container_id)
        run = OwnedRun(
            role=role_name,
            container_id=container_id,
            handoff_id=handoff_id,
            cgroup_name=container_id,
            cgroup_path=cgroup_path,
            epoch=baseline["dispatcher_epoch"],
            pid=0,
            pidfd=-1,
            parent_cgroup_fd=parent_fd,
            cgroup_fd=cgroup_fd,
            parent_identity=parent_identity,
            cgroup_identity=cgroup_identity,
            bundle_path="",
        )
        self.active[role_name] = run
        registration_dir = str(pathlib.PurePosixPath(role.registration_socket).parent)
        spec = build_oci_spec(
            self.runtime["rootfs"],
            registration_dir,
            role_name,
            role.uid,
            role.gid,
            self.config["image"]["entrypoint"],
            self._environment,
            container_id,
            handoff_id,
            cgroup_path,
        )
        run.bundle_path = self._create_bundle(container_id, spec)
        pid_file = run.bundle_path + "/init.pid"
        log_file = run.bundle_path + "/runc.log"
        self._run_runc(
            "--log", log_file, "--log-format", "json", "create", "--bundle", run.bundle_path,
            "--pid-file", pid_file, container_id,
            timeout=60,
        )
        self._verify_runc_state(run, pid_file)
        metadata = self._build_handoff(run, role)
        baseline_sequence = baseline["sequence"]

        def send_and_ack() -> None:
            send_handoff_and_wait_ack(
                self.dispatcher["handoff_socket"], metadata, run.pidfd,
                self.runtime["handoff_timeout_seconds"],
            )

        def require_handed_off() -> None:
            snapshot = self._wait_status_role(
                role_name,
                handoff_id,
                "handed_off",
                run.epoch,
                self.runtime["handoff_timeout_seconds"],
                baseline_sequence,
            )
            require(snapshot["dispatcher_state"] == "running", "DISPATCHER_NOT_RUNNING")

        def start() -> None:
            self._run_runc("start", container_id, timeout=15)
            run.started = True

        release_exec_after_handoff(send_and_ack, require_handed_off, start)
        ready_snapshot = self._wait_status_role(
            role_name,
            handoff_id,
            "ready",
            run.epoch,
            self.runtime["ready_timeout_seconds"],
            baseline_sequence,
        )
        require(ready_snapshot["dispatcher_state"] == "running", "DISPATCHER_NOT_RUNNING")
        return run

    def _current_role_status(self, run: OwnedRun, snapshot: dict[str, Any]) -> dict[str, Any]:
        require(snapshot["dispatcher_epoch"] == run.epoch, "STATUS_EPOCH_CHANGED")
        role_status = snapshot["roles"][run.role]
        require(role_status["state"] != "red", "DISPATCHER_RED")
        require(role_status["handoff_id"] == run.handoff_id, "STATUS_HANDOFF_MISMATCH")
        return role_status

    def _cgroup_empty(self, run: OwnedRun) -> bool:
        current = os.fstat(run.cgroup_fd)
        require(_file_identity(current) == run.cgroup_identity, "CGROUP_IDENTITY_CHANGED")
        procs = _read_at(run.cgroup_fd, "cgroup.procs")
        events = dict(
            item.split()
            for item in _read_at(run.cgroup_fd, "cgroup.events").splitlines()
            if len(item.split()) == 2
        )
        return procs == "" and events.get("populated") == "0"

    def _remove_bundle(self, run: OwnedRun) -> None:
        fd = _open_dir_component(self._bundle_root_fd, run.container_id)
        try:
            info = os.fstat(fd)
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "BUNDLE_UNSAFE")
            for name in os.listdir(fd):
                child = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISREG(child.st_mode) and child.st_uid == 0, "BUNDLE_CONTENT_UNSAFE")
                os.unlink(name, dir_fd=fd)
        finally:
            os.close(fd)
        os.rmdir(run.container_id, dir_fd=self._bundle_root_fd)

    def _remove_cgroup(self, run: OwnedRun) -> None:
        parent_info = os.fstat(run.parent_cgroup_fd)
        require(_file_identity(parent_info) == run.parent_identity, "CGROUP_PARENT_CHANGED")
        try:
            info = os.stat(run.cgroup_name, dir_fd=run.parent_cgroup_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        require(stat.S_ISDIR(info.st_mode) and _file_identity(info) == run.cgroup_identity, "CGROUP_IDENTITY_CHANGED")
        try:
            os.rmdir(run.cgroup_name, dir_fd=run.parent_cgroup_fd)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise SupervisorFailure("CGROUP_REMOVE_FAILED") from exc

    def _cleanup_reaped_run(self, run: OwnedRun, snapshot: dict[str, Any]) -> bool:
        pidfd_exited = _pidfd_exited(run.pidfd)
        cgroup_empty = self._cgroup_empty(run)
        if not cleanup_authorized(snapshot, run.role, run.epoch, run.handoff_id, pidfd_exited, cgroup_empty):
            return False
        # Re-read the root-owned status immediately before destructive cleanup.
        fresh = self._read_current_status()
        self._current_role_status(run, fresh)
        require(cleanup_authorized(fresh, run.role, run.epoch, run.handoff_id, _pidfd_exited(run.pidfd), self._cgroup_empty(run)), "REAP_PROOF_MISSING")
        self._run_runc("delete", run.container_id, timeout=15)
        self._remove_cgroup(run)
        self._remove_bundle(run)
        os.close(run.pidfd)
        run.pidfd = -1
        os.close(run.cgroup_fd)
        run.cgroup_fd = -1
        os.close(run.parent_cgroup_fd)
        run.parent_cgroup_fd = -1
        del self.active[run.role]
        return True

    def _advance_run(self, run: OwnedRun, snapshot: dict[str, Any]) -> bool:
        role_status = self._current_role_status(run, snapshot)
        if role_status["state"] in {"ready", "busy"}:
            overdue = False
            if role_status["state"] == "busy":
                deadline = parse_utc_timestamp(role_status["lease_deadline"])
                overdue = dt.datetime.now(dt.timezone.utc) >= deadline
            if run.reap_status_deadline is not None or overdue or _pidfd_exited(run.pidfd):
                # The dispatcher owns termination and publishes REAPED only
                # after collecting its proof. A still-fresh READY/BUSY snapshot
                # can lag that exit. Keep the same owned run until the exact
                # epoch/handoff reaches REAPED; never extend this deadline on
                # repeated polls or use a dead pidfd as cleanup authorization.
                now = time.monotonic()
                if run.reap_status_deadline is None:
                    run.reap_status_deadline = now + REAP_STATUS_GRACE_SECONDS
                require(now < run.reap_status_deadline, "REAP_STATUS_TIMEOUT")
            return False
        require(role_status["state"] == "reaped", "STATUS_ROLE_TRANSITION_INVALID")
        return self._cleanup_reaped_run(run, snapshot)

    def _close_local_descriptors(self) -> None:
        for run in list(self.active.values()):
            for attribute in ("pidfd", "cgroup_fd", "parent_cgroup_fd"):
                fd = getattr(run, attribute)
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    setattr(run, attribute, -1)
        if self.status is not None:
            self.status.close()
            self.status = None
        for attribute in ("_cgroup_root_fd", "_runc_state_fd", "_bundle_root_fd", "_runtime_dir_fd", "_lock_fd"):
            fd = getattr(self, attribute)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, attribute, -1)

    def request_stop(self, _signum: int | None = None, _frame: Any | None = None) -> None:
        self.stop_requested = True
        if self._shutdown_deadline is None:
            self._shutdown_deadline = time.monotonic() + self.runtime["shutdown_grace_seconds"]

    def _drain_after_stop(self) -> None:
        """Wait for dispatcher teardown even if SIGTERM interrupted registration."""
        self.request_stop()
        while self.active:
            require(time.monotonic() < self._shutdown_deadline, "SHUTDOWN_UNREAPED")
            snapshot = self._read_current_status()
            for run in tuple(self.active.values()):
                role_status = snapshot["roles"][run.role]
                # An unaccepted handoff cannot authorize cleanup. In that case
                # the bounded stop fails and preserves the incident state.
                if role_status["state"] == "reaped" and role_status["handoff_id"] == run.handoff_id:
                    if self._cleanup_reaped_run(run, snapshot):
                        self._log("PARSER_REAPED", run.role)
            if self.active:
                time.sleep(self.runtime["status_poll_seconds"])

    def run(self) -> None:
        require(sys.platform == "linux", "LINUX_REQUIRED")
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        try:
            self._prepare_runtime_directories()
            self.directory_identities = verify_prepared_host_directories(self.config)
            self._verify_runtime_binary()
            self._verify_offline_image()
            self._prepare_cgroup_parent()
            initial = self._wait_for_dispatcher()
            for role_name in ("OFFICE", "PDF"):
                initial = self._read_current_status()
                self._launch_role(role_name, initial)
            while True:
                if self.stop_event is not None and self.stop_event.is_set():
                    self.request_stop()
                snapshot = self._read_current_status()
                if snapshot["dispatcher_state"] == "stopping":
                    self.request_stop()
                if self.stop_requested:
                    self._drain_after_stop()
                    return
                for role_name in tuple(self.active):
                    run = self.active[role_name]
                    if self._advance_run(run, snapshot):
                        self._log("PARSER_REAPED", role_name)
                if self.stop_requested:
                    if not self.active:
                        return
                    if self._shutdown_deadline is None:
                        self._shutdown_deadline = time.monotonic() + self.runtime["shutdown_grace_seconds"]
                    if time.monotonic() >= self._shutdown_deadline:
                        raise SupervisorFailure("SHUTDOWN_UNREAPED")
                elif snapshot["dispatcher_state"] == "running":
                    for role_name in ("OFFICE", "PDF"):
                        if role_name not in self.active:
                            current = self._read_current_status()
                            if current["roles"][role_name]["state"] in {"empty", "reaped"}:
                                self._launch_role(role_name, current)
                time.sleep(self.runtime["status_poll_seconds"])
        except SupervisorFailure as exc:
            if exc.code != "STOP_REQUESTED" or not self.stop_requested:
                raise
            self._drain_after_stop()
        finally:
            self._close_local_descriptors()


def main() -> int:
    if sys.platform != "linux":
        print('{"component":"native-ingest-supervisor","code":"LINUX_REQUIRED"}', file=sys.stderr)
        return 1
    try:
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        config = load_config()
        if sys.argv[1:] == ["--prepare-only"]:
            prepare_host_directories(config)
            print('{"component":"native-ingest-supervisor","code":"HOST_DIRS_PREPARED"}', file=sys.stderr, flush=True)
            return 0
        require(not sys.argv[1:], "ARGUMENTS_INVALID")
        supervisor = NativeSupervisor(config)
        signal.signal(signal.SIGTERM, supervisor.request_stop)
        signal.signal(signal.SIGINT, supervisor.request_stop)
        supervisor.run()
        return 0
    except SupervisorFailure as exc:
        print(json.dumps({"component": "native-ingest-supervisor", "code": exc.code}, separators=(",", ":")), file=sys.stderr)
        return 1
    except Exception:
        print('{"component":"native-ingest-supervisor","code":"INTERNAL_FAILURE"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
