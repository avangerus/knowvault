import copy
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import native_ingest_supervisor as supervisor


UTC = dt.timezone.utc


def status_document(now: dt.datetime | None = None) -> dict:
    written = now or dt.datetime(2026, 9, 15, 10, 0, 0, 123456, tzinfo=UTC)
    return {
        "schema_version": supervisor.STATUS_SCHEMA,
        "dispatcher_epoch": "a" * 32,
        "sequence": 1,
        "written_at": written.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "valid_until": (written + dt.timedelta(seconds=5)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "dispatcher_state": "running",
        "roles": {
            "OFFICE": {"state": "empty", "handoff_id": None},
            "PDF": {"state": "empty", "handoff_id": None},
        },
    }


class StatusContractTests(unittest.TestCase):
    def owned_run(self) -> supervisor.OwnedRun:
        return supervisor.OwnedRun(
            role="OFFICE", container_id="kvp-office-" + "1" * 32,
            handoff_id="b" * 64, cgroup_name="unused", cgroup_path="unused",
            epoch="a" * 32, pid=1, pidfd=99, parent_cgroup_fd=98, cgroup_fd=97,
            parent_identity=(1, 1), cgroup_identity=(1, 2), bundle_path="unused",
        )

    def test_process_exit_waits_for_exact_reap_publication(self) -> None:
        for state in ("ready", "busy"):
            with self.subTest(state=state):
                runner = supervisor.NativeSupervisor(copy.deepcopy(supervisor.DEFAULT_CONFIG))
                run = self.owned_run()
                document = status_document(dt.datetime.now(UTC))
                document["roles"]["OFFICE"] = {"state": state, "handoff_id": run.handoff_id}
                if state == "busy":
                    document["roles"]["OFFICE"]["lease_deadline"] = (dt.datetime.now(UTC)+dt.timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
                with patch.object(supervisor, "_pidfd_exited", return_value=True), patch.object(runner, "_cleanup_reaped_run", return_value=True) as cleanup:
                    with patch.object(supervisor.time, "monotonic", return_value=100):
                        self.assertFalse(runner._advance_run(run, document))
                    with patch.object(supervisor.time, "monotonic", return_value=101):
                        self.assertFalse(runner._advance_run(run, document))
                    self.assertEqual(run.reap_status_deadline, 105)
                    cleanup.assert_not_called()
                    reaped = copy.deepcopy(document)
                    reaped["sequence"] += 1
                    reaped["roles"]["OFFICE"] = {"state":"reaped", "handoff_id":run.handoff_id}
                    self.assertTrue(runner._advance_run(run, reaped))
                    cleanup.assert_called_once_with(run, reaped)

    def test_reap_wait_is_bounded_for_exit_and_overdue_lease(self) -> None:
        for exited in (True, False):
            with self.subTest(exited=exited):
                runner = supervisor.NativeSupervisor(copy.deepcopy(supervisor.DEFAULT_CONFIG))
                run = self.owned_run()
                document = status_document(dt.datetime.now(UTC))
                document["roles"]["OFFICE"] = {"state":"busy", "handoff_id":run.handoff_id, "lease_deadline":"2026-01-01T00:00:00Z"}
                with patch.object(supervisor, "_pidfd_exited", return_value=exited), patch.object(runner, "_cleanup_reaped_run") as cleanup:
                    with patch.object(supervisor.time, "monotonic", return_value=100):
                        self.assertFalse(runner._advance_run(run, document))
                    with patch.object(supervisor.time, "monotonic", return_value=104.99):
                        self.assertFalse(runner._advance_run(run, document))
                    with patch.object(supervisor.time, "monotonic", return_value=105):
                        with self.assertRaisesRegex(supervisor.SupervisorFailure, "REAP_STATUS_TIMEOUT"):
                            runner._advance_run(run, document)
                    cleanup.assert_not_called()

    def test_reap_wait_never_accepts_wrong_authority_or_red(self) -> None:
        for mutation, code in (("epoch", "STATUS_EPOCH_CHANGED"), ("handoff", "STATUS_HANDOFF_MISMATCH"), ("red", "DISPATCHER_RED")):
            with self.subTest(mutation=mutation):
                runner = supervisor.NativeSupervisor(copy.deepcopy(supervisor.DEFAULT_CONFIG))
                run = self.owned_run()
                run.reap_status_deadline = 105
                document = status_document()
                document["roles"]["OFFICE"] = {"state":"reaped", "handoff_id":run.handoff_id}
                if mutation == "epoch": document["dispatcher_epoch"] = "c" * 32
                elif mutation == "handoff": document["roles"]["OFFICE"]["handoff_id"] = "d" * 64
                else: document["roles"]["OFFICE"]["state"] = "red"
                with patch.object(runner, "_cleanup_reaped_run") as cleanup:
                    with self.assertRaisesRegex(supervisor.SupervisorFailure, code):
                        runner._advance_run(run, document)
                    cleanup.assert_not_called()

    def test_registration_can_be_consumed_before_supervisor_poll(self) -> None:
        for state in ("ready", "busy", "reaped"):
            with self.subTest(state=state):
                runner = supervisor.NativeSupervisor(copy.deepcopy(supervisor.DEFAULT_CONFIG))
                document = status_document()
                document["sequence"] = 2
                document["roles"]["OFFICE"] = {"state": state, "handoff_id": "b" * 64}
                with patch.object(runner, "_read_current_status", return_value=document):
                    observed = runner._wait_status_role("OFFICE", "b" * 64, "ready", "a" * 32, .01, 1)
                self.assertEqual(observed["roles"]["OFFICE"]["state"], state)

    def test_later_role_state_cannot_release_pre_exec_barrier(self) -> None:
        runner = supervisor.NativeSupervisor(copy.deepcopy(supervisor.DEFAULT_CONFIG))
        document = status_document()
        document["sequence"] = 2
        document["roles"]["OFFICE"] = {"state": "busy", "handoff_id": "b" * 64}
        with patch.object(runner, "_read_current_status", return_value=document):
            with self.assertRaisesRegex(supervisor.SupervisorFailure, "STATUS_TRANSITION_TIMEOUT"):
                runner._wait_status_role("OFFICE", "b" * 64, "handed_off", "a" * 32, .01, 1)

    def test_repeated_stop_does_not_extend_shutdown_deadline(self) -> None:
        runner = supervisor.NativeSupervisor(copy.deepcopy(supervisor.DEFAULT_CONFIG))
        with patch.object(supervisor.time, "monotonic", return_value=100):
            runner.request_stop()
        deadline = runner._shutdown_deadline
        with patch.object(supervisor.time, "monotonic", return_value=200):
            runner.request_stop()
        self.assertEqual(runner._shutdown_deadline, deadline)

    def test_dispatcher_stop_interrupts_registration_into_drain(self) -> None:
        runner = supervisor.NativeSupervisor(copy.deepcopy(supervisor.DEFAULT_CONFIG))
        document = status_document()
        document["sequence"] = 2
        document["dispatcher_state"] = "stopping"
        document["roles"]["OFFICE"] = {"state": "reaped", "handoff_id": "b" * 64}
        with patch.object(runner, "_read_current_status", return_value=document):
            with self.assertRaisesRegex(supervisor.SupervisorFailure, "STOP_REQUESTED"):
                runner._wait_status_role("OFFICE", "b" * 64, "ready", "a" * 32, .01, 1)
        self.assertTrue(runner.stop_requested)
        self.assertIsNotNone(runner._shutdown_deadline)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0, "root-owned status contract")
    def test_fresh_stopping_status_does_not_pin_old_epoch_on_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = status_document(dt.datetime.now(UTC))
            document["dispatcher_state"] = "stopping"
            path = pathlib.Path(temporary)/"status.json"
            path.write_text(json.dumps(document))
            path.chmod(0o600)
            fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            with patch.object(supervisor, "_secure_status_parent", return_value=fd):
                reader = supervisor.StatusReader("/run/knowvault/sandbox/supervisor/status.json")
            try:
                with self.assertRaisesRegex(supervisor.SupervisorFailure, "DISPATCHER_NOT_RUNNING"):
                    reader.read(initial_running=True)
                self.assertIsNone(reader.sequence.epoch)
                document["dispatcher_state"] = "running"
                document["dispatcher_epoch"] = "c" * 32
                path.write_text(json.dumps(document))
                self.assertEqual(reader.read(initial_running=True)["dispatcher_epoch"], "c" * 32)
            finally:
                reader.close()

    def test_valid_status_and_role_lease(self) -> None:
        now = dt.datetime(2026, 9, 15, 10, 0, 1, tzinfo=UTC)
        document = status_document(dt.datetime(2026, 9, 15, 10, 0, 0, tzinfo=UTC))
        document["sequence"] = 2
        document["roles"]["OFFICE"] = {
            "state": "busy",
            "handoff_id": "b" * 64,
            "lease_deadline": "2026-09-15T10:00:02Z",
        }
        validated = supervisor.validate_status_document(document, now)
        self.assertEqual(validated["roles"]["OFFICE"]["state"], "busy")

    def test_expiry_epoch_and_unknown_fields_fail_closed(self) -> None:
        now = dt.datetime(2026, 9, 15, 10, 0, 6, tzinfo=UTC)
        with self.assertRaises(supervisor.SupervisorFailure) as stale:
            supervisor.validate_status_document(status_document(), now)
        self.assertEqual(stale.exception.code, "STATUS_STALE")

        good = status_document(now - dt.timedelta(seconds=1))
        sequence = supervisor.StatusSequence()
        sequence.accept(good)
        changed_epoch = copy.deepcopy(good)
        changed_epoch["dispatcher_epoch"] = "c" * 32
        with self.assertRaises(supervisor.SupervisorFailure) as epoch:
            sequence.accept(changed_epoch)
        self.assertEqual(epoch.exception.code, "STATUS_EPOCH_CHANGED")

        unknown = copy.deepcopy(good)
        unknown["worker_id"] = "must-not-be-present"
        with self.assertRaises(supervisor.SupervisorFailure) as fields:
            supervisor.validate_status_document(unknown, now)
        self.assertEqual(fields.exception.code, "STATUS_FIELDS_INVALID")

    def test_sequence_rewrite_and_rollback_rejected(self) -> None:
        first = status_document()
        sequence = supervisor.StatusSequence()
        sequence.accept(first)
        rewritten = copy.deepcopy(first)
        rewritten["roles"]["OFFICE"] = {"state": "ready", "handoff_id": "d" * 64}
        with self.assertRaises(supervisor.SupervisorFailure) as rewrite:
            sequence.accept(rewritten)
        self.assertEqual(rewrite.exception.code, "STATUS_SEQUENCE_REWRITTEN")

        later = copy.deepcopy(first)
        later["sequence"] = 2
        sequence.accept(later)
        with self.assertRaises(supervisor.SupervisorFailure) as rollback:
            sequence.accept(first)
        self.assertEqual(rollback.exception.code, "STATUS_SEQUENCE_ROLLBACK")

    def test_cleanup_requires_matching_reaped_and_both_local_proofs(self) -> None:
        document = status_document()
        document["roles"]["OFFICE"] = {"state": "reaped", "handoff_id": "e" * 64}
        allowed = supervisor.cleanup_authorized(document, "OFFICE", "a" * 32, "e" * 64, True, True)
        self.assertTrue(allowed)
        self.assertFalse(supervisor.cleanup_authorized(document, "OFFICE", "a" * 32, "e" * 64, False, True))
        self.assertFalse(supervisor.cleanup_authorized(document, "OFFICE", "a" * 32, "e" * 64, True, False))
        self.assertFalse(supervisor.cleanup_authorized(document, "OFFICE", "f" * 32, "e" * 64, True, True))
        self.assertFalse(supervisor.cleanup_authorized(document, "OFFICE", "a" * 32, "g" * 64, True, True))
        document["dispatcher_state"] = "red"
        self.assertFalse(supervisor.cleanup_authorized(document, "OFFICE", "a" * 32, "e" * 64, True, True))


class HandoffAndBundleTests(unittest.TestCase):
    def test_start_requires_ack_then_status(self) -> None:
        events: list[str] = []
        supervisor.release_exec_after_handoff(
            lambda: events.append("ack"),
            lambda: events.append("status"),
            lambda: events.append("start"),
        )
        self.assertEqual(events, ["ack", "status", "start"])

        events.clear()
        with self.assertRaisesRegex(RuntimeError, "status"):
            supervisor.release_exec_after_handoff(
                lambda: events.append("ack"),
                lambda: (_ for _ in ()).throw(RuntimeError("status")),
                lambda: events.append("start"),
            )
        self.assertEqual(events, ["ack"])

        events.clear()
        with self.assertRaisesRegex(RuntimeError, "ack"):
            supervisor.release_exec_after_handoff(
                lambda: (_ for _ in ()).throw(RuntimeError("ack")),
                lambda: events.append("status"),
                lambda: events.append("start"),
            )
        self.assertEqual(events, [])

    def test_bundle_has_only_the_pinned_worker_boundary(self) -> None:
        office = supervisor.build_oci_spec(
            "/opt/knowvault/native-ingest-v3/rootfs",
            "/run/knowvault/sandbox/office",
            "OFFICE",
            65532,
            65532,
            supervisor.PINNED["entrypoint"],
            ["LANG=C"],
            "kvp-office-" + "1" * 32,
            "2" * 64,
            "/knowvault_native.slice/knowvault-native-supervisor.service/parsers/kvp-office-" + "1" * 32,
        )
        self.assertTrue(office["root"]["readonly"])
        self.assertTrue(office["process"]["noNewPrivileges"])
        self.assertEqual(office["process"]["cwd"], "/app")
        self.assertEqual(office["linux"]["resources"], {
            "memory": {"limit": 64 * 1024 * 1024},
            "cpu": {"quota": 10_000, "period": 100_000},
            "pids": {"limit": 16},
        })
        self.assertEqual(
            [mount["destination"] for mount in office["mounts"]],
            ["/proc", "/dev", "/tmp", "/run/knowvault"],
        )
        self.assertEqual(office["mounts"][-1]["source"], "/run/knowvault/sandbox/office")
        self.assertIn("--parser-type=OFFICE", office["process"]["args"])
        self.assertFalse(any("database" in item.lower() or "source" in item.lower() for item in office["process"]["env"]))

    def test_bundle_rejects_role_identity_or_socket_swap(self) -> None:
        args = (
            "/opt/knowvault/native-ingest-v3/rootfs",
            "/run/knowvault/sandbox/office",
            "OFFICE",
            65533,
            65533,
            supervisor.PINNED["entrypoint"],
            [],
            "kvp-office-" + "1" * 32,
            "2" * 64,
            "/knowvault_native.slice/knowvault-native-supervisor.service/parsers/kvp-office-" + "1" * 32,
        )
        with self.assertRaises(supervisor.SupervisorFailure):
            supervisor.build_oci_spec(*args)
        with self.assertRaises(supervisor.SupervisorFailure):
            supervisor.build_oci_spec(*args[:1], "/run/knowvault/sandbox/pdf", *args[2:])


class StrictInputTests(unittest.TestCase):
    def test_duplicate_json_keys_rejected(self) -> None:
        with self.assertRaises(supervisor.SupervisorFailure) as duplicate:
            supervisor.strict_json_loads(b'{"sequence":1,"sequence":2}')
        self.assertEqual(duplicate.exception.code, "JSON_DUPLICATE_KEY")

    def test_config_is_an_exact_pinned_candidate(self) -> None:
        config = copy.deepcopy(supervisor.DEFAULT_CONFIG)
        self.assertEqual(supervisor.validate_config(config), config)
        config_path = pathlib.Path(__file__).with_name("native-ingest-supervisor.json")
        config_bytes = config_path.read_bytes()
        self.assertEqual(supervisor.strict_json_loads(config_bytes), supervisor.DEFAULT_CONFIG)
        config["runtime"]["handoff_timeout_seconds"] = 600
        with self.assertRaises(supervisor.SupervisorFailure) as changed:
            supervisor.validate_config(config)
        self.assertEqual(changed.exception.code, "CONFIG_PIN_MISMATCH")

    def test_status_directory_is_a_single_canonical_path(self) -> None:
        with self.assertRaises(supervisor.SupervisorFailure) as bad_path:
            supervisor.prepare_status_directory("/tmp/other/status.json")
        self.assertEqual(bad_path.exception.code, "STATUS_PATH_INVALID")

    def test_prepared_directory_modes_are_exact(self) -> None:
        self.assertEqual(supervisor.PREPARED_DIRECTORY_MODES["/run/knowvault/sandbox/supervisor"], 0o700)
        self.assertEqual(supervisor.PREPARED_DIRECTORY_MODES["/run/knowvault/sandbox/office"], 0o711)
        self.assertEqual(supervisor.PREPARED_DIRECTORY_MODES["/run/knowvault/sandbox/pdf"], 0o711)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0, "directory ownership check needs root-owned POSIX files")
    def test_preparation_refuses_symlinks_and_wrong_modes_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent_fd = os.open(temporary, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                created_fd = supervisor._open_prepared_directory_child(parent_fd, "created", 0o700, create=True)
                os.close(created_fd)

                os.mkdir(os.path.join(temporary, "wrong-mode"), 0o755)
                with self.assertRaises(supervisor.SupervisorFailure):
                    supervisor._open_prepared_directory_child(parent_fd, "wrong-mode", 0o711, create=False)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(temporary, "wrong-mode")).st_mode), 0o755)

                os.mkdir(os.path.join(temporary, "target"), 0o711)
                os.symlink(os.path.join(temporary, "target"), os.path.join(temporary, "link"))
                with self.assertRaises(supervisor.SupervisorFailure):
                    supervisor._open_prepared_directory_child(parent_fd, "link", 0o711, create=False)

                os.mkdir(os.path.join(temporary, "wrong-owner"), 0o711)
                os.chown(os.path.join(temporary, "wrong-owner"), 65532, 65532)
                with self.assertRaises(supervisor.SupervisorFailure):
                    supervisor._open_prepared_directory_child(parent_fd, "wrong-owner", 0o711, create=False)
            finally:
                os.close(parent_fd)

    def test_cgroup_parent_rejects_every_child_directory(self) -> None:
        supervisor.validate_empty_cgroup_parent([
            ("cgroup.controllers", stat.S_IFREG),
            ("cgroup.procs", stat.S_IFREG),
        ])
        with self.assertRaises(supervisor.SupervisorFailure) as child:
            supervisor.validate_empty_cgroup_parent([("unexpected", stat.S_IFDIR)])
        self.assertEqual(child.exception.code, "CGROUP_PARENT_NOT_EMPTY")
        with self.assertRaises(supervisor.SupervisorFailure) as link:
            supervisor.validate_empty_cgroup_parent([("unexpected", stat.S_IFLNK)])
        self.assertEqual(link.exception.code, "CGROUP_PARENT_NOT_EMPTY")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0, "runc pin verifier needs root-owned POSIX files")
    def test_runc_is_rechecked_for_each_identity_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = os.path.join(temporary, "runc")
            with open(path, "wb") as output:
                output.write(b"pinned-runc")
            os.chmod(path, 0o755)
            digest = hashlib.sha256(b"pinned-runc").hexdigest()
            fd, identity = supervisor._open_verified_runc(path, digest)
            os.close(fd)

            same_content_replacement = os.path.join(temporary, "runc.same")
            with open(same_content_replacement, "wb") as output:
                output.write(b"pinned-runc")
            os.chmod(same_content_replacement, 0o755)
            os.replace(same_content_replacement, path)
            with self.assertRaises(supervisor.SupervisorFailure) as replaced:
                supervisor._open_verified_runc(path, digest, identity)
            self.assertEqual(replaced.exception.code, "RUNC_IDENTITY_CHANGED")

            replacement = os.path.join(temporary, "runc.new")
            with open(replacement, "wb") as output:
                output.write(b"changed-runc")
            os.chmod(replacement, 0o755)
            os.replace(replacement, path)
            with self.assertRaises(supervisor.SupervisorFailure) as changed:
                supervisor._open_verified_runc(path, digest, identity)
            self.assertEqual(changed.exception.code, "RUNC_DIGEST_MISMATCH")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0, "pinned archive verifier needs root-owned POSIX files")
    def test_oci_archive_is_rewound_and_working_directory_is_pinned(self) -> None:
        def make_archive(archive_path: str, working_dir: str) -> dict[str, object]:
            config = {
                "architecture": "amd64",
                "os": "linux",
                "config": {"Entrypoint": supervisor.PINNED["entrypoint"], "WorkingDir": working_dir, "Cmd": [], "Env": []},
                "rootfs": {"type": "layers", "diff_ids": []},
            }
            config_body = json.dumps(config, separators=(",", ":"), sort_keys=True).encode()
            config_digest = hashlib.sha256(config_body).hexdigest()
            manifest = {
                "schemaVersion": 2,
                "config": {"digest": "sha256:" + config_digest},
                "layers": [],
            }
            manifest_body = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
            manifest_digest = hashlib.sha256(manifest_body).hexdigest()
            index = {
                "schemaVersion": 2,
                "manifests": [{
                    "digest": "sha256:" + manifest_digest,
                    "platform": {"architecture": "amd64", "os": "linux"},
                }],
            }
            files = {
                "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
                "index.json": json.dumps(index, separators=(",", ":"), sort_keys=True).encode(),
                "blobs/sha256/" + manifest_digest: manifest_body,
                "blobs/sha256/" + config_digest: config_body,
            }
            with tarfile.open(archive_path, "w") as archive:
                for name in sorted(files):
                    info = tarfile.TarInfo(name)
                    info.size = len(files[name])
                    info.mode = 0o444
                    archive.addfile(info, io.BytesIO(files[name]))
            with open(archive_path, "rb") as source:
                archive_digest = hashlib.sha256(source.read()).hexdigest()
            return {
                "oci_archive_sha256": archive_digest,
                "oci_manifest_digest": "sha256:" + manifest_digest,
                "oci_config_digest": "sha256:" + config_digest,
                "entrypoint": supervisor.PINNED["entrypoint"],
                "working_dir": "/app",
                "layers": [],
            }

        with tempfile.TemporaryDirectory() as temporary:
            correct_path = os.path.join(temporary, "correct.oci.tar")
            correct_pins = make_archive(correct_path, "/app")
            self.assertEqual(supervisor.verify_oci_archive(correct_path, correct_pins), [])
            wrong_path = os.path.join(temporary, "wrong.oci.tar")
            wrong_pins = make_archive(wrong_path, "/")
            with self.assertRaises(supervisor.SupervisorFailure) as working_dir:
                supervisor.verify_oci_archive(wrong_path, wrong_pins)
            self.assertEqual(working_dir.exception.code, "OCI_PROCESS_CONFIG_MISMATCH")

    @unittest.skipUnless(os.name == "posix", "descriptor-relative rootfs walk requires POSIX openat")
    def test_rootfs_tree_hash_is_stable_and_detects_content_change(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app")
            os.mkdir(path)
            payload = os.path.join(path, "artifact.sha256")
            with open(payload, "wb") as output:
                output.write(b"sha256:fixture\n")
            first = supervisor.rootfs_tree_sha256(root)
            second = supervisor.rootfs_tree_sha256(root)
            self.assertEqual(first, second)
            with open(payload, "wb") as output:
                output.write(b"sha256:changed\n")
            self.assertNotEqual(first, supervisor.rootfs_tree_sha256(root))


if __name__ == "__main__":
    unittest.main()
