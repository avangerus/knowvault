import io
import os
import pathlib
import tarfile
import tempfile
import unittest

from native_ingest_supervisor import SupervisorFailure
from prepare_native_rootfs import apply_layer, prepare_mountpoints


def layer_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, kind, body in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.uid = os.getuid()
            info.gid = os.getgid()
            info.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            if kind == tarfile.REGTYPE:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            else:
                info.linkname = body
                archive.addfile(info)
    output.seek(0)
    return output


@unittest.skipUnless(os.name == "posix", "POSIX offline packaging")
class OfflineLayerTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "root-owned mountpoint contract")
    def test_mountpoints_exist_before_runtime_and_reject_hidden_contents(self):
        with tempfile.TemporaryDirectory() as root:
            prepare_mountpoints(pathlib.Path(root))
            for name in ("proc", "dev", "tmp", "run/knowvault"):
                self.assertTrue((pathlib.Path(root)/name).is_dir())
                self.assertEqual(list((pathlib.Path(root)/name).iterdir()), [])
        with tempfile.TemporaryDirectory() as root:
            (pathlib.Path(root)/"proc").mkdir()
            (pathlib.Path(root)/"proc/payload").write_text("must not be hidden by mount")
            with self.assertRaisesRegex(SupervisorFailure, "ROOTFS_MOUNTPOINT_NOT_EMPTY"):
                prepare_mountpoints(pathlib.Path(root))
            self.assertEqual((pathlib.Path(root)/"proc/payload").read_text(), "must not be hidden by mount")

    def apply(self, root, entries):
        apply_layer(layer_bytes(entries), pathlib.Path(root), [0, 0])

    def test_ordered_layers_replace_file_bytes_and_keep_relative_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            self.apply(root, [("app", tarfile.DIRTYPE, ""), ("app/worker", tarfile.REGTYPE, b"first"),
                              ("app/current", tarfile.SYMTYPE, "worker")])
            self.apply(root, [("app/worker", tarfile.REGTYPE, b"second")])
            self.assertEqual((pathlib.Path(root)/"app/current").read_bytes(), b"second")
            self.assertEqual(os.readlink(pathlib.Path(root)/"app/current"), "worker")

    def test_path_traversal_and_absolute_path_are_rejected(self):
        for name in ("../escape", "/absolute", "a/../../escape"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                with self.assertRaisesRegex(SupervisorFailure, "LAYER_PATH_INVALID"):
                    self.apply(root, [(name, tarfile.REGTYPE, b"bad")])
                self.assertEqual(list(pathlib.Path(root).iterdir()), [])

    def test_parent_symlink_is_never_followed(self):
        with tempfile.TemporaryDirectory() as root:
            self.apply(root, [("real", tarfile.DIRTYPE, ""), ("alias", tarfile.SYMTYPE, "real")])
            with self.assertRaisesRegex(SupervisorFailure, "LAYER_PARENT_UNSAFE"):
                self.apply(root, [("alias/payload", tarfile.REGTYPE, b"bad")])
            self.assertFalse((pathlib.Path(root)/"real/payload").exists())

    def test_whiteouts_and_hardlinks_require_explicit_packager_support(self):
        for entry, code in [((".wh.old", tarfile.REGTYPE, b""), "LAYER_WHITEOUT_UNSUPPORTED"),
                            (("hard", tarfile.LNKTYPE, "target"), "LAYER_TYPE_UNSUPPORTED")]:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as root:
                with self.assertRaisesRegex(SupervisorFailure, code):
                    self.apply(root, [entry])

    def test_symlink_escape_and_absolute_link_are_rejected(self):
        for link, code in [("../../escape", "LAYER_LINK_ESCAPE"), ("/etc/passwd", "LAYER_LINK_INVALID")]:
            with self.subTest(link=link), tempfile.TemporaryDirectory() as root:
                with self.assertRaisesRegex(SupervisorFailure, code):
                    self.apply(root, [("app/link", tarfile.SYMTYPE, link)])

    def test_duplicate_entry_is_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(SupervisorFailure, "LAYER_DUPLICATE_PATH"):
                self.apply(root, [("one", tarfile.REGTYPE, b"first"), ("one", tarfile.REGTYPE, b"second")])
            self.assertEqual((pathlib.Path(root)/"one").read_bytes(), b"first")


if __name__ == "__main__":
    unittest.main()
