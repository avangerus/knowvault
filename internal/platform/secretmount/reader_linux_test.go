//go:build linux

package secretmount

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMountedRootReadsOnlyPinnedRegularSecretFiles(t *testing.T) {
	rootPath := newMountedRootFixture(t)
	writeMountedFile(t, rootPath, "value", []byte("preloaded-secret"), 0o400)
	root, err := openMountedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	contents, err := root.read("value", 128)
	if err != nil || string(contents) != "preloaded-secret" {
		t.Fatalf("contents=%q err=%v", contents, err)
	}
	if _, err := root.read("../outside", 128); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("traversal error=%v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := root.read("value", 128); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("closed root read error=%v", err)
	}
}

func TestZeroMountedRootCannotReadOrCloseAProcessDescriptor(t *testing.T) {
	root := &mountedRoot{}
	if _, err := root.read("value", 128); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("zero root read error=%v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("zero root close error=%v", err)
	}
}

func TestMountedRootRejectsSymlinkFIFOAndDirectory(t *testing.T) {
	rootPath := newMountedRootFixture(t)
	writeMountedFile(t, rootPath, "target", []byte("secret"), 0o400)
	if err := os.Symlink(filepath.Join(rootPath, "target"), filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(rootPath, "pipe"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rootPath, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := openMountedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, filename := range []string{"link", "pipe", "directory"} {
		if _, err := root.read(filename, 128); CodeOf(err) != CodeMaterialInvalid {
			t.Fatalf("%s error=%v", filename, err)
		}
	}
}

func TestMountedRootRejectsUnsafePermissionsAndOversizeFiles(t *testing.T) {
	rootPath := newMountedRootFixture(t)
	writeMountedFile(t, rootPath, "permissive", []byte("secret"), 0o640)
	writeMountedFile(t, rootPath, "large", bytes.Repeat([]byte{'x'}, 129), 0o400)
	root, err := openMountedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.read("permissive", 128); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("permissive file error=%v", err)
	}
	if _, err := root.read("large", 128); CodeOf(err) != CodeMaterialInvalid {
		t.Fatalf("oversize file error=%v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootPath, 0o770); err != nil {
		t.Fatal(err)
	}
	if reopened, err := openMountedRoot(rootPath); CodeOf(err) != CodeUnavailable || reopened != nil {
		t.Fatalf("unsafe root=%#v err=%v", reopened, err)
	}
}

func TestMountedRootAcceptsRootOwnedGroupReadableFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership boundary requires root test container")
	}
	rootPath := newMountedRootFixture(t)
	writeMountedFile(t, rootPath, "group-readable", []byte("secret"), 0o440)
	root, err := openMountedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	contents, err := root.read("group-readable", 128)
	if err != nil || string(contents) != "secret" {
		t.Fatalf("contents=%q err=%v", contents, err)
	}
}

func TestMountedRootRejectsHardLinkedSecretFile(t *testing.T) {
	rootPath := newMountedRootFixture(t)
	writeMountedFile(t, rootPath, "value", []byte("secret"), 0o400)
	if err := os.Link(filepath.Join(rootPath, "value"), filepath.Join(rootPath, "alias")); err != nil {
		t.Fatal(err)
	}
	root, err := openMountedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, filename := range []string{"value", "alias"} {
		if _, err := root.read(filename, 128); CodeOf(err) != CodeMaterialInvalid {
			t.Fatalf("hard-linked %s error=%v", filename, err)
		}
	}
}

// F9-sec: the reader refuses a root or file owned by any group other than the
// pinned runtime group, even when the mode bits look exactly right. A mount
// hardened with the wrong group must never verify green.
func TestMountedRootRejectsForeignGroupOnRootAndFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership boundary requires root test container")
	}
	t.Run("root", func(t *testing.T) {
		rootPath := newMountedRootFixture(t)
		if err := os.Chown(rootPath, 0, 1000); err != nil {
			t.Fatal(err)
		}
		if root, err := openMountedRoot(rootPath); root != nil || CodeOf(err) != CodeUnavailable {
			t.Fatalf("foreign-group root=%#v err=%v", root, err)
		}
	})
	t.Run("file", func(t *testing.T) {
		rootPath := newMountedRootFixture(t)
		writeMountedFile(t, rootPath, "value", []byte("secret"), 0o440)
		if err := os.Chown(filepath.Join(rootPath, "value"), 0, 1000); err != nil {
			t.Fatal(err)
		}
		root, err := openMountedRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if _, err := root.read("value", 128); CodeOf(err) != CodeMaterialInvalid {
			t.Fatalf("foreign-group file error=%v", err)
		}
	})
}

// N1: a world-traversable mount root (0755) is refused even though it is not
// writable by the world: key file metadata must not be visible to the world.
func TestMountedRootRejectsWorldTraversableRoot(t *testing.T) {
	rootPath := newMountedRootFixture(t)
	if err := os.Chmod(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if root, err := openMountedRoot(rootPath); root != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("world-traversable root=%#v err=%v", root, err)
	}
}

func TestMountedRootRejectsSymlinkedRootAndRedactsErrors(t *testing.T) {
	rootPath := newMountedRootFixture(t)
	parent := t.TempDir()
	link := filepath.Join(parent, "mounted-link")
	if err := os.Symlink(rootPath, link); err != nil {
		t.Fatal(err)
	}
	if root, err := openMountedRoot(link); CodeOf(err) != CodeUnavailable || root != nil {
		t.Fatalf("symlink root=%#v err=%v", root, err)
	}
}

func TestMountedRootRejectsNonRootOwnedRootAndFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership boundary requires root test container")
	}
	t.Run("root", func(t *testing.T) {
		rootPath := newMountedRootFixture(t)
		if err := os.Chown(rootPath, 1, 1); err != nil {
			t.Fatal(err)
		}
		if root, err := openMountedRoot(rootPath); root != nil || CodeOf(err) != CodeUnavailable {
			t.Fatalf("non-root-owned root=%#v err=%v", root, err)
		}
	})
	t.Run("file", func(t *testing.T) {
		rootPath := newMountedRootFixture(t)
		writeMountedFile(t, rootPath, "value", []byte("secret"), 0o400)
		if err := os.Chown(filepath.Join(rootPath, "value"), 1, 1); err != nil {
			t.Fatal(err)
		}
		root, err := openMountedRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if _, err := root.read("value", 128); CodeOf(err) != CodeMaterialInvalid {
			t.Fatalf("non-root-owned file error=%v", err)
		}
	})
}

// newMountedRootFixture builds a root-owned mount directory owned by the
// pinned runtime group, matching the image contract the linux reader enforces
// (uid 0, gid RuntimeGID, mode 0700). Every fixture consumer relies on this
// boundary, so the whole suite requires a root test container.
func newMountedRootFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(rootPath, 0, RuntimeGID); err != nil {
		t.Fatal(err)
	}
	return rootPath
}

func writeMountedFile(t *testing.T, rootPath, filename string, contents []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(rootPath, filename)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, RuntimeGID); err != nil {
		t.Fatal(err)
	}
}
