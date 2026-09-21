package analyticcatalog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadMountedClassifiesAbsentRootAndCatalog(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	assertMountError(t, loadMountedError(root), CodeMountUnavailable)

	root = t.TempDir()
	assertMountError(t, loadMountedError(root), CodeMountUnavailable)
}

func TestLoadMountedRejectsUnsafeRootAndCatalogObjects(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, datasetProfileCatalogFilename), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	assertMountError(t, loadMountedError(root), CodeMountInvalid)
	if err := os.WriteFile(filepath.Join(root, datasetProfileCatalogFilename), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	assertMountError(t, loadMountedError(root), CodeMountInvalid)

	fileRoot := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(fileRoot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	assertMountError(t, loadMountedError(fileRoot), CodeMountInvalid)

	root = t.TempDir()
	if err := os.Mkdir(filepath.Join(root, datasetProfileCatalogFilename), 0o700); err != nil {
		t.Fatal(err)
	}
	assertMountError(t, loadMountedError(root), CodeMountInvalid)
}

func TestLoadMountedRejectsCatalogOverReadCap(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, datasetProfileCatalogFilename)
	if err := os.WriteFile(filename, bytes.Repeat([]byte{' '}, maximumCatalogBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	assertMountError(t, loadMountedError(root), CodeMountInvalid)
	if err := os.WriteFile(filename, bytes.Repeat([]byte{' '}, maximumCatalogBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	assertMountError(t, loadMountedError(root), CodeMountInvalid)
}

func TestLoadMountedRejectsRootSymlinks(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "root-link")
	makeSymlink(t, target, link, false)
	assertMountError(t, loadMountedError(link), CodeMountInvalid)

	dangling := filepath.Join(t.TempDir(), "dangling-root-link")
	makeSymlink(t, filepath.Join(t.TempDir(), "absent"), dangling, true)
	assertMountError(t, loadMountedError(dangling), CodeMountInvalid)
}

func TestLoadMountedRejectsCatalogSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "catalog")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, datasetProfileCatalogFilename)
	makeSymlink(t, target, link, false)
	assertMountError(t, loadMountedError(root), CodeMountInvalid)

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	makeSymlink(t, filepath.Join(t.TempDir(), "absent-catalog"), link, true)
	assertMountError(t, loadMountedError(root), CodeMountInvalid)
}

func TestCodeOfKeepsUnknownErrorsClosed(t *testing.T) {
	if got := CodeOf(nil); got != "" {
		t.Fatalf("CodeOf(nil)=%q, want empty", got)
	}
	if got := CodeOf(errors.New("filesystem detail")); got != CodeMountInvalid {
		t.Fatalf("CodeOf(unknown)=%q, want %q", got, CodeMountInvalid)
	}
}

func loadMountedError(root string) error {
	_, err := LoadMountedAt(root)
	return err
}

func assertMountError(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected mount error %q, got nil", want)
	}
	if got := CodeOf(err); got != want {
		t.Fatalf("mount error code=%q, want %q", got, want)
	}
	if err.Error() != string(want) {
		t.Fatalf("mount error text=%q, want %q", err.Error(), want)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("mount error unexpectedly unwraps: %v", errors.Unwrap(err))
	}
}

func makeSymlink(t *testing.T, oldname, newname string, dangling bool) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		if os.IsPermission(err) || errors.Is(err, syscall.ENOSYS) ||
			errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP) ||
			errors.Is(err, syscall.EINVAL) {
			t.Skipf("os.Symlink unsupported: %v", err)
		}
		t.Fatalf("create symlink (dangling=%v): %v", dangling, err)
	}
}
