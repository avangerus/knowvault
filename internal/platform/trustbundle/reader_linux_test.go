//go:build linux

package trustbundle

import (
	"bytes"
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestStableReadRequiresExactInitialSize(t *testing.T) {
	payload := bytes.Repeat([]byte("stable-trust-bundle\n"), 32)
	file, initial := newStableReadFixture(t, payload)
	initial.Size++
	if contents, err := stableRead(int(file.Fd()), maximumBundleBytes, initial, func(_ int, output *syscall.Stat_t) error {
		*output = initial
		return nil
	}); contents != nil || CodeOf(err) != CodeInvalid {
		t.Fatalf("size-mismatched stable read returned %d bytes err=%v", len(contents), err)
	}
}

func TestStableReadRequiresUnchangedSameFDMetadata(t *testing.T) {
	mutations := map[string]func(*syscall.Stat_t){
		"device":     func(value *syscall.Stat_t) { value.Dev++ },
		"inode":      func(value *syscall.Stat_t) { value.Ino++ },
		"type":       func(value *syscall.Stat_t) { value.Mode = value.Mode&^syscall.S_IFMT | syscall.S_IFDIR },
		"mode":       func(value *syscall.Stat_t) { value.Mode ^= 0o004 },
		"uid":        func(value *syscall.Stat_t) { value.Uid++ },
		"gid":        func(value *syscall.Stat_t) { value.Gid++ },
		"link count": func(value *syscall.Stat_t) { value.Nlink++ },
		"size":       func(value *syscall.Stat_t) { value.Size++ },
		"mtime":      func(value *syscall.Stat_t) { value.Mtim.Nsec++ },
		"ctime":      func(value *syscall.Stat_t) { value.Ctim.Nsec++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			payload := []byte("one stable trust bundle snapshot")
			file, initial := newStableReadFixture(t, payload)
			if contents, err := stableRead(int(file.Fd()), maximumBundleBytes, initial, func(_ int, output *syscall.Stat_t) error {
				*output = initial
				mutate(output)
				return nil
			}); contents != nil || CodeOf(err) != CodeInvalid {
				t.Fatalf("changed %s returned %d bytes err=%v", name, len(contents), err)
			}
		})
	}
}

func TestStableReadAcceptsExactSnapshotAndRejectsSecondFstatFailure(t *testing.T) {
	payload := []byte("exact stable trust bundle snapshot")
	file, initial := newStableReadFixture(t, payload)
	contents, err := stableRead(int(file.Fd()), maximumBundleBytes, initial, syscall.Fstat)
	if err != nil || !bytes.Equal(contents, payload) {
		t.Fatalf("exact snapshot contents=%q err=%v", contents, err)
	}

	file, initial = newStableReadFixture(t, payload)
	if contents, err := stableRead(int(file.Fd()), maximumBundleBytes, initial, func(int, *syscall.Stat_t) error {
		return errors.New("injected fstat failure")
	}); contents != nil || CodeOf(err) != CodeInvalid {
		t.Fatalf("failed second fstat returned %d bytes err=%v", len(contents), err)
	}
}

func newStableReadFixture(t *testing.T, payload []byte) (*os.File, syscall.Stat_t) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stable-read-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var info syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &info); err != nil {
		t.Fatal(err)
	}
	return file, info
}
