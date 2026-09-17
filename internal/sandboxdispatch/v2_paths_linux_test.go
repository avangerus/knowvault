//go:build linux

package sandboxdispatch

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareV2SocketPathRejectsUnsafeFilesystemAuthority(t *testing.T) {
	t.Run("world-writable parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "unsafe")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := prepareV2SocketPath(filepath.Join(parent, "submit.sock")); err == nil {
			t.Fatal("world-writable socket parent accepted")
		}
	})

	t.Run("symlink path", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.WriteFile(target, []byte("not-a-socket"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "submit.sock")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := prepareV2SocketPath(path); err == nil {
			t.Fatal("symlink socket path accepted")
		}
	})

	t.Run("regular file path", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "submit.sock")
		if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := prepareV2SocketPath(path); err == nil {
			t.Fatal("regular file socket path accepted")
		}
	})

	t.Run("owned stale socket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "submit.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		if err := prepareV2SocketPath(path); err != nil {
			t.Fatalf("owned stale socket rejected: %v", err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("stale socket was not removed: %v", err)
		}
	})
}
