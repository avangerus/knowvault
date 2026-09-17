//go:build linux

package sandboxdispatch

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func prepareV2SocketPath(path string) error {
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		parentInfo, err = os.Lstat(parent)
		if err != nil {
			return err
		}
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe socket parent")
	}
	if stat, ok := parentInfo.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("socket parent owner")
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path is not a unix socket")
	}
	return os.Remove(path)
}

func validateV2DirectoryOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("unsafe socket directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("socket directory owner")
	}
	return nil
}

// chownV2ParserSocket applies the exact parser role identity after the
// listener is created. The mode intentionally stays owner-only: directory
// traversal is granted by the deployment-owned role mount, while no unrelated
// user or group can open a parser listener.
func chownV2ParserSocket(path string, uid, gid int) error {
	if uid < 1 || gid < 1 {
		return fmt.Errorf("invalid parser socket owner")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("unsafe parser socket")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("parser socket disappeared")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("parser socket owner drift")
	}
	return nil
}

func chownV2Socket(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return fmt.Errorf("invalid socket owner")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("unsafe socket")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket disappeared")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("socket owner drift")
	}
	return nil
}
