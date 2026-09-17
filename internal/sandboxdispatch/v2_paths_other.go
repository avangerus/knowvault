//go:build !linux

package sandboxdispatch

import (
	"fmt"
	"os"
	"path/filepath"
)

func prepareV2SocketPath(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(parent)
		if err != nil {
			return err
		}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe socket parent")
	}
	entry, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if entry.Mode()&os.ModeSymlink != 0 || entry.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path is not a unix socket")
	}
	return os.Remove(path)
}

func validateV2DirectoryOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("unsafe socket directory")
	}
	return nil
}

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
	return nil
}
