//go:build linux

package operator

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// verifyMountBoundary proves, before any file is written, that the mount
// target cannot be redirected between validation and generation: the mount
// parent must be a real root-owned directory and the mount root, when
// present, must be a real root-owned directory too — never a symlink. The
// written mount is re-verified through the product loader afterwards; this
// check closes the fail-after-write window.
func verifyMountBoundary(mountRoot string) error {
	if err := verifyRootOwnedDirectory(filepath.Dir(mountRoot), "mount parent"); err != nil {
		return err
	}
	info, err := os.Lstat(mountRoot)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("mount root is a symlink")
		}
		if !info.IsDir() {
			return errors.New("mount root is not a directory")
		}
		if err := verifyRootOwnedDirectory(mountRoot, "mount root"); err != nil {
			return err
		}
	case os.IsNotExist(err):
		// The root is created by the operator inside the verified parent.
	default:
		return err
	}
	return nil
}

func verifyRootOwnedDirectory(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New(label + " does not exist: " + path)
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New(label + " is a symlink: " + path)
	}
	if !info.IsDir() {
		return errors.New(label + " is not a directory: " + path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New(label + " is not root-owned: " + path)
	}
	return nil
}
