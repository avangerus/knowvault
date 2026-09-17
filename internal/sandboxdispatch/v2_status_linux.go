//go:build linux

package sandboxdispatch

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const canonicalV2SupervisorStatusPath = "/run/knowvault/sandbox/supervisor/status.json"

type linuxV2StatusWriter struct {
	mu     sync.Mutex
	path   string
	name   string
	dirFD  int
	device uint64
	inode  uint64
	uid    uint32
	closed bool
}

func newV2StatusWriter(statusPath string) (v2StatusWriter, error) {
	if !path.IsAbs(statusPath) || path.Clean(statusPath) != statusPath || path.Base(statusPath) != "status.json" || strings.Contains(statusPath, "//") {
		return nil, ErrSupervisorStatusUnavailable
	}
	uid := uint32(os.Geteuid())
	if statusPath == canonicalV2SupervisorStatusPath && uid != 0 {
		return nil, ErrSupervisorStatusUnavailable
	}
	dirPath := path.Dir(statusPath)
	dirFD, info, err := openV2StatusDirectory(dirPath, uid)
	if err != nil {
		return nil, ErrSupervisorStatusUnavailable
	}
	if err := validateExistingV2StatusFile(dirFD, path.Base(statusPath), uid); err != nil {
		_ = unix.Close(dirFD)
		return nil, ErrSupervisorStatusUnavailable
	}
	return &linuxV2StatusWriter{
		path: statusPath, name: path.Base(statusPath), dirFD: dirFD,
		device: uint64(info.Dev), inode: info.Ino, uid: uid,
	}, nil
}

func openV2StatusDirectory(directory string, expectedUID uint32) (int, unix.Stat_t, error) {
	if !path.IsAbs(directory) || path.Clean(directory) != directory || strings.Contains(directory, "//") {
		return -1, unix.Stat_t{}, ErrSupervisorStatusUnavailable
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, unix.Stat_t{}, ErrSupervisorStatusUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return -1, unix.Stat_t{}, ErrSupervisorStatusUnavailable
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, unix.Stat_t{}, ErrSupervisorStatusUnavailable
		}
		fd = next
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != expectedUID || info.Mode&0o7777 != 0o700 {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, ErrSupervisorStatusUnavailable
	}
	return fd, info, nil
}

func (writer *linuxV2StatusWriter) Write(data []byte) error {
	if writer == nil || len(data) == 0 || len(data) > v2StatusMaximumBytes {
		return ErrSupervisorStatusUnavailable
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed || writer.dirFD < 0 {
		return ErrSupervisorStatusUnavailable
	}
	if err := writer.verifyPinnedDirectory(); err != nil {
		return err
	}
	if err := validateExistingV2StatusFile(writer.dirFD, writer.name, writer.uid); err != nil {
		return err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrSupervisorStatusUnavailable
	}
	temporaryName := ".status-" + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := unix.Openat(writer.dirFD, temporaryName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrSupervisorStatusUnavailable
	}
	removed := false
	defer func() {
		if !removed {
			_ = unix.Unlinkat(writer.dirFD, temporaryName, 0)
		}
	}()
	var fileInfo unix.Stat_t
	if err := unix.Fstat(fd, &fileInfo); err != nil || fileInfo.Mode&unix.S_IFMT != unix.S_IFREG || fileInfo.Uid != writer.uid || fileInfo.Mode&0o7777 != 0o600 || uint64(fileInfo.Dev) != writer.device {
		_ = unix.Close(fd)
		return ErrSupervisorStatusUnavailable
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return ErrSupervisorStatusUnavailable
	}
	if err := writeV2StatusAll(fd, data); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		return ErrSupervisorStatusUnavailable
	}
	if err := unix.Close(fd); err != nil {
		return ErrSupervisorStatusUnavailable
	}
	if err := writer.verifyPinnedDirectory(); err != nil {
		return err
	}
	if err := validateExistingV2StatusFile(writer.dirFD, writer.name, writer.uid); err != nil {
		return err
	}
	if err := unix.Renameat(writer.dirFD, temporaryName, writer.dirFD, writer.name); err != nil {
		return ErrSupervisorStatusUnavailable
	}
	removed = true
	if err := unix.Fsync(writer.dirFD); err != nil {
		return ErrSupervisorStatusUnavailable
	}
	if err := validateExistingV2StatusFile(writer.dirFD, writer.name, writer.uid); err != nil {
		return err
	}
	return nil
}

func writeV2StatusAll(fd int, data []byte) error {
	for len(data) > 0 {
		written, err := unix.Write(fd, data)
		if err != nil {
			return ErrSupervisorStatusUnavailable
		}
		if written <= 0 {
			return errors.New("sandboxdispatch: status short write")
		}
		data = data[written:]
	}
	return nil
}

func (writer *linuxV2StatusWriter) verifyPinnedDirectory() error {
	fd, current, err := openV2StatusDirectory(path.Dir(writer.path), writer.uid)
	if err != nil {
		return ErrSupervisorStatusUnavailable
	}
	_ = unix.Close(fd)
	var pinned unix.Stat_t
	if err := unix.Fstat(writer.dirFD, &pinned); err != nil ||
		uint64(current.Dev) != writer.device || current.Ino != writer.inode ||
		uint64(pinned.Dev) != writer.device || pinned.Ino != writer.inode || pinned.Uid != writer.uid ||
		pinned.Mode&unix.S_IFMT != unix.S_IFDIR || pinned.Mode&0o7777 != 0o700 {
		return ErrSupervisorStatusUnavailable
	}
	return nil
}

func validateExistingV2StatusFile(dirFD int, name string, expectedUID uint32) error {
	var info unix.Stat_t
	err := unix.Fstatat(dirFD, name, &info, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != expectedUID || info.Mode&0o7777 != 0o600 {
		return ErrSupervisorStatusUnavailable
	}
	return nil
}

func (writer *linuxV2StatusWriter) Close() error {
	if writer == nil {
		return nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return nil
	}
	writer.closed = true
	if writer.dirFD >= 0 {
		err := unix.Close(writer.dirFD)
		writer.dirFD = -1
		if err != nil {
			return ErrSupervisorStatusUnavailable
		}
	}
	return nil
}

func openV2StatusCgroupFD(cgroupPath string) (int, error) {
	return openV2CgroupFD(cgroupPath)
}
