//go:build linux

package trustbundle

import (
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"syscall"
)

func openMountedRootForConsumer(path string, consumer runtimeidentity.MountConsumer) (*mountedRoot, error) {
	group, valid := consumer.GroupID()
	if path == "" || !valid {
		return nil, &Error{code: CodeUnavailable}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFDIR || info.Uid != 0 || info.Gid != group || info.Mode&0o7777 != 0o750 {
		_ = syscall.Close(fd)
		return nil, &Error{code: CodeUnavailable}
	}
	return &mountedRoot{fd: fd, opened: true, group: group}, nil
}

func (root *mountedRoot) read(filename string, maxBytes int) ([]byte, error) {
	if root == nil || (filename != databaseBundleFilename && filename != oidcBundleFilename &&
		filename != gitBundleFilename && filename != mailBundleFilename) || maxBytes < 1 || maxBytes > maximumBundleBytes {
		return nil, &Error{code: CodeInvalid}
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if !root.opened || root.fd < 0 {
		return nil, &Error{code: CodeInvalid}
	}
	fd, err := syscall.Openat(root.fd, filename, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &Error{code: CodeInvalid}
	}
	defer func() { _ = syscall.Close(fd) }()
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Uid != 0 || info.Gid != root.group || info.Nlink != 1 || !validFileMode(info.Mode) || info.Size < 1 || info.Size > int64(maxBytes) {
		return nil, &Error{code: CodeInvalid}
	}
	return stableRead(fd, maxBytes, info, syscall.Fstat)
}

func validFileMode(mode uint32) bool {
	return mode&0o7777 == 0o440
}

func boundedRead(fd, maxBytes, expectedSize int) ([]byte, error) {
	if expectedSize < 1 || expectedSize > maxBytes {
		return nil, &Error{code: CodeInvalid}
	}
	contents := make([]byte, 0, expectedSize)
	buffer := make([]byte, 4096)
	for {
		count, err := syscall.Read(fd, buffer)
		if count > 0 {
			if len(contents)+count > maxBytes {
				return nil, &Error{code: CodeInvalid}
			}
			contents = append(contents, buffer[:count]...)
		}
		if err == nil {
			if count == 0 {
				return contents, nil
			}
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		return nil, &Error{code: CodeUnavailable}
	}
}

type fstatFunc func(int, *syscall.Stat_t) error

func stableRead(fd, maxBytes int, initial syscall.Stat_t, fstat fstatFunc) ([]byte, error) {
	if fstat == nil || initial.Size < 1 || initial.Size > int64(maxBytes) {
		return nil, &Error{code: CodeInvalid}
	}
	contents, err := boundedRead(fd, maxBytes, int(initial.Size))
	if err != nil {
		return nil, err
	}
	if len(contents) != int(initial.Size) {
		return nil, &Error{code: CodeInvalid}
	}
	var final syscall.Stat_t
	if err := fstat(fd, &final); err != nil || !sameFileSnapshot(initial, final) {
		return nil, &Error{code: CodeInvalid}
	}
	return contents, nil
}

func sameFileSnapshot(initial, final syscall.Stat_t) bool {
	return initial.Dev == final.Dev && initial.Ino == final.Ino &&
		initial.Mode&syscall.S_IFMT == final.Mode&syscall.S_IFMT && initial.Mode == final.Mode &&
		initial.Uid == final.Uid && initial.Gid == final.Gid && initial.Nlink == final.Nlink && initial.Size == final.Size &&
		initial.Mtim.Sec == final.Mtim.Sec && initial.Mtim.Nsec == final.Mtim.Nsec &&
		initial.Ctim.Sec == final.Ctim.Sec && initial.Ctim.Nsec == final.Ctim.Nsec
}

func (root *mountedRoot) Close() error {
	if root == nil {
		return nil
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if !root.opened || root.fd < 0 {
		return nil
	}
	err := syscall.Close(root.fd)
	root.fd = -1
	root.opened = false
	if err != nil {
		return &Error{code: CodeUnavailable}
	}
	return nil
}
