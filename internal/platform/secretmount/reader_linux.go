//go:build linux

package secretmount

import (
	"syscall"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
)

const (
	minimumReadBytes = 1
	maximumReadBytes = 1 << 20
)

// openMountedRootForConsumer pins a trusted mount directory before a loader
// opens its children. O_NOFOLLOW rejects the common symlink-projected secret
// volume profile deliberately; this boundary accepts only a root-owned
// directory owned by the selected consumer's fixed group, without
// group/other write bits and without any world access bits:
// a world-traversable or foreign-group mount root fails closed.
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
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		info.Uid != 0 || info.Gid != group || info.Mode&0o022 != 0 || info.Mode&0o007 != 0 {
		_ = syscall.Close(fd)
		return nil, &Error{code: CodeUnavailable}
	}
	return &mountedRoot{fd: fd, opened: true, group: group}, nil
}

// read opens exactly one basename relative to the still-open root descriptor.
// It neither resolves a caller-provided path nor follows a symlink; validation
// is based on fstat of the opened descriptor rather than a racy pathname stat.
func (root *mountedRoot) read(filename string, maxBytes int) ([]byte, error) {
	if root == nil || !validMountedFilename(filename) || maxBytes < minimumReadBytes || maxBytes > maximumReadBytes {
		return nil, &Error{code: CodeMaterialInvalid}
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if !root.opened || root.fd < 0 {
		return nil, &Error{code: CodeMaterialInvalid}
	}

	fd, err := syscall.Openat(root.fd, filename, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &Error{code: CodeMaterialInvalid}
	}
	defer func() { _ = syscall.Close(fd) }()

	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Uid != 0 ||
		info.Gid != root.group || info.Nlink != 1 || !validSecretFileMode(info.Mode) || info.Size < 0 || info.Size > int64(maxBytes) {
		return nil, &Error{code: CodeMaterialInvalid}
	}
	contents, err := boundedRead(fd, maxBytes, int(info.Size))
	if err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	return contents, nil
}

// Close releases the directory descriptor once every selected file has been
// preloaded. It is idempotent and never exposes a raw syscall error.
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

func validSecretFileMode(mode uint32) bool {
	permissions := mode & 0o777
	return permissions == 0o400 || permissions == 0o440
}

func boundedRead(fd, maxBytes, expectedSize int) ([]byte, error) {
	capacity := expectedSize
	if capacity < 0 || capacity > maxBytes {
		return nil, syscall.EINVAL
	}
	contents := make([]byte, 0, capacity)
	buffer := make([]byte, 4096)
	for {
		count, err := syscall.Read(fd, buffer)
		if count > 0 {
			if len(contents)+count > maxBytes {
				return nil, syscall.EFBIG
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
		return nil, err
	}
}
