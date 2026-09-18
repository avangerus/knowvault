//go:build linux

package reranking

import (
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"path/filepath"
	"strings"
	"syscall"
)

func openRerankingMountedRootForConsumer(path string, consumer runtimeidentity.MountConsumer) (*rerankingMountedRoot, error) {
	group, valid := consumer.GroupID()
	if path == "" || !valid || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, &Error{code: CodeMountInvalid}
	}
	fd, err := openSecureDirectory(path)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, &Error{code: CodeMountUnavailable}
		}
		return nil, &Error{code: CodeMountInvalid}
	}
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		info.Uid != 0 || info.Gid != group || info.Mode&0o7777 != 0o750 {
		_ = syscall.Close(fd)
		return nil, &Error{code: CodeMountInvalid}
	}
	return &rerankingMountedRoot{fd: fd, opened: true, group: group}, nil
}

// Every component is opened relative to an already-open directory. Neither a
// final symlink nor an ancestor symlink can redirect the administrator mount.
func openSecureDirectory(path string) (int, error) {
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, err := syscall.Openat(fd, component, flags, 0)
		_ = syscall.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

func (root *rerankingMountedRoot) read(filename string, maxBytes int) ([]byte, error) {
	if root == nil || (filename != rerankingManifestFilename && filename != rerankingProfileFilename &&
		filename != rerankingRootCAFilename && filename != rerankingClientCertFile && filename != rerankingClientKeyFile) ||
		(maxBytes != maximumManifestBytes && maxBytes != maximumProfileBytes && maxBytes != maximumRootBytes && maxBytes != maximumClientCertBytes) {
		return nil, &Error{code: CodeMountInvalid}
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	if !root.opened || root.fd < 0 {
		return nil, &Error{code: CodeMountUnavailable}
	}
	var directory syscall.Stat_t
	if syscall.Fstat(root.fd, &directory) != nil || directory.Uid != 0 || directory.Gid != root.group || directory.Mode&0o7777 != 0o750 {
		return nil, &Error{code: CodeMountInvalid}
	}
	fd, err := syscall.Openat(root.fd, filename, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &Error{code: CodeMountInvalid}
	}
	defer func() { _ = syscall.Close(fd) }()
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		info.Uid != 0 || info.Gid != root.group || info.Nlink != 1 || info.Mode&0o7777 != 0o440 ||
		info.Size < 1 || info.Size > int64(maxBytes) {
		return nil, &Error{code: CodeMountInvalid}
	}
	return stableRerankingRead(fd, maxBytes, info)
}

func stableRerankingRead(fd, maxBytes int, initial syscall.Stat_t) ([]byte, error) {
	if initial.Size < 1 || initial.Size > int64(maxBytes) {
		return nil, &Error{code: CodeMountInvalid}
	}
	contents := make([]byte, 0, int(initial.Size))
	buffer := make([]byte, 4096)
	for {
		count, err := syscall.Read(fd, buffer)
		if count > 0 {
			if len(contents)+count > maxBytes {
				return nil, &Error{code: CodeMountInvalid}
			}
			contents = append(contents, buffer[:count]...)
		}
		if err == nil {
			if count == 0 {
				break
			}
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		return nil, &Error{code: CodeMountUnavailable}
	}
	var final syscall.Stat_t
	if len(contents) != int(initial.Size) || syscall.Fstat(fd, &final) != nil || !sameRerankingSnapshot(initial, final) {
		return nil, &Error{code: CodeMountInvalid}
	}
	return contents, nil
}

func sameRerankingSnapshot(initial, final syscall.Stat_t) bool {
	return initial.Dev == final.Dev && initial.Ino == final.Ino &&
		initial.Mode&syscall.S_IFMT == final.Mode&syscall.S_IFMT && initial.Mode == final.Mode &&
		initial.Uid == final.Uid && initial.Gid == final.Gid && initial.Nlink == final.Nlink &&
		initial.Size == final.Size && initial.Mtim.Sec == final.Mtim.Sec && initial.Mtim.Nsec == final.Mtim.Nsec &&
		initial.Ctim.Sec == final.Ctim.Sec && initial.Ctim.Nsec == final.Ctim.Nsec
}

func (root *rerankingMountedRoot) Close() error {
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
		return &Error{code: CodeMountUnavailable}
	}
	return nil
}
