//go:build linux

package main

import (
	"os"
	"syscall"

	"knowvault.local/verified-workspace/internal/operator"
)

// protectedClientSecretFileMetadata applies the Linux ownership/link-count
// part of the protected-input boundary. The descriptor checks in
// readProtectedClientSecretFile already bind the read to this exact inode;
// requiring one link and UID 0 prevents an operator-root process from
// accepting a user-controlled hard link.
func protectedClientSecretFileMetadata(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return false
	}
	// Group-readable input is accepted only for the one deployment runtime
	// group shared by the scratch images. Owner-only files do not expose bytes
	// through their group bits, so their numeric group is immaterial.
	return info.Mode().Perm() != 0o440 || stat.Gid == operator.RuntimeGID
}
