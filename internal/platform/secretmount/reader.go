// Package secretmount contains fail-closed primitives for reading customer-mounted
// secret material. Higher-level manifest/provider composition is intentionally
// separate from this narrow filesystem boundary.
package secretmount

import (
	"strings"
	"sync"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
)

// mountedRoot owns one trusted directory file descriptor. It serialises close
// and reads so callers cannot accidentally reuse an already-closed descriptor.
// It is deliberately unexported: only the future manifest loader should use
// it to preload a complete secret set before exposing any configuration.
type mountedRoot struct {
	group  uint32
	mu     sync.Mutex
	fd     int
	opened bool
}

func openMountedRoot(path string) (*mountedRoot, error) {
	return openMountedRootForConsumer(path, runtimeidentity.Server)
}

func validMountedFilename(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || value == "." || value == ".." ||
		strings.ContainsAny(value, "/\\\x00") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}
