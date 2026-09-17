package trustbundle

import (
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"sync"
)

type mountedRoot struct {
	group  uint32
	mu     sync.Mutex
	fd     int
	opened bool
}

func openMountedRoot(path string) (*mountedRoot, error) {
	return openMountedRootForConsumer(path, runtimeidentity.Server)
}
