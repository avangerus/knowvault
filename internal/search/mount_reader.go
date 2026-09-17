package search

import (
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"sync"
)

type searchMountedRoot struct {
	group  uint32
	mu     sync.Mutex
	fd     int
	opened bool
}

func openSearchMountedRoot(path string) (*searchMountedRoot, error) {
	return openSearchMountedRootForConsumer(path, runtimeidentity.Server)
}
