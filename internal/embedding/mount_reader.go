package embedding

import (
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"sync"
)

type embeddingMountedRoot struct {
	group  uint32
	mu     sync.Mutex
	fd     int
	opened bool
}

func openEmbeddingMountedRoot(path string) (*embeddingMountedRoot, error) {
	return openEmbeddingMountedRootForConsumer(path, runtimeidentity.Server)
}
