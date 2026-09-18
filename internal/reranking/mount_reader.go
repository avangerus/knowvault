package reranking

import (
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"sync"
)

type rerankingMountedRoot struct {
	group  uint32
	mu     sync.Mutex
	fd     int
	opened bool
}

func openRerankingMountedRoot(path string) (*rerankingMountedRoot, error) {
	return openRerankingMountedRootForConsumer(path, runtimeidentity.Server)
}
