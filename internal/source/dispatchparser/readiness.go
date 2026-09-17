package dispatchparser

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

// CheckProductionReadiness uses the same submit boundary as extraction. The
// caller chooses only the composition-owned socket, never parser identities or
// a fallback implementation. It does not transfer any source material.
func CheckProductionReadiness(ctx context.Context, socketPath string) error {
	submitter := &sandboxdispatch.Submitter{V2SubmitSocketPath: socketPath, FrameTimeout: 5 * time.Second}
	return submitter.CheckNativeReadiness(ctx)
}
