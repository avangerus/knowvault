//go:build !linux

// Package parserv2harness contains test-only plumbing for exercising the
// production dispatcher facade with the released parser image. The real
// implementation is intentionally Linux-only: DispatcherV2's kernel evidence
// contract requires cgroup v2, PID namespaces and pidfds.
package parserv2harness

import (
	"errors"
	"os"
	"testing"
)

const (
	DefaultImage          = "knowvault-document-parser:2.1.0"
	QualifiedArtifactHash = "sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414"
	RequireRealV2Env      = "KNOWVAULT_REQUIRE_REAL_V2"
)

// Harness is unavailable on non-Linux hosts because the production dispatcher
// refuses registrations without kernel-derived cgroup/PID evidence.
type Harness struct{}

// New reports a skippable prerequisite failure in ordinary developer runs and
// is fatal when the dedicated real-v2 qualification is requested.
func New(t testing.TB, _ string) *Harness {
	t.Helper()
	if requireReal() {
		t.Fatalf("real DispatcherV2 Java harness requires Linux cgroup v2, CLONE_NEWPID and pidfd support")
	}
	t.Skip("real DispatcherV2 Java harness requires Linux cgroup v2, CLONE_NEWPID and pidfd support")
	return nil
}

func requireReal() bool {
	return os.Getenv(RequireRealV2Env) == "1"
}

func (h *Harness) SubmitSocketPath() string { return "" }
func (h *Harness) Close()                   {}

var ErrUnavailable = errors.New("parserv2harness: unavailable on this platform")

// ExecImageEntrypoint is called only by the gated child helper test on Linux.
func ExecImageEntrypoint() error { return ErrUnavailable }

// RunSubmitProxyHelper is called only by the gated child helper test on Linux.
func RunSubmitProxyHelper() error { return ErrUnavailable }
