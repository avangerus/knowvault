package composition

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

// TestHTTPWriteTimeoutFitsToolLoopBudgetWithMargin is R3's guard against the
// exact drift the review found: modelgateway.ToolLoopProfile.Validate allowed
// a per-question tool-loop/model budget (TimeoutSeconds) that, at its
// maximum, left no room inside httpWriteTimeout for the tool loop's own
// trailing detached persistence (internal/question's
// modelAttemptPersistenceTimeout / questionFailureCleanupTimeout, 5s each) --
// so a question that legitimately spent its whole configured budget could
// have its connection closed by the Go HTTP server before its terminal frame
// (a TIME_LIMIT failure or a degraded INSUFFICIENT_EVIDENCE answer) was ever
// written, surfacing to the client as a bare connection drop instead.
//
// This must keep failing if either constant is ever changed without
// re-checking the other.
func TestHTTPWriteTimeoutFitsToolLoopBudgetWithMargin(t *testing.T) {
	const trailingDetachedPersistence = 5 * time.Second
	const requiredMargin = 5 * time.Second

	maxToolLoopBudget := time.Duration(modelgateway.MaxToolLoopTimeoutSeconds) * time.Second
	worstCase := maxToolLoopBudget + trailingDetachedPersistence

	if worstCase+requiredMargin > httpWriteTimeout {
		t.Fatalf("modelgateway.MaxToolLoopTimeoutSeconds (%s) plus its trailing detached "+
			"persistence (%s) leaves less than the required %s margin inside httpWriteTimeout "+
			"(%s): worst case %s. A question that spends its full budget can have its "+
			"connection closed before its terminal frame is written.",
			maxToolLoopBudget, trailingDetachedPersistence, requiredMargin, httpWriteTimeout, worstCase)
	}

	// A profile at exactly the allowed maximum must still be accepted: this
	// test's ceiling and Validate's ceiling must be the same number.
	profile := modelgateway.ToolLoopProfile{
		ID: "runtime-timeout-margin-check", MaxTurns: 2, MaxToolCalls: 2,
		MaxInputBytes: 8192, MaxToolResultBytes: 1024, MaxOutputTokens: 256,
		TimeoutSeconds: modelgateway.MaxToolLoopTimeoutSeconds,
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("profile at MaxToolLoopTimeoutSeconds must validate: %v", err)
	}
	profile.TimeoutSeconds++
	if err := profile.Validate(); err == nil {
		t.Fatal("profile one second above MaxToolLoopTimeoutSeconds must be rejected")
	}
}
