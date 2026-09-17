package modelgateway

import "testing"

// The bounded two-attempt budget (ADR-0088) exists for non-deterministic
// sampling: a model that returns a malformed ClaimPlan once returns a valid one
// on the retry. A received-but-rejected response must therefore be allowed to
// spend the second attempt, while deterministic refusals must not.
func TestRetryableAttemptCode(t *testing.T) {
	for _, code := range []ErrorCode{CodeUnavailable, CodeResponse} {
		if !retryableAttemptCode(code) {
			t.Fatalf("%s must be allowed to use the second bounded attempt", code)
		}
	}
	for _, code := range []ErrorCode{CodeInvalid, CodeRejected, CodeProfile, CodeBinding, CodeBudget} {
		if retryableAttemptCode(code) {
			t.Fatalf("%s is deterministic and must stay terminal on the first attempt", code)
		}
	}
	if labMaxAttemptsPerCall != 2 {
		t.Fatalf("bounded attempt budget = %d, want the ADR-0088 cap of 2", labMaxAttemptsPerCall)
	}
}
