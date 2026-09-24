package question

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestQuestionFailureTerminalRequiresRequestCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
	// markedFromHealthyCtx simulates exactly what executeToolLoop's defer (or
	// questionContextError) produces for a DeadlineExceeded that a caller
	// already verified against its OWN question-budget context: the caller ctx
	// passed to questionFailureTerminal below may still have time left, since
	// that budget context is a different, tighter, request-scoped one the
	// caller never exposes here.
	markedFromHealthyCtx := markQuestionTimeBudgetExpired(expired, context.DeadlineExceeded)
	// unmarkedGatewayTimeout simulates F2's exact finding: an error chain
	// (modelgateway.Error wraps its cause; Unwrap exposes it to errors.Is)
	// whose root cause happens to be a DeadlineExceeded from the model
	// gateway's OWN bounded HTTP client timeout (gateway.go's
	// Client.http.Timeout) -- independent of, and typically shorter than, the
	// question's own configured time budget. It carries no
	// errQuestionTimeBudgetExpired marker because nothing along that chain
	// ever checked it against the question's own budget context.
	unmarkedGatewayTimeout := fmt.Errorf("model gateway unavailable: %w", context.DeadlineExceeded)
	for _, test := range []struct {
		name   string
		ctx    context.Context
		cause  error
		status string
		code   string
	}{
		{"request cancelled", cancelled, errors.Join(errors.New("tool stopped"), context.Canceled), "CANCELLED", "QUESTION_CANCELLED"},
		{"cancelled request with unrelated failure", cancelled, errors.New("storage failure"), "FAILED", "QUESTION_EXECUTION_FAILED"},
		{"internal cancellation only", context.Background(), context.Canceled, "FAILED", "QUESTION_EXECUTION_FAILED"},
		// An expired ctx with an unmarked deadline is the caller's own
		// deadline (e.g. the legacy generative path), not the tool loop's
		// question budget: it keeps QUESTION_EXECUTION_FAILED and its audit code.
		{"caller deadline expired without the budget marker", expired, context.DeadlineExceeded, "FAILED", "QUESTION_EXECUTION_FAILED"},
		// F2: a bare/unmarked DeadlineExceeded cause, with the caller ctx
		// passed to questionFailureTerminal still healthy, is NOT enough on
		// its own -- it previously let an unrelated inner timeout (the model
		// gateway's own HTTP client) masquerade as the question's own budget
		// expiring. This must stay QUESTION_EXECUTION_FAILED.
		{"unrelated inner timeout while the caller ctx still has time is not the question's own budget", context.Background(), unmarkedGatewayTimeout, "FAILED", "QUESTION_EXECUTION_FAILED"},
		// F2 (fixed side): the SAME "caller ctx still has time" shape, but the
		// cause carries errQuestionTimeBudgetExpired because it was verified,
		// where it was produced, against the actual question-budget context
		// (the tool loop's own profile.TimeoutSeconds-bound ctx, invisible
		// here) -- exactly executeToolLoop's real shape. This must still be
		// TIME_LIMIT.
		{"question's own time budget marked expired even though the caller ctx still has time", context.Background(), markedFromHealthyCtx, "FAILED", "TIME_LIMIT"},
		{"nil context", nil, context.Canceled, "FAILED", "QUESTION_EXECUTION_FAILED"},
		// F2: same as above with a nil caller ctx -- an unmarked cause is not
		// enough, but the marker alone is, since path 1 never needs ctx.
		{"nil context with an unmarked deadline cause", nil, unmarkedGatewayTimeout, "FAILED", "QUESTION_EXECUTION_FAILED"},
		{"nil context with a marked time-budget cause", nil, markedFromHealthyCtx, "FAILED", "TIME_LIMIT"},
		{"unrelated failure never mistaken for a deadline", context.Background(), errors.New("storage failure"), "FAILED", "QUESTION_EXECUTION_FAILED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, code := questionFailureTerminal(test.ctx, test.cause)
			if status != test.status || code != test.code {
				t.Fatalf("terminal = (%q, %q), want (%q, %q)", status, code, test.status, test.code)
			}
		})
	}
}
