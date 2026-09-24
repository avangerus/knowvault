package question

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestQuestionFailureTerminalRequiresRequestCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
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
		// R2: the question's time budget expiring is its own consistent
		// terminal outcome, distinct from an unrelated execution failure, so a
		// caller (e.g. Ask) can tell the two apart instead of seeing the same
		// generic QUESTION_EXECUTION_FAILED for both.
		{"deadline expired", expired, context.DeadlineExceeded, "FAILED", "TIME_LIMIT"},
		{"deadline expired on an inner budget while the caller ctx still has time", context.Background(), context.DeadlineExceeded, "FAILED", "TIME_LIMIT"},
		{"nil context", nil, context.Canceled, "FAILED", "QUESTION_EXECUTION_FAILED"},
		{"nil context with a deadline cause", nil, context.DeadlineExceeded, "FAILED", "TIME_LIMIT"},
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
