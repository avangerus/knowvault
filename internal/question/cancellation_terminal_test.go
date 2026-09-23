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
		{"deadline expired", expired, context.DeadlineExceeded, "FAILED", "QUESTION_EXECUTION_FAILED"},
		{"nil context", nil, context.Canceled, "FAILED", "QUESTION_EXECUTION_FAILED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, code := questionFailureTerminal(test.ctx, test.cause)
			if status != test.status || code != test.code {
				t.Fatalf("terminal = (%q, %q), want (%q, %q)", status, code, test.status, test.code)
			}
		})
	}
}
