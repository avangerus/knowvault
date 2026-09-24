package question

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

func TestGenerationRequestSchemaUsesEvidenceBackedFactClaims(t *testing.T) {
	var schema any
	if err := json.Unmarshal([]byte(generationOutputSchema), &schema); err != nil {
		t.Fatalf("generation output schema is invalid JSON: %v", err)
	}
	for _, required := range []string{`"kind":{"const":"FACT"}`, `"unknown_reason":{"type":"null"}`, `"evidence_ids":{"type":"array","minItems":1`, `"supporting_claim_ids":{"type":"array","maxItems":0}`} {
		if !strings.Contains(generationOutputSchema, required) {
			t.Fatalf("generation output schema is missing %s", required)
		}
	}
	for _, unsupported := range []string{`"INFERENCE"`, `"UNKNOWN"`} {
		if strings.Contains(generationOutputSchema, unsupported) {
			t.Fatalf("generation output schema exposes unsupported claim kind %s", unsupported)
		}
	}
}

func TestQuestionRunContextBoundsGenerativeMode(t *testing.T) {
	parent := context.Background()
	started := time.Now()
	bounded, cancel := questionRunContext(parent, answerModeGenerative)
	defer cancel()

	deadline, ok := bounded.Deadline()
	if !ok {
		t.Fatal("GENERATIVE question context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > generativeQuestionRunBudget || deadline.Before(started.Add(generativeQuestionRunBudget-time.Second)) {
		t.Fatalf("GENERATIVE deadline=%s remaining=%s, want about %s", deadline, remaining, generativeQuestionRunBudget)
	}
	if generativeQuestionRunBudget+questionFailureCleanupTimeout >= 180*time.Second {
		t.Fatalf("question budget plus detached cleanup=%s, must stay below the 180-second proxy ceiling", generativeQuestionRunBudget+questionFailureCleanupTimeout)
	}
}

func TestQuestionRunContextLeavesExtractiveModeUnchanged(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	bounded, cancel := questionRunContext(parent, answerMode)
	defer cancel()
	if bounded != parent {
		t.Fatal("EXTRACTIVE question context was replaced with a GENERATIVE deadline")
	}

	cancelParent()
	if !errors.Is(bounded.Err(), context.Canceled) {
		t.Fatalf("EXTRACTIVE context error=%v, want caller cancellation", bounded.Err())
	}
}

func TestQuestionRunContextPreservesEarlierParentDeadline(t *testing.T) {
	parentDeadline := time.Now().Add(time.Minute)
	parent, cancelParent := context.WithDeadline(context.Background(), parentDeadline)
	defer cancelParent()

	bounded, cancel := questionRunContext(parent, answerModeGenerative)
	defer cancel()
	deadline, ok := bounded.Deadline()
	if !ok || !deadline.Equal(parentDeadline) {
		t.Fatalf("GENERATIVE deadline=%s, want the earlier caller deadline=%s", deadline, parentDeadline)
	}
}

func TestQuestionContextErrorPrefersCancellationOverFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if !errors.Is(questionContextError(ctx, errors.New("model response")), context.Canceled) {
		t.Fatal("canceled question was eligible for the GENERATIVE fallback")
	}
	if questionContextError(context.Background(), errors.New("model response")) != nil {
		t.Fatal("ordinary model failure was mistaken for context cancellation")
	}
}

// TestQuestionContextErrorDoesNotTrustAnUnrelatedDeadlineExceededCause is F2's
// regression test at questionContextError itself: this is where
// completeGenerative/completeGenerativeInsufficient feed genErr/verifyErr
// (from service.generation.Generate, i.e. modelgateway's Client) in as cause.
// A model gateway call that fails with its OWN bounded HTTP client timeout
// (gateway.go's Client.http.Timeout, wrapped into cause via
// modelgateway.Error's Unwrap) must not be mistaken for THIS ctx's own
// question-budget deadline when ctx itself has not expired: it must fall
// through to nil, so each call site's normal modelgateway.CodeOf-based
// retry/degrade handling -- its real classification -- runs instead of a
// short-circuited context-shaped failure.
func TestQuestionContextErrorDoesNotTrustAnUnrelatedDeadlineExceededCause(t *testing.T) {
	unrelatedGatewayTimeout := fmt.Errorf("model gateway unavailable: %w", context.DeadlineExceeded)
	if err := questionContextError(context.Background(), unrelatedGatewayTimeout); err != nil {
		t.Fatalf("unrelated DeadlineExceeded cause with a healthy ctx = %v, want nil", err)
	}

	// When ctx itself actually IS the question's own expired budget context,
	// questionContextError still reports it -- and marks it, so
	// questionFailureTerminal can trust it downstream.
	expired, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
	err := questionContextError(expired, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired question-budget ctx = %v, want a DeadlineExceeded", err)
	}
	if !errors.Is(err, errQuestionTimeBudgetExpired) {
		t.Fatalf("expired question-budget ctx = %v, want it marked errQuestionTimeBudgetExpired", err)
	}
}

func TestMarkQuestionTimeBudgetExpiredRequiresCtxsOwnDeadline(t *testing.T) {
	expired, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	// ctx's own deadline expired AND err is DeadlineExceeded-shaped: mark it.
	marked := markQuestionTimeBudgetExpired(expired, context.DeadlineExceeded)
	if !errors.Is(marked, errQuestionTimeBudgetExpired) || !errors.Is(marked, context.DeadlineExceeded) {
		t.Fatalf("expired ctx + DeadlineExceeded err = %v, want it marked and still a DeadlineExceeded", marked)
	}

	// ctx has NOT expired: an unrelated DeadlineExceeded-shaped err (e.g. the
	// model gateway's own HTTP client timeout) is never marked (F2).
	if got := markQuestionTimeBudgetExpired(context.Background(), context.DeadlineExceeded); errors.Is(got, errQuestionTimeBudgetExpired) {
		t.Fatalf("healthy ctx marked an unrelated DeadlineExceeded err: %v", got)
	}

	// ctx was cancelled, not deadline-exceeded: never marked, even if err
	// itself happens to be DeadlineExceeded-shaped.
	if got := markQuestionTimeBudgetExpired(cancelled, context.DeadlineExceeded); errors.Is(got, errQuestionTimeBudgetExpired) {
		t.Fatalf("cancelled (not expired) ctx marked a DeadlineExceeded err: %v", got)
	}

	// err itself is not DeadlineExceeded-shaped: never marked, even though
	// ctx's own deadline did expire.
	unrelated := errors.New("storage failure")
	if got := markQuestionTimeBudgetExpired(expired, unrelated); errors.Is(got, errQuestionTimeBudgetExpired) || got != unrelated {
		t.Fatalf("non-deadline err = %v, want it returned unchanged and unmarked", got)
	}

	if markQuestionTimeBudgetExpired(expired, nil) != nil {
		t.Fatal("nil err must stay nil")
	}
	if got := markQuestionTimeBudgetExpired(nil, context.DeadlineExceeded); !errors.Is(got, context.DeadlineExceeded) || errors.Is(got, errQuestionTimeBudgetExpired) {
		t.Fatalf("nil ctx = %v, want the err returned unchanged and unmarked", got)
	}
}

func TestModelAttemptPersistenceContextDetachesFromRunDeadline(t *testing.T) {
	type contextKey string
	parent := context.WithValue(context.Background(), contextKey("request"), "request-value")
	parent, cancelParent := context.WithTimeout(parent, time.Millisecond)
	defer cancelParent()
	<-parent.Done()

	persist, cancelPersist := modelAttemptPersistenceContext(parent)
	defer cancelPersist()
	if persist.Err() != nil {
		t.Fatalf("detached persistence context inherited parent error: %v", persist.Err())
	}
	if got := persist.Value(contextKey("request")); got != "request-value" {
		t.Fatalf("detached persistence context lost request value: %v", got)
	}
	deadline, ok := persist.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining <= 0 || remaining > modelAttemptPersistenceTimeout {
		t.Fatalf("persistence deadline=%s remaining=%s, want a fresh bounded deadline within %s", deadline, remaining, modelAttemptPersistenceTimeout)
	}

	second, cancelSecond := modelAttemptPersistenceContext(parent)
	defer cancelSecond()
	if persist == second {
		t.Fatal("two model attempts reused one persistence context")
	}
}

func TestModelResponseStageReasonCodeIsClosedAndContentFree(t *testing.T) {
	tests := []struct {
		stage modelgateway.ResponseStage
		want  string
	}{
		{stage: modelgateway.ResponseStageWire, want: "MODEL_RESPONSE_STAGE_WIRE"},
		{stage: modelgateway.ResponseStageJSON, want: "MODEL_RESPONSE_STAGE_JSON"},
		{stage: modelgateway.ResponseStageClaim, want: "MODEL_RESPONSE_STAGE_CLAIM"},
		{stage: "MODEL_RESPONSE_STAGE_PROMPT", want: ""},
	}
	for _, test := range tests {
		t.Run(string(test.stage), func(t *testing.T) {
			if got := modelResponseStageReasonCode(test.stage); got != test.want {
				t.Fatalf("stage reason=%q, want %q", got, test.want)
			}
		})
	}
}
