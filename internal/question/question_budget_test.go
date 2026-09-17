package question

import (
	"context"
	"encoding/json"
	"errors"
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
