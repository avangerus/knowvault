package postgres_test

// Card D-15 result 2: the kind the separate recognition step returns for a run
// is the kind recorded with that run, and the record survives the encrypted
// artifact round trip. The recognition step itself is stubbed, so this test
// proves the wiring and the run record, not the model's judgement (that is the
// measurement command's subject).

import (
	"context"
	"net/http/httptest"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// d15StubKindRecogniser is the stubbed recognition step: it returns one fixed
// outcome and remembers the question it was handed.
type d15StubKindRecogniser struct {
	outcome  question.KindRecognition
	question string
}

func (stub *d15StubKindRecogniser) Recognise(_ context.Context, value string) question.KindRecognition {
	stub.question = value
	return stub.outcome
}

func TestD15RecognisedKindIsRecordedWithTheRun(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)
	stubModel := questions.NewStubModel()
	server := httptest.NewServer(stubModel)
	defer server.Close()

	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: server.URL, ModelID: "d15-stub",
		MaxOutputTokens: 4096, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "steps-2", MaxTurns: 2, MaxToolCalls: 2, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 4096, TimeoutSeconds: 120,
		},
	})
	if err != nil {
		t.Fatalf("stub adapter: %v", err)
	}
	defer adapter.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d15-kind"})
	env.Questions.EnableGeneration(adapter, nil)

	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_d15_kind"}

	// A non-full kind returned by the recognition step is the kind in the run
	// record, on the run's own question.
	recogniser := &d15StubKindRecogniser{outcome: question.KindRecognition{Kind: question.AnswerKindPlainOverview, Valid: true}}
	env.Questions.EnableAnswerKindRecogniser(recogniser)
	run, err := env.Questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: "что тут есть?",
		IdempotencyKey: e1aIdempotencyKey("d15-kind-plain"),
	})
	if err != nil {
		t.Fatalf("create run with stubbed recognition: %v (code=%s)", err, question.CodeOf(err))
	}
	if run.ToolLoop == nil {
		t.Fatal("run has no tool-loop record")
	}
	if run.ToolLoop.AnswerKind != string(question.AnswerKindPlainOverview) {
		t.Fatalf("run record kind = %q, want %q", run.ToolLoop.AnswerKind, question.AnswerKindPlainOverview)
	}
	if recogniser.question != "что тут есть?" {
		t.Fatalf("recognition step saw %q, want the run's question", recogniser.question)
	}
	if run.ToolLoop.AnswerKindUsage == nil {
		t.Fatal("the run record does not carry the recognition step's token usage")
	}

	// A failed or unlisted recognition is recorded as full, the amendment's
	// default, never as the failing answer.
	failing := &d15StubKindRecogniser{outcome: question.KindRecognition{Kind: "banana", Valid: true}}
	env.Questions.EnableAnswerKindRecogniser(failing)
	fallback, err := env.Questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: "сколько действующих договоров?",
		IdempotencyKey: e1aIdempotencyKey("d15-kind-full"),
	})
	if err != nil {
		t.Fatalf("create run with failing recognition: %v (code=%s)", err, question.CodeOf(err))
	}
	if fallback.ToolLoop == nil || fallback.ToolLoop.AnswerKind != string(question.AnswerKindFull) {
		t.Fatalf("run record kind = %#v, want full", fallback.ToolLoop)
	}
}
