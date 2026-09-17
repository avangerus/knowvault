package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/registration"
)

// TestPostgreSQLCreateRejectsUnknownAggregateMetricWithNumericSnapshot proves
// the complete Question Create path refuses an unresolved SUM metric when the
// loaded PostgreSQL snapshot has numeric columns. The refusal must be
// terminal: the ordinary analytic fallback must not reinterpret the only
// numeric column as the requested metric and publish a COUNT or SUM.
func TestPostgreSQLCreateRejectsUnknownAggregateMetricWithNumericSnapshot(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live aggregate refusal proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())

	const schema = "kv_pgq_aggregate_ambiguity"
	today := time.Now().UTC()
	firstCollected := time.Date(today.Year(), today.Month(), today.Day(), 8, 15, 0, 0, time.UTC)
	secondCollected := time.Date(today.Year(), today.Month(), today.Day(), 9, 45, 0, 0, time.UTC)
	if _, err := external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_aggregate_ambiguity" CASCADE;
		CREATE SCHEMA "kv_pgq_aggregate_ambiguity";
		CREATE TABLE "kv_pgq_aggregate_ambiguity"."operations_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
	`); err != nil {
		t.Fatalf("seed external aggregate projection: %v", err)
	}
	if _, err := external.Exec(ctx, `
		INSERT INTO "kv_pgq_aggregate_ambiguity"."operations_data" VALUES
			('550e8400-e29b-41d4-a716-446655440070', $1, 12.345, 'North route'),
			('550e8400-e29b-41d4-a716-446655440071', $2, 7.125, 'South route')
	`, firstCollected, secondCollected); err != nil {
		t.Fatalf("seed external aggregate rows: %v", err)
	}
	if _, err := external.Exec(ctx, `
		CREATE VIEW "kv_pgq_aggregate_ambiguity"."operations_view" AS
			SELECT route_id, collected_at, tonnes, note
			FROM "kv_pgq_aggregate_ambiguity"."operations_data"
	`); err != nil {
		t.Fatalf("create external aggregate view: %v", err)
	}
	defer func() {
		_, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_aggregate_ambiguity" CASCADE`)
	}()

	admin := resetStage1Database(t)
	appStore, codec, registrationService := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := isolationProjectionRequest(schema, "operations_view", "aggregate-ambiguity-lineage", "Aggregate ambiguity", "sha256:"+strings.Repeat("7", 64))
	registered, err := registrationService.Register(ctx, regOwnerAccess("req_aggregate_ambiguity_register"), request)
	if err != nil {
		t.Fatalf("register aggregate projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)

	binding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FD0")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, binding, "aggregate-ambiguity-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(binding, regOwner, "req_aggregate_ambiguity_confirm"), confirmRuntimeRequest(binding, grant, "aggregate-ambiguity-confirm")); err != nil {
		t.Fatalf("confirm aggregate workspace source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, registered, request, "aggregate-ambiguity")

	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}
	run, err := questions.Create(ctx, regOwnerAccess("req_aggregate_ambiguity_question"), question.CreateRequest{
		WorkspaceID:    binding.workspaceID,
		Question:       "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?",
		AnswerMode:     "EXTRACTIVE",
		IdempotencyKey: isolationQuestionKey("aggregate-ambiguity-question"),
	})
	if err != nil {
		t.Fatalf("Create aggregate refusal: %v (code=%s)", err, question.CodeOf(err))
	}
	if run.ResultStatus != "INSUFFICIENT_EVIDENCE" {
		t.Fatalf("Create status=%q, want terminal INSUFFICIENT_EVIDENCE; run=%#v", run.ResultStatus, run)
	}
	if run.Answer != "\u041d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u0434\u043e\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044c\u0441\u0442\u0432 \u0432 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d\u043d\u044b\u0445 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445." {
		t.Fatalf("Create answer=%q, want the stable insufficient-evidence answer", run.Answer)
	}
	if len(run.Citations) != 0 {
		t.Fatalf("terminal refusal disclosed %d citations", len(run.Citations))
	}
	if run.AnswerResult != nil || strings.Contains(run.Answer, "\u0418\u0442\u043e\u0433\u043e:") || strings.Contains(run.Answer, "\u041e\u0442\u0432\u0435\u0442:") {
		t.Fatalf("terminal refusal published an aggregate result: answer_result=%#v answer=%q", run.AnswerResult, run.Answer)
	}
	foundInsufficientEvidence := false
	for _, uncertainty := range run.Uncertainties {
		if uncertainty.Code == question.UncertaintyInsufficientEvidence {
			foundInsufficientEvidence = true
			break
		}
	}
	if !foundInsufficientEvidence {
		t.Fatalf("terminal refusal lacks %q uncertainty: %#v", question.UncertaintyInsufficientEvidence, run.Uncertainties)
	}
}
