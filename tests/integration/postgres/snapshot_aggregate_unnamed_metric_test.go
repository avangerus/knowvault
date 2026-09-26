package postgres_test

// Card D-14 result 2, live proof: a question whose SUM metric is not named is
// refused -- the ordinary analytic fallback must never reinterpret one of the
// snapshot's numeric columns as the requested metric and publish a total. The
// refusal is terminal: INSUFFICIENT_EVIDENCE, no citations, no published
// aggregate result, in the language of the question.
//
// The projection's own text column deliberately carries the words of both
// questions, so the ordinary retrieval path DOES match this data. That is the
// exact condition under which the old fallback used to publish a total with a
// citation for a metric the snapshot itself refused to resolve; the refusal
// must survive it in Russian and in English.
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

func TestUnnamedAggregateMetricStaysRefusedWhenDataCarriesQuestionWords(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live unnamed-metric refusal proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())

	const schema = "kv_pgq_unnamed_metric_refusal"
	// The note carries "отходов"/"вывезено" and "waste"/"hauled" -- the words
	// of the two questions below -- so lexical retrieval matches the data's own
	// text column. The numeric column is present too, which is exactly what an
	// unresolved SUM must not silently fall back to.
	if _, err := external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_unnamed_metric_refusal" CASCADE;
		CREATE SCHEMA "kv_pgq_unnamed_metric_refusal";
		CREATE TABLE "kv_pgq_unnamed_metric_refusal"."waste_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
		INSERT INTO "kv_pgq_unnamed_metric_refusal"."waste_data" VALUES
			('550e8400-e29b-41d4-a716-4466554400a0', date_trunc('day', now()), 12.345, 'отходов вывезено waste hauled'),
			('550e8400-e29b-41d4-a716-4466554400a1', date_trunc('day', now()), 7.125, 'отходов вывезено waste hauled');
		CREATE VIEW "kv_pgq_unnamed_metric_refusal"."waste_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_unnamed_metric_refusal"."waste_data";
	`); err != nil {
		t.Fatalf("seed external unnamed-metric projection: %v", err)
	}
	defer func() {
		_, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_unnamed_metric_refusal" CASCADE`)
	}()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := isolationProjectionRequest(schema, "waste_view", "unnamed-metric-refusal-lineage", "Waste haulage", "sha256:"+strings.Repeat("8", 64))
	registered, err := service.Register(ctx, regOwnerAccess("req_unnamed_metric_register"), request)
	if err != nil {
		t.Fatalf("register unnamed-metric projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)

	binding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FE1")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, binding, "unnamed-metric-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(binding, regOwner, "req_unnamed_metric_confirm"), confirmRuntimeRequest(binding, grant, "unnamed-metric-confirm")); err != nil {
		t.Fatalf("confirm unnamed-metric source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, registered, request, "unnamed-metric")

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

	for _, tc := range []struct {
		name       string
		question   string
		wantAnswer string
		forbid     []string
	}{
		{
			name:       "russian_question",
			question:   "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?",
			wantAnswer: "\u041d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u0434\u043e\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044c\u0441\u0442\u0432 \u0432 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d\u043d\u044b\u0445 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445.",
			forbid:     []string{"\u0418\u0442\u043e\u0433\u043e:", "\u041e\u0442\u0432\u0435\u0442:", "Total:", "Answer:"},
		},
		{
			name:       "english_question",
			question:   "how much waste was hauled today?",
			wantAnswer: "Insufficient evidence in the connected sources.",
			forbid:     []string{"Total:", "Answer:", "\u0418\u0442\u043e\u0433\u043e:", "\u041e\u0442\u0432\u0435\u0442:"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := questions.Create(ctx, regOwnerAccess("req_unnamed_metric_"+tc.name), question.CreateRequest{
				WorkspaceID:    binding.workspaceID,
				Question:       tc.question,
				AnswerMode:     "EXTRACTIVE",
				IdempotencyKey: isolationQuestionKey("unnamed-metric-" + tc.name),
			})
			if err != nil {
				t.Fatalf("Create %q: %v (code=%s)", tc.question, err, question.CodeOf(err))
			}
			if run.ResultStatus != "INSUFFICIENT_EVIDENCE" {
				t.Fatalf("question %q status=%q answer=%q, want the terminal INSUFFICIENT_EVIDENCE refusal", tc.question, run.ResultStatus, run.Answer)
			}
			if run.Answer != tc.wantAnswer {
				t.Fatalf("question %q answer=%q, want the stable refusal %q", tc.question, run.Answer, tc.wantAnswer)
			}
			if len(run.Citations) != 0 {
				t.Fatalf("question %q refusal disclosed %d citations", tc.question, len(run.Citations))
			}
			if run.AnswerResult != nil {
				t.Fatalf("question %q refusal published an aggregate result: %#v", tc.question, run.AnswerResult)
			}
			for _, phrase := range tc.forbid {
				if strings.Contains(run.Answer, phrase) {
					t.Fatalf("question %q answer %q carries aggregate text %q", tc.question, run.Answer, phrase)
				}
			}
			foundInsufficientEvidence := false
			for _, uncertainty := range run.Uncertainties {
				if uncertainty.Code == question.UncertaintyInsufficientEvidence {
					foundInsufficientEvidence = true
					break
				}
			}
			if !foundInsufficientEvidence {
				t.Fatalf("question %q refusal lacks %q uncertainty: %#v", tc.question, question.UncertaintyInsufficientEvidence, run.Uncertainties)
			}
		})
	}
}
