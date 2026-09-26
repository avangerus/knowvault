package postgres_test

// Card D-14 result 1, live proof: every answer the product composes itself --
// a calculation with a period, an equality filter, a declared status condition
// and its row cards, an empty enumeration, an insufficient-evidence refusal and
// an extractive answer -- is written in the language of the question. Each
// question is asked against a real POSTGRESQL_QUERY projection through the
// production registration/authority/ingestion/question stack, so the text that
// reaches the user is the text under test, never a fixture's paraphrase.

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
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

func answerLanguageProjectionRequest(schema, relation, lineage, name, contractHash string) registration.RegisterRequest {
	return registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: name, Kind: "business-object",
		DatabaseIdentity: "cluster-answer-language", LineageID: lineage, ProjectionRevision: 1,
		ContractHash: contractHash, SchemaName: schema, RelationName: relation, RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "request_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "address", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence, postgresqlquery.RoleTitle}, MaxBytes: 512},
			{Ordinal: 3, Name: "deadline_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint, postgresqlquery.RoleEvidence, postgresqlquery.RolePeriod}, Precision: 6, MaxBytes: 64},
			{Ordinal: 4, Name: "status", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence, postgresqlquery.RoleStatus}, MaxBytes: 64},
			{Ordinal: 5, Name: "note", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Nullable: true, MaxBytes: 1024},
		},
	}
}

func assertNoAnswerPhrases(t *testing.T, answer string, forbid []string) {
	t.Helper()
	for _, phrase := range forbid {
		if strings.Contains(answer, phrase) {
			t.Fatalf("answer %q carries foreign-language product text %q", answer, phrase)
		}
	}
}

func TestProductComposedAnswersFollowQuestionLanguage(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live answer-language proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())
	const schema = "kv_pgq_answer_language"
	if _, err := external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_answer_language" CASCADE;
		CREATE SCHEMA "kv_pgq_answer_language";
		CREATE TABLE "kv_pgq_answer_language"."requests_data" (
			request_id uuid NOT NULL,
			address text NOT NULL,
			deadline_at timestamptz NOT NULL,
			status text NOT NULL,
			note text
		);
		INSERT INTO "kv_pgq_answer_language"."requests_data" VALUES
			('550e8400-e29b-41d4-a716-446655440090', 'ул. Ленина, д. 12', date_trunc('day', now()), 'OPEN', 'просроченное обращение по адресу'),
			('550e8400-e29b-41d4-a716-446655440091', 'ул. Мира, д. 45', date_trunc('day', now()) - interval '5 days', 'CLOSED', 'закрытое обращение'),
			('550e8400-e29b-41d4-a716-446655440092', 'ул. Садовая, д. 3', date_trunc('day', now()) + interval '5 days', 'OPEN', 'срок ещё не наступил');
		CREATE VIEW "kv_pgq_answer_language"."requests_view" AS
			SELECT request_id, address, deadline_at, status, note FROM "kv_pgq_answer_language"."requests_data";
	`); err != nil {
		t.Fatalf("seed external answer-language projection: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_answer_language" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := answerLanguageProjectionRequest(schema, "requests_view", "answer-language-lineage", "Citizen requests (operational database)", "sha256:"+strings.Repeat("9", 64))
	registered, err := service.Register(ctx, regOwnerAccess("req_answer_language_register"), request)
	if err != nil {
		t.Fatalf("register answer-language projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)

	binding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FE0")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, binding, "answer-language-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(binding, regOwner, "req_answer_language_confirm"), confirmRuntimeRequest(binding, grant, "answer-language-confirm")); err != nil {
		t.Fatalf("confirm answer-language source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, registered, request, "answer-language")

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
	ask := func(label, questionText string) question.Run {
		t.Helper()
		run, err := questions.Create(ctx, regOwnerAccess("req_answer_language_"+label), question.CreateRequest{
			WorkspaceID: binding.workspaceID, Question: questionText, AnswerMode: "EXTRACTIVE",
			IdempotencyKey: isolationQuestionKey("answer-language-" + label),
		})
		if err != nil {
			t.Fatalf("question %q: %v (code=%s)", questionText, err, question.CodeOf(err))
		}
		return run
	}

	t.Run("russian_overdue_list_with_period_filter_status_and_row_cards", func(t *testing.T) {
		run := ask("ru-overdue-list", "Какие обращения граждан просрочены сегодня, status = OPEN?")
		if run.ResultStatus != "COMPLETED" || len(run.Citations) != 1 {
			t.Fatalf("run status=%s citations=%d answer=%q", run.ResultStatus, len(run.Citations), run.Answer)
		}
		for _, want := range []string{
			"Ответ: ул. Ленина, д. 12 — всего 1.",
			"Расчёт выполнен детерминированно",
			"Период по колонке deadline_at",
			"Отбор: status = open.",
			"Отбор: просрочено — колонка deadline_at",
			"Статус учтён: закрытые статусы исключены.",
			"Карточки строк: [1]",
		} {
			if !strings.Contains(run.Answer, want) {
				t.Fatalf("answer %q is missing %q", run.Answer, want)
			}
		}
		assertNoAnswerPhrases(t, run.Answer, []string{"Answer:", "Calculated", "Selection:", "Status considered", "Row cards", "Period by column"})
	})

	t.Run("english_overdue_count_with_period_filter_status_and_row_cards", func(t *testing.T) {
		run := ask("en-overdue-count", "how many citizen requests are overdue today, status = OPEN?")
		if run.ResultStatus != "COMPLETED" || len(run.Citations) != 1 {
			t.Fatalf("run status=%s citations=%d answer=%q", run.ResultStatus, len(run.Citations), run.Answer)
		}
		for _, want := range []string{
			"Answer: 1.",
			"Calculated deterministically",
			"Period by column deadline_at",
			"Selection: status = open.",
			"Selection: overdue — column deadline_at",
			"Status considered: closed statuses excluded.",
			"Row cards: [1]",
		} {
			if !strings.Contains(run.Answer, want) {
				t.Fatalf("answer %q is missing %q", run.Answer, want)
			}
		}
		assertNoAnswerPhrases(t, run.Answer, []string{"Ответ:", "Расчёт", "Отбор:", "Статус учтён", "Карточки строк", "Период по колонке"})
	})

	t.Run("russian_zero_match_declines_in_russian", func(t *testing.T) {
		// A reduction with no matching rows carries no witness to disclose, so
		// the structured path declines and the run reaches the ordinary
		// insufficient-evidence refusal -- in the question's language. (The
		// renderer's own "no matching records" sentence is covered directly by
		// internal/question's answer_language_test.go.)
		run := ask("ru-no-matches", "Какие обращения граждан были вчера, status = OPEN?")
		if run.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(run.Citations) != 0 {
			t.Fatalf("run status=%s citations=%d answer=%q", run.ResultStatus, len(run.Citations), run.Answer)
		}
		if run.Answer != "Недостаточно доказательств в подключённых источниках." {
			t.Fatalf("answer=%q", run.Answer)
		}
	})

	t.Run("english_insufficient_evidence_refusal", func(t *testing.T) {
		run := ask("en-insufficient", "how many requests have region = north?")
		if run.ResultStatus != "INSUFFICIENT_EVIDENCE" || run.Answer != "Insufficient evidence in the connected sources." || len(run.Citations) != 0 {
			t.Fatalf("run status=%s answer=%q citations=%d", run.ResultStatus, run.Answer, len(run.Citations))
		}
	})

	t.Run("russian_extractive_answer", func(t *testing.T) {
		run := ask("ru-extractive", "покажи обращение по адресу")
		if run.ResultStatus != "COMPLETED" || len(run.Citations) == 0 {
			t.Fatalf("run status=%s citations=%d answer=%q", run.ResultStatus, len(run.Citations), run.Answer)
		}
		if !strings.Contains(run.Answer, "просроченное обращение по адресу") {
			t.Fatalf("extractive answer does not quote the matched row: %q", run.Answer)
		}
		assertNoAnswerPhrases(t, run.Answer, []string{"Answer:", "Insufficient evidence", "Row cards", "Selection:", "Calculated"})
	})
}
