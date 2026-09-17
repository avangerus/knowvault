package postgres_test

// This acceptance proof drives two independent PostgreSQL business-object
// projections into two workspaces and asks the real Question Run authority as
// different principals.  The external database is a real second cluster; the
// local catalog, encrypted evidence, workspace confirmation and question
// artifacts all use the production runtime roles.  A green result therefore
// proves both data separation and membership authorization, rather than only
// a route-level workspace parameter check.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	"knowvault.local/verified-workspace/internal/workspace"
)

const (
	isolationWorkspaceBeta = "ws_registration_beta"
	isolationPrincipalBeta = "usr_registration_beta"
)

// TestPostgreSQLQueryQuestionWorkspaceIsolation proves the user-facing
// multi-workspace scenario over two real external projections.  Workspace A
// contains only the alpha projection and its member; workspace B contains only
// beta and a different member.  The same owner can administer both, while the
// per-workspace members cannot cross the boundary.
func TestPostgreSQLQueryQuestionWorkspaceIsolation(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live workspace isolation proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())
	const schema = "kv_pgq_workspace_iso"
	today := time.Now().UTC()
	alphaCollected := time.Date(today.Year(), today.Month(), today.Day(), 9, 34, 56, 789000000, time.UTC)
	betaCollected := time.Date(today.Year(), today.Month(), today.Day(), 10, 34, 56, 789000000, time.UTC)
	_, err = external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_workspace_iso" CASCADE;
		CREATE SCHEMA "kv_pgq_workspace_iso";
		CREATE TABLE "kv_pgq_workspace_iso"."alpha_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
		CREATE TABLE "kv_pgq_workspace_iso"."beta_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
	`)
	if err != nil {
		t.Fatalf("seed external workspace projections: %v", err)
	}
	if _, err := external.Exec(ctx, "INSERT INTO \"kv_pgq_workspace_iso\".\"alpha_data\" VALUES ($1, $2, 42.000, 'alpha-only route \u043e\u0442\u0445\u043e\u0434\u043e\u0432')", "550e8400-e29b-41d4-a716-446655440020", alphaCollected); err != nil {
		t.Fatalf("seed alpha projection row: %v", err)
	}
	if _, err := external.Exec(ctx, "INSERT INTO \"kv_pgq_workspace_iso\".\"beta_data\" VALUES ($1, $2, 7.000, 'beta-only route \u043e\u0442\u0445\u043e\u0434\u043e\u0432')", "550e8400-e29b-41d4-a716-446655440021", betaCollected); err != nil {
		t.Fatalf("seed beta projection row: %v", err)
	}
	if _, err := external.Exec(ctx, `
		CREATE VIEW "kv_pgq_workspace_iso"."alpha_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_workspace_iso"."alpha_data";
		CREATE VIEW "kv_pgq_workspace_iso"."beta_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_workspace_iso"."beta_data";
	`); err != nil {
		t.Fatalf("create external workspace views: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_workspace_iso" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationBetaPrincipal(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	alphaRequest := isolationProjectionRequest(schema, "alpha_view", "alpha-lineage", "Alpha operations", "sha256:"+strings.Repeat("2", 64))
	betaRequest := isolationProjectionRequest(schema, "beta_view", "beta-lineage", "Beta operations", "sha256:"+strings.Repeat("3", 64))
	alpha, err := service.Register(ctx, regOwnerAccess("req_iso_register_alpha"), alphaRequest)
	if err != nil {
		t.Fatalf("register alpha projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	beta, err := service.Register(ctx, regOwnerAccess("req_iso_register_beta"), betaRequest)
	if err != nil {
		t.Fatalf("register beta projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, alpha.ConnectionID)
	verifyIsolationTrust(t, ctx, admin, beta.ConnectionID)

	alphaBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, alpha.SourceScopeID, alpha.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	alphaAuthority := newAuthorityRuntime(t, ctx)
	alphaGrant := issueRuntimeGrant(t, ctx, alphaAuthority, alphaBinding, "iso-alpha-grant")
	if _, err := alphaAuthority.ConfirmManagedSource(ctx, authorityAccess(alphaBinding, regOwner, "req_iso_alpha_confirm"), confirmRuntimeRequest(alphaBinding, alphaGrant, "iso-alpha-confirm")); err != nil {
		t.Fatalf("confirm alpha workspace source: %v", err)
	}
	seedIsolationBetaWorkspaceBinding(t, ctx, admin, beta.SourceScopeID, beta.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FBY")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	// The publisher itself is the production ingestion handler.  It receives a
	// typed snapshot from the real external reader and never receives SQL text.
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, alpha, alphaRequest, "iso-alpha")
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, beta, betaRequest, "iso-beta")

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
	ask := func(principal, workspaceID, label string) (question.Run, error) {
		return questions.Create(ctx, database.AccessContext{OrganizationID: regOrg, PrincipalID: principal, RequestID: "req_iso_question_" + label}, question.CreateRequest{
			WorkspaceID: workspaceID, Question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?", AnswerMode: "EXTRACTIVE",
			IdempotencyKey: isolationQuestionKey(label),
		})
	}

	alphaOwner, err := ask(regOwner, regWorkspace, "owner-alpha")
	if err != nil || alphaOwner.ResultStatus != "COMPLETED" || alphaOwner.Answer != "\u0418\u0442\u043e\u0433\u043e: 42.000" || len(alphaOwner.Citations) != 1 {
		t.Fatalf("alpha owner answer=%#v err=%v", alphaOwner, err)
	}
	if alphaOwner.Citations[0].Excerpt != "tonnes = 42.000" || alphaOwner.Citations[0].SourceObjectID == "" || alphaOwner.Citations[0].EvidenceFragment == "" {
		t.Fatalf("alpha citation lost numeric evidence lineage: %#v", alphaOwner.Citations[0])
	}
	// Force the generic group-by path through the same Question authority. The
	// field name is a catalog term from the projection, not an entity-specific
	// planner branch; a durable tool receipt must bind to this run's plan and
	// the exact returned Evidence set.
	groupedAlpha, err := questions.Create(ctx, database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_iso_question_grouped_alpha"}, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043f\u043e note?",
		AnswerMode: "EXTRACTIVE", IdempotencyKey: isolationQuestionKey("owner-alpha-grouped"),
	})
	if err != nil || groupedAlpha.ResultStatus != "COMPLETED" || len(groupedAlpha.Citations) == 0 {
		t.Fatalf("generic grouped alpha answer=%#v err=%v", groupedAlpha, err)
	}
	var toolRunCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.question_tool_run
		WHERE organization_id=$1 AND question_run_id=$2 AND status='SUCCEEDED'`, regOrg, groupedAlpha.ID).Scan(&toolRunCount); err != nil {
		t.Fatal(err)
	}
	if toolRunCount != 1 {
		t.Fatalf("generic grouped question persisted %d analytic tool receipts, want 1", toolRunCount)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.question_tool_run SET status='FAILED' WHERE organization_id=$1 AND question_run_id=$2`, regOrg, groupedAlpha.ID); err == nil {
		t.Fatal("analytic tool receipt was mutable")
	}
	var betaVisible int
	if err := appStore.Read(ctx, database.AccessContext{OrganizationID: regOrg, PrincipalID: isolationPrincipalBeta, RequestID: "req_iso_tool_receipt_cross"}, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `SELECT count(*) FROM public.question_tool_run WHERE organization_id=$1 AND question_run_id=$2`, regOrg, groupedAlpha.ID).Scan(&betaVisible)
	}); err != nil {
		t.Fatal(err)
	}
	if betaVisible != 0 {
		t.Fatalf("cross-workspace principal saw %d analytic tool receipts", betaVisible)
	}
	betaOwner, err := ask(regOwner, isolationWorkspaceBeta, "owner-beta")
	if err != nil || betaOwner.ResultStatus != "COMPLETED" || betaOwner.Answer != "\u0418\u0442\u043e\u0433\u043e: 7.000" || len(betaOwner.Citations) != 1 {
		t.Fatalf("beta owner answer=%#v err=%v", betaOwner, err)
	}
	if betaOwner.Citations[0].Excerpt != "tonnes = 7.000" || betaOwner.Citations[0].SourceObjectID == "" || betaOwner.Citations[0].EvidenceFragment == "" {
		t.Fatalf("beta citation lost numeric evidence lineage: %#v", betaOwner.Citations[0])
	}
	alphaMember, err := ask(regViewer, regWorkspace, "member-alpha")
	if err != nil || alphaMember.Answer != "\u0418\u0442\u043e\u0433\u043e: 42.000" {
		t.Fatalf("alpha member answer=%#v err=%v", alphaMember, err)
	}
	betaMember, err := ask(isolationPrincipalBeta, isolationWorkspaceBeta, "member-beta")
	if err != nil || betaMember.Answer != "\u0418\u0442\u043e\u0433\u043e: 7.000" {
		t.Fatalf("beta member answer=%#v err=%v", betaMember, err)
	}

	if _, err := ask(regViewer, isolationWorkspaceBeta, "member-alpha-cross"); question.CodeOf(err) != question.CodeDenied {
		t.Fatalf("alpha member cross-workspace code=%s err=%v, want QUESTION_DENIED", question.CodeOf(err), err)
	}
	if _, err := ask(isolationPrincipalBeta, regWorkspace, "member-beta-cross"); question.CodeOf(err) != question.CodeDenied {
		t.Fatalf("beta member cross-workspace code=%s err=%v, want QUESTION_DENIED", question.CodeOf(err), err)
	}
	if alphaOwner.Answer == betaOwner.Answer || alphaOwner.Citations[0].EvidenceFragment == betaOwner.Citations[0].EvidenceFragment {
		t.Fatalf("workspace answers share data: alpha=%#v beta=%#v", alphaOwner, betaOwner)
	}
}

// TestPostgreSQLQuestionRunMultiDimensionalAggregate proves the generic
// planner/reducer path over a real allowlisted PostgreSQL view. The question
// names two arbitrary projection columns and a rank; no crew, waste or other
// business-specific branch is involved. Both composite buckets must carry
// their numeric and per-dimension Evidence citations.
func TestPostgreSQLQuestionRunMultiDimensionalAggregate(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live multi-group proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())
	const schema = "kv_pgq_multigroup"
	_, err = external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_multigroup" CASCADE;
		CREATE SCHEMA "kv_pgq_multigroup";
		CREATE TABLE "kv_pgq_multigroup"."orders" (
			order_id uuid NOT NULL,
			amount numeric(12,3) NOT NULL,
			region text NOT NULL,
			channel text NOT NULL
		);
		INSERT INTO "kv_pgq_multigroup"."orders" VALUES
			('550e8400-e29b-41d4-a716-446655440030', 7.000, 'North', 'Web'),
			('550e8400-e29b-41d4-a716-446655440031', 5.000, 'North', 'Web'),
			('550e8400-e29b-41d4-a716-446655440032', 10.000, 'South', 'Store');
		CREATE VIEW "kv_pgq_multigroup"."orders_view" AS
			SELECT order_id, amount, region, channel FROM "kv_pgq_multigroup"."orders";
	`)
	if err != nil {
		t.Fatalf("seed external multi-group view: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_multigroup" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := multiGroupProjectionRequest(schema, "orders_view", "multi-group-lineage", "Multi-group orders", "sha256:"+strings.Repeat("7", 64))
	registered, err := service.Register(ctx, regOwnerAccess("req_multi_group_register"), request)
	if err != nil {
		t.Fatalf("register multi-group projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	binding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FBZ")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, binding, "multi-group-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(binding, regOwner, "req_multi_group_confirm"), confirmRuntimeRequest(binding, grant, "multi-group-confirm")); err != nil {
		t.Fatalf("confirm multi-group source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, registered, request, "multi-group")

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
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_multi_group_question"}, question.CreateRequest{
		WorkspaceID: regWorkspace,
		Question:    "aggregate entity orders metric_field=amount group_by=region,channel top=2 order=desc",
		AnswerMode:  "EXTRACTIVE", IdempotencyKey: isolationQuestionKey("multi-group"),
	})
	if err != nil {
		t.Fatalf("multi-group question: %v (code=%s)", err, question.CodeOf(err))
	}
	if run.ResultStatus != "COMPLETED" || run.PlanningOperation != "AGGREGATE" || !strings.Contains(run.Answer, "North / Web") || !strings.Contains(run.Answer, "South / Store") {
		t.Fatalf("multi-group run=%+v", run)
	}
	if len(run.Citations) < 6 {
		t.Fatalf("multi-group citations=%d, want numeric and two group dimensions", len(run.Citations))
	}
	for _, citation := range run.Citations {
		if citation.EvidenceFragment == "" || citation.DeepLink == "" || citation.SourceVersionID == "" || citation.Anchor == "" {
			t.Fatalf("incomplete multi-group citation=%+v", citation)
		}
	}
	var receiptCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.question_tool_run WHERE organization_id=$1 AND question_run_id=$2 AND status='SUCCEEDED'`, regOrg, run.ID).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 {
		t.Fatalf("multi-group analytic receipts=%d, want one sealed invocation", receiptCount)
	}
}

// TestPostgreSQLQuestionRunJSONPathMultiDimensionalAggregate proves that
// JSON business-object leaves remain generic planner fields, not opaque text.
// The real PostgreSQL view emits one JSONB payload per entity; ingestion
// expands its RFC-6901 leaves and the Question authority aggregates exact
// metric/group paths with per-path Evidence anchors.
func TestPostgreSQLQuestionRunJSONPathMultiDimensionalAggregate(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live JSON-path proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())
	const schema = "kv_pgq_jsonpath"
	_, err = external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_jsonpath" CASCADE;
		CREATE SCHEMA "kv_pgq_jsonpath";
		CREATE TABLE "kv_pgq_jsonpath"."records" (
			entity_id uuid NOT NULL,
			payload jsonb NOT NULL
		);
		INSERT INTO "kv_pgq_jsonpath"."records" VALUES
			('550e8400-e29b-41d4-a716-446655440040', '{"Region":"North","Channel":"Web","Amount":7}'::jsonb),
			('550e8400-e29b-41d4-a716-446655440041', '{"Region":"North","Channel":"Web","Amount":5}'::jsonb),
			('550e8400-e29b-41d4-a716-446655440042', '{"Region":"South","Channel":"Store","Amount":10}'::jsonb);
		CREATE VIEW "kv_pgq_jsonpath"."records_view" AS
			SELECT entity_id, payload FROM "kv_pgq_jsonpath"."records";
	`)
	if err != nil {
		t.Fatalf("seed external JSON-path view: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_jsonpath" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := jsonPathProjectionRequest(schema, "records_view", "json-path-lineage", "JSON-path records", "sha256:"+strings.Repeat("8", 64))
	registered, err := service.Register(ctx, regOwnerAccess("req_json_path_register"), request)
	if err != nil {
		t.Fatalf("register JSON-path projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	binding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FC0")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, binding, "json-path-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(binding, regOwner, "req_json_path_confirm"), confirmRuntimeRequest(binding, grant, "json-path-confirm")); err != nil {
		t.Fatalf("confirm JSON-path source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, registered, request, "json-path")

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
	questionText := "aggregate entity records metric_field=payload[/Amount] group_by=payload[/Region],payload[/Channel] top=2 order=desc"
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_json_path_question"}, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: questionText, AnswerMode: "EXTRACTIVE", IdempotencyKey: isolationQuestionKey("json-path-multi-group"),
	})
	if err != nil {
		t.Fatalf("JSON-path question: %v (code=%s)", err, question.CodeOf(err))
	}
	if run.ResultStatus != "COMPLETED" || run.PlanningOperation != "AGGREGATE" || !strings.Contains(run.Answer, "North / Web") || !strings.Contains(run.Answer, "South / Store") {
		t.Fatalf("JSON-path run=%+v", run)
	}
	if len(run.Citations) != 7 {
		t.Fatalf("JSON-path citations=%d, want numeric and two path dimensions for both buckets", len(run.Citations))
	}
	for _, citation := range run.Citations {
		if citation.EvidenceFragment == "" || citation.DeepLink == "" || citation.SourceVersionID == "" || citation.Anchor == "" || !strings.Contains(citation.Anchor, `"json_path":"/`) ||
			(!strings.Contains(citation.Anchor, `"json_path":"/Amount"`) && !strings.Contains(citation.Anchor, `"json_path":"/Region"`) && !strings.Contains(citation.Anchor, `"json_path":"/Channel"`)) {
			t.Fatalf("incomplete JSON-path citation=%+v", citation)
		}
	}
	var receiptCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.question_tool_run WHERE organization_id=$1 AND question_run_id=$2 AND status='SUCCEEDED'`, regOrg, run.ID).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 {
		t.Fatalf("JSON-path analytic receipts=%d, want one sealed invocation", receiptCount)
	}
	assertJSONPathRESTMCPParity(t, ctx, appStore, authority, service, viewer, questions, questionText, run)
}

func isolationProjectionRequest(schema, relation, lineage, name, contractHash string) registration.RegisterRequest {
	return registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: name, Kind: "business-object",
		DatabaseIdentity: "cluster-workspace-isolation", LineageID: lineage, ProjectionRevision: 1,
		ContractHash: contractHash, SchemaName: schema, RelationName: relation, RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "route_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "collected_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint, postgresqlquery.RoleEvidence}, Precision: 3, MaxBytes: 64},
			{Ordinal: 3, Name: "tonnes", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
			{Ordinal: 4, Name: "note", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Nullable: true, MaxBytes: 1024},
		},
	}
}

func multiGroupProjectionRequest(schema, relation, lineage, name, contractHash string) registration.RegisterRequest {
	return registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: name, Kind: "business-object",
		DatabaseIdentity: "cluster-workspace-multigroup", LineageID: lineage, ProjectionRevision: 1,
		ContractHash: contractHash, SchemaName: schema, RelationName: relation, RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "order_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "amount", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
			{Ordinal: 3, Name: "region", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 256},
			{Ordinal: 4, Name: "channel", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 256},
		},
	}
}

func jsonPathProjectionRequest(schema, relation, lineage, name, contractHash string) registration.RegisterRequest {
	return registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: name, Kind: "business-object",
		DatabaseIdentity: "cluster-workspace-multigroup", LineageID: lineage, ProjectionRevision: 1,
		ContractHash: contractHash, SchemaName: schema, RelationName: relation, RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "entity_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "payload", TypeFingerprint: "oid:3802", LogicalType: postgresqlquery.TypeJSONB, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 4096},
		},
	}
}

func seedIsolationPostgreSQLProfile(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	_, err := admin.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
			connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
			item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
		VALUES ('cap_pgq_workspace_iso', $1, 'pgq-build-workspace-iso', 'POSTGRESQL_QUERY', '1.0.0',
			$2, true, true, true, false, true, true, true, true, true, true, $3, transaction_timestamp())`,
		"sha256:"+strings.Repeat("4", 64), "sha256:"+strings.Repeat("5", 64), "sha256:"+strings.Repeat("6", 64))
	if err != nil {
		t.Fatalf("seed workspace-isolation PGQ capability: %v", err)
	}
}

func seedIsolationBetaPrincipal(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, isolationPrincipalBeta, regOrg); err != nil {
		t.Fatalf("seed beta principal: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_registration_beta', $1, $2, 'MEMBER', 1, $3)`, regOrg, isolationPrincipalBeta, regOwner); err != nil {
		t.Fatalf("seed beta organization role: %v", err)
	}
}

func verifyIsolationTrust(t *testing.T, ctx context.Context, admin *pgxpool.Pool, connectionID string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `UPDATE public.source_connection_trust_projection p
		SET status='VERIFIED'
		WHERE p.organization_id=$1 AND p.trust_record_id=(SELECT trust_record_id FROM public.source_connection_revision WHERE organization_id=$1 AND connection_id=$2 AND revision=1)`, regOrg, connectionID); err != nil {
		t.Fatalf("verify isolation PGQ trust: %v", err)
	}
}

// seedIsolationBetaWorkspaceBinding is the same production authority chain as
// the registration helper, with a distinct workspace and member set.  The
// canonical snapshot is built through workspace.Normalize, then the grant and
// confirmation are minted by the real authority repository.
func seedIsolationBetaWorkspaceBinding(t *testing.T, ctx context.Context, admin *pgxpool.Pool, scopeID, scopeConfigHash, bindingID string) authorityOpsFixture {
	t.Helper()
	const policyID = "policy-registration-01ARZ3NDEKTSV4RRFFQ69G5FAV"
	policyHash := "sha256:" + strings.Repeat("d", 64)
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: regOrg, ID: isolationWorkspaceBeta, Revision: 1, Name: isolationWorkspaceBeta,
		Status: workspace.StatusActive, OwnerPrincipalID: regOwner,
		Members:        []workspace.Member{{PrincipalID: regOwner, Role: workspace.RoleOwner}, {PrincipalID: isolationPrincipalBeta, Role: workspace.RoleMember}},
		SourceBindings: []workspace.SourceBinding{{SourceScopeID: scopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeConfigHash, Enabled: true}},
	})
	if err != nil {
		t.Fatalf("normalize beta workspace: %v", err)
	}
	workspaceHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("beta workspace hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("beta workspace canonical snapshot: %v", err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, args ...any) {
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			t.Fatalf("seed beta workspace: %v\n%s", err, statement)
		}
	}
	var policyExists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.organization_policy_revision WHERE organization_id=$1 AND revision=1)`, regOrg).Scan(&policyExists); err != nil {
		t.Fatal(err)
	}
	if !policyExists {
		exec(`INSERT INTO public.organization_policy_revision (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by) VALUES ($1,1,$2,$3,'2019-01-01T00:00:00Z',$4)`, regOrg, policyID, policyHash, regOwner)
	}
	exec(`INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id, current_revision) VALUES ($1,$2,$3,'ACTIVE',$4,1)`, isolationWorkspaceBeta, regOrg, isolationWorkspaceBeta, regOwner)
	exec(`INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by) VALUES ($1,$2,1,$3,$4)`, regOrg, isolationWorkspaceBeta, workspaceHash, regOwner)
	exec(`INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes) VALUES ($1,$2,1,$3,$4)`, regOrg, isolationWorkspaceBeta, workspaceHash, canonicalBytes)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by) VALUES ('wm_iso_beta_owner',$1,$2,$3,'OWNER',1,$3)`, regOrg, isolationWorkspaceBeta, regOwner)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by) VALUES ('wm_iso_beta_member',$1,$2,$3,'MEMBER',1,$4)`, regOrg, isolationWorkspaceBeta, isolationPrincipalBeta, regOwner)
	exec(`INSERT INTO public.workspace_source (organization_id, id, workspace_id, source_scope_id, added_by) VALUES ($1,$2,$3,$4,$5)`, regOrg, bindingID, isolationWorkspaceBeta, scopeID, regOwner)
	exec(`INSERT INTO public.workspace_revision_source (organization_id, workspace_id, workspace_revision, workspace_configuration_hash, workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled) VALUES ($1,$2,1,$3,$4,$5,1,$6,'WORKSPACE_MANAGED',true)`, regOrg, isolationWorkspaceBeta, workspaceHash, bindingID, scopeID, scopeConfigHash)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit beta workspace: %v", err)
	}
	fixture := authorityOpsFixture{organizationID: regOrg, ownerID: regOwner, workspaceID: isolationWorkspaceBeta,
		policyID: policyID, policyNumber: 1, workspaceRevision: 1, workspaceConfHash: workspaceHash,
		workspaceSourceID: bindingID, sourceScopeID: scopeID, sourceScopeRevision: 1, scopeConfigHash: scopeConfigHash}
	authorityStore := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, fixture, "iso-beta-grant")
	if _, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(fixture, regOwner, "req_iso_beta_confirm"), confirmRuntimeRequest(fixture, grant, "iso-beta-confirm")); err != nil {
		t.Fatalf("confirm beta workspace source: %v", err)
	}
	return fixture
}

func isolationQuestionKey(label string) string {
	digest := sha256.Sum256([]byte("iso-question-key\x00" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// publishIsolationProjection performs the same enqueue/claim/begin/read/publish
// sequence used by the worker, but keeps the external connection explicit so
// the test can use the existing non-TLS CI PostgreSQL service.  The snapshot
// and catalog writes remain production code paths.
func publishIsolationProjection(t *testing.T, ctx context.Context, external *pgx.Conn, appStore, workerStore *database.Store, workerQueue *jobs.Queue, handler *ingestion.Handler, registered registration.RegisterResult, request registration.RegisterRequest, label string) {
	t.Helper()
	appQueue, err := jobs.New(appStore)
	if err != nil {
		t.Fatalf("create app queue %s: %v", label, err)
	}
	jobID := mustID(t, "job")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_iso_enqueue_"+label), jobs.Spec{
		JobID: jobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": registered.SourceScopeID},
		IdempotencyKey: "iso-job-" + label, Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue %s: %v", label, err)
	}
	claimed, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim %s: %v ok=%v", label, err, ok)
	}
	if claimed.ID != jobID {
		t.Fatalf("claimed %s job=%q want=%q", label, claimed.ID, jobID)
	}
	publishRunID := mustID(t, "syncrun")
	projection := requestProjection(registered.ConnectionID, request)
	if err := workerStore.Write(ctx, workerAccess(t, regOrg), func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`, registered.SourceScopeID, int64(1), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, registered.SourceScopeID, int64(1), request.ContractHash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`, regOrg, publishRunID, registered.SourceScopeID, claimed.ID)
		return err
	}); err != nil {
		t.Fatalf("begin %s publication: %v", label, err)
	}
	snapshot, err := postgresqlquery.ReadProjection(ctx, external, projection, postgresqlquery.DefaultLimits())
	if err != nil {
		t.Fatalf("read %s external projection: %v", label, err)
	}
	result, err := handler.PublishPostgreSQLSnapshot(ctx, workerAccess(t, regOrg), ingestion.PostgreSQLSnapshotRequest{ScopeID: registered.SourceScopeID, ScopeRevision: 1, SyncRunID: publishRunID, Projection: projection, Snapshot: snapshot, Claimed: claimed})
	if err != nil {
		t.Fatalf("publish %s snapshot: %v (code=%s)", label, err, ingestion.CodeOf(err))
	}
	expectedRows := len(snapshot.Rows)
	expectedEvidence := expectedPublishedEvidence(t, snapshot, request)
	if result.ObjectsSeen != expectedRows || result.ObjectsIngested != expectedRows || result.VersionsCreated != expectedRows || result.EvidencePublished != expectedEvidence {
		t.Fatalf("publish %s counters=%#v", label, result)
	}
	if err := workerQueue.Complete(ctx, workerAccess(t, regOrg), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
		t.Fatalf("complete %s: %v", label, err)
	}
}

func expectedPublishedEvidence(t *testing.T, snapshot postgresqlquery.Snapshot, request registration.RegisterRequest) int {
	t.Helper()
	count := 0
	for _, row := range snapshot.Rows {
		for index, column := range request.Columns {
			evidenceRole := false
			for _, role := range column.Roles {
				if role == postgresqlquery.RoleEvidence {
					evidenceRole = true
					break
				}
			}
			if !evidenceRole {
				continue
			}
			if column.LogicalType != postgresqlquery.TypeJSON && column.LogicalType != postgresqlquery.TypeJSONB {
				count++
				continue
			}
			if index >= len(row.Values) {
				t.Fatalf("snapshot row has no value for JSON column %s", column.Name)
			}
			raw, ok := row.Values[index].Value.(jsontext.Value)
			if !ok {
				t.Fatalf("JSON column %s has unexpected value type %T", column.Name, row.Values[index].Value)
			}
			leaves, err := postgresqlquery.JSONLeaves(raw)
			if err != nil {
				t.Fatalf("JSON leaves for %s: %v", column.Name, err)
			}
			count += len(leaves)
		}
	}
	return count
}

func requestProjection(connectionID string, request registration.RegisterRequest) postgresqlquery.Projection {
	return postgresqlquery.Projection{ConnectionID: connectionID, DatabaseIdentity: request.DatabaseIdentity, LineageID: request.LineageID, Revision: request.ProjectionRevision, ContractHash: request.ContractHash, SchemaName: request.SchemaName, RelationName: request.RelationName, RelationKind: request.RelationKind, Columns: request.Columns, EmptySnapshotPolicy: request.EmptySnapshotPolicy}
}
