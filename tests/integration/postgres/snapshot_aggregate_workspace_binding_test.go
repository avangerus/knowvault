package postgres_test

// AGG-2 defect A, real-PostgreSQL regression.
//
// Disabling a source in a workspace (DELETE binding / RemoveSource) never
// changes public.source_object_scope.membership_state -- that field is
// catalog reconciliation ("is this object still discoverable by the
// connector's own listing"), not workspace binding, and it correctly stays
// ACTIVE for a source a workspace has merely stopped using. Before this fix,
// internal/question/snapshot_aggregate.go's loadStructuredSnapshot resolved
// which structural source a row belongs to using membership_state alone, with
// no check that the owning source is actually bound and enabled in THIS
// workspace at its current revision -- so a structural source a workspace had
// disabled could still anchor a snapshot group.
//
// This test binds TWO real structural POSTGRESQL_QUERY sources -- driven
// through the production registration/authority/ingestion pipeline against a
// real second PostgreSQL cluster, exactly like
// TestPostgreSQLQueryQuestionWorkspaceIsolation -- to the SAME workspace, then
// disables one of them (RemoveSource, the real "DELETE binding" the acc stand
// demo used). It proves the aggregate answer counts only the still-enabled
// source: its exact value, its citations, and the fact that the disabled
// source's rows never appear, while directly confirming on the database that
// the disabled source's own public.source_object_scope membership is still
// ACTIVE (the defect's exact root-cause condition) alongside
// public.workspace_revision_source.enabled=false for it at the workspace's
// current revision (what actually gates it now).
import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// agg2StableWorkspaceSourceID duplicates
// internal/workspace/repository.stableWorkspaceSourceID (unexported) so this
// test can seed a binding through seedRegistrationWorkspaceBinding's raw-SQL
// path and still call the real store.RemoveSource on it afterward:
// RemoveSource independently recomputes this exact deterministic id from
// (organization, workspace, scope) and rejects any WorkspaceSourceID that
// does not match it, regardless of what a test seeded into workspace_source.
func agg2StableWorkspaceSourceID(organizationID, workspaceID, sourceScopeID string) string {
	digest := sha256.Sum256([]byte("workspace-source-lineage-v1\x00" + organizationID + "\x00" + workspaceID + "\x00" + sourceScopeID))
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	value := digest[:16]
	result := make([]byte, 0, 26)
	var accumulator uint32
	bits := uint(2)
	for _, item := range value {
		accumulator = (accumulator << 8) | uint32(item)
		bits += 8
		for bits >= 5 {
			bits -= 5
			result = append(result, alphabet[(accumulator>>bits)&31])
			if bits == 0 {
				accumulator = 0
			} else {
				accumulator &= (1 << bits) - 1
			}
		}
	}
	return "binding_" + string(result)
}

func TestSnapshotAggregateExcludesSourceDisabledInThisWorkspace(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live AGG-2 disabled-source proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())
	const schema = "kv_pgq_agg2_binding"
	today := time.Now().UTC()
	enabledCollected := time.Date(today.Year(), today.Month(), today.Day(), 8, 15, 0, 0, time.UTC)
	disabledCollected := time.Date(today.Year(), today.Month(), today.Day(), 9, 45, 0, 0, time.UTC)
	_, err = external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_agg2_binding" CASCADE;
		CREATE SCHEMA "kv_pgq_agg2_binding";
		CREATE TABLE "kv_pgq_agg2_binding"."enabled_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
		CREATE TABLE "kv_pgq_agg2_binding"."disabled_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
	`)
	if err != nil {
		t.Fatalf("seed external AGG-2 projections: %v", err)
	}
	if _, err := external.Exec(ctx, "INSERT INTO \"kv_pgq_agg2_binding\".\"enabled_data\" VALUES ($1, $2, 42.000, 'still-enabled route \u043e\u0442\u0445\u043e\u0434\u043e\u0432')",
		"550e8400-e29b-41d4-a716-446655440050", enabledCollected); err != nil {
		t.Fatalf("seed enabled-source row: %v", err)
	}
	if _, err := external.Exec(ctx, "INSERT INTO \"kv_pgq_agg2_binding\".\"disabled_data\" VALUES ($1, $2, 7.000, 'disabled-in-workspace route \u043e\u0442\u0445\u043e\u0434\u043e\u0432')",
		"550e8400-e29b-41d4-a716-446655440051", disabledCollected); err != nil {
		t.Fatalf("seed disabled-source row: %v", err)
	}
	if _, err := external.Exec(ctx, `
		CREATE VIEW "kv_pgq_agg2_binding"."enabled_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_agg2_binding"."enabled_data";
		CREATE VIEW "kv_pgq_agg2_binding"."disabled_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_agg2_binding"."disabled_data";
	`); err != nil {
		t.Fatalf("create external AGG-2 views: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_agg2_binding" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	enabledRequest := isolationProjectionRequest(schema, "enabled_view", "agg2-enabled-lineage", "AGG-2 enabled operations", "sha256:"+strings.Repeat("a", 64))
	disabledRequest := isolationProjectionRequest(schema, "disabled_view", "agg2-disabled-lineage", "AGG-2 disabled operations", "sha256:"+strings.Repeat("b", 64))
	enabledSource, err := service.Register(ctx, regOwnerAccess("req_agg2_register_enabled"), enabledRequest)
	if err != nil {
		t.Fatalf("register enabled projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	disabledSource, err := service.Register(ctx, regOwnerAccess("req_agg2_register_disabled"), disabledRequest)
	if err != nil {
		t.Fatalf("register disabled projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, enabledSource.ConnectionID)
	verifyIsolationTrust(t, ctx, admin, disabledSource.ConnectionID)

	// Both sources are bound to the SAME workspace, in sequence, each
	// confirmed while its own binding is still the workspace's live one --
	// exactly the interleaving seedRegistrationWorkspaceBinding's own doc
	// comment describes for a repeated call on one tenant (a fresh cutover
	// revision that carries the prior binding forward unchanged).
	authority := newAuthorityRuntime(t, ctx)
	enabledBindingID := agg2StableWorkspaceSourceID(regOrg, regWorkspace, enabledSource.SourceScopeID)
	enabledBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, enabledSource.SourceScopeID, enabledSource.ScopeConfigHash, enabledBindingID)
	enabledGrant := issueRuntimeGrant(t, ctx, authority, enabledBinding, "agg2-enabled-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(enabledBinding, regOwner, "req_agg2_enabled_confirm"), confirmRuntimeRequest(enabledBinding, enabledGrant, "agg2-enabled-confirm")); err != nil {
		t.Fatalf("confirm enabled workspace source: %v", err)
	}
	disabledBindingID := agg2StableWorkspaceSourceID(regOrg, regWorkspace, disabledSource.SourceScopeID)
	disabledBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, disabledSource.SourceScopeID, disabledSource.ScopeConfigHash, disabledBindingID)
	disabledGrant := issueRuntimeGrant(t, ctx, authority, disabledBinding, "agg2-disabled-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(disabledBinding, regOwner, "req_agg2_disabled_confirm"), confirmRuntimeRequest(disabledBinding, disabledGrant, "agg2-disabled-confirm")); err != nil {
		t.Fatalf("confirm disabled workspace source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, enabledSource, enabledRequest, "agg2-enabled")
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, disabledSource, disabledRequest, "agg2-disabled")

	// Now disable the second source in this workspace -- the production
	// "DELETE binding" RemoveSource path, at the current (post-both-bindings)
	// revision. This never touches public.source_object_scope: its membership
	// stays exactly what ingestion set it to, ACTIVE.
	if _, err := authority.RemoveSource(ctx, regOwnerAccess("req_agg2_disable"), workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("agg2-disable-second-source"), WorkspaceID: regWorkspace,
		ExpectedWorkspaceRevision: disabledBinding.workspaceRevision, ExpectedConfigurationHash: disabledBinding.workspaceConfHash,
		WorkspaceSourceID: disabledBinding.workspaceSourceID, SourceScopeID: disabledSource.SourceScopeID,
		SourceScopeRevision: 1, ScopeConfigHash: disabledSource.ScopeConfigHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	}); err != nil {
		t.Fatalf("disable second source in workspace: %v", err)
	}

	// Root-cause condition, confirmed directly on the database: the disabled
	// source's own catalog membership is untouched by RemoveSource.
	var membershipState string
	if err := admin.QueryRow(ctx, `SELECT membership_state FROM public.source_object_scope
		WHERE organization_id=$1 AND source_scope_id=$2`, regOrg, disabledSource.SourceScopeID).Scan(&membershipState); err != nil {
		t.Fatalf("read disabled source membership: %v", err)
	}
	if membershipState != "ACTIVE" {
		t.Fatalf("disabled source membership_state=%q, want it to remain ACTIVE (RemoveSource must not touch it)", membershipState)
	}
	// What actually gates it now: workspace_revision_source.enabled at the
	// workspace's CURRENT revision.
	var currentRevision int64
	var enabledAtCurrentRevision bool
	if err := admin.QueryRow(ctx, `SELECT current_revision FROM public.workspace WHERE organization_id=$1 AND id=$2`,
		regOrg, regWorkspace).Scan(&currentRevision); err != nil {
		t.Fatalf("read workspace current revision: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT enabled FROM public.workspace_revision_source
		WHERE organization_id=$1 AND workspace_id=$2 AND workspace_revision=$3 AND source_scope_id=$4`,
		regOrg, regWorkspace, currentRevision, disabledSource.SourceScopeID).Scan(&enabledAtCurrentRevision); err != nil {
		t.Fatalf("read disabled source binding: %v", err)
	}
	if enabledAtCurrentRevision {
		t.Fatalf("disabled source binding still enabled at current revision %d", currentRevision)
	}

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
	// Spell out the numeric metric: the source-neutral planner deliberately
	// refuses a natural-language SUM when a snapshot has an unknown metric
	// alongside a numeric column (see the aggregate ambiguity regression).
	// This test is about the enabled workspace binding, so it must reach the
	// exact aggregate reducer rather than exercise that separate refusal.
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_agg2_question_after_disable"},
		question.CreateRequest{
			WorkspaceID: regWorkspace, Question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f? metric_field=tonnes", AnswerMode: "EXTRACTIVE",
			IdempotencyKey: isolationQuestionKey("agg2-after-disable"),
		})
	if err != nil {
		t.Fatalf("aggregate question after disabling the second source: %v (code=%s)", err, question.CodeOf(err))
	}
	if run.ResultStatus != "COMPLETED" || run.AnswerResult == nil || run.AnswerResult.Value != "42.000" || !strings.HasPrefix(run.Answer, "\u041e\u0442\u0432\u0435\u0442: 42.000.") {
		t.Fatalf("aggregate answer=%#v, want the still-enabled source's exact total (42.000), unaffected by the disabled source's rows", run)
	}
	if len(run.Citations) != 1 {
		t.Fatalf("aggregate citations=%d, want exactly one (the enabled source's own row)", len(run.Citations))
	}
	if strings.Contains(run.Citations[0].Excerpt, "disabled-in-workspace") || run.Citations[0].SourceObjectID == "" {
		t.Fatalf("aggregate citation leaked the disabled source's evidence: %#v", run.Citations[0])
	}
}
