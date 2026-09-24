package postgres_test

// S2 card A (ADR-0098) database-side acceptance proof: a durable, versioned,
// immutable WorkspaceModelContext with role-split RLS, optimistic
// concurrency (If-Match / 412), idempotent replay, and exactly one
// content-free audit event per revision and per audited read. It exercises
// the real internal/workspacecontext.Store against a real PostgreSQL
// database (KNOWVAULT_TEST_POSTGRES_URL), through the same Go path the REST
// transport (internal/platform/workspaceapi/model_context.go) calls, plus
// direct SQL against the workspace_member/knowvault_app runtime role for the
// RLS and immutability triggers no Go-level check alone would catch a
// regression in.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

func newModelContextTestStore(t *testing.T, ctx context.Context) (*workspacecontext.Store, *workspacerepository.Store, *database.Store) {
	t.Helper()
	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}
	contextStore, err := workspacecontext.NewStore(databaseStore, workspaceStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace context store: %v", err)
	}
	return contextStore, workspaceStore, databaseStore
}

func addModelContextMember(t *testing.T, ctx context.Context, workspaceStore *workspacerepository.Store,
	owner database.AccessContext, organizationID, workspaceID, principalID, displayName string, role workspace.Role, idempotencyLabel string) {
	t.Helper()
	current, err := workspaceStore.Get(ctx, owner, workspaceID)
	if err != nil {
		t.Fatalf("load workspace before adding %s: %v", principalID, err)
	}
	if _, err := workspaceStore.AddMember(ctx, owner, workspacerepository.AddMemberRequest{
		IdempotencyKey:            workspaceIdempotencyKey(idempotencyLabel),
		WorkspaceID:               workspaceID,
		ExpectedConfigurationHash: mustWorkspaceHash(t, current),
		PrincipalID:               principalID,
		Role:                      role,
	}); err != nil {
		t.Fatalf("add %s as %s: %v", principalID, role, err)
	}
}

func TestWorkspaceModelContextStoreRightsIsolationConflictsAndAudit(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")

	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status) VALUES
		('usr_carol', 'org_alpha', 'USER', 'Carol', 'ACTIVE'),
		('usr_dave', 'org_alpha', 'USER', 'Dave', 'ACTIVE')
	`); err != nil {
		t.Fatalf("insert carol/dave principals: %v", err)
	}

	contextStore, workspaceStore, _ := newModelContextTestStore(t, ctx)

	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_mc_alice"}
	carol := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_mc_carol"}
	dave := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_dave", RequestID: "req_mc_dave"}
	bob := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_bob", RequestID: "req_mc_bob"}

	addModelContextMember(t, ctx, workspaceStore, alice, "org_alpha", "ws_alpha", "usr_carol", "Carol", workspace.RoleManager, "mc-add-carol")
	addModelContextMember(t, ctx, workspaceStore, alice, "org_alpha", "ws_alpha", "usr_dave", "Dave", workspace.RoleMember, "mc-add-dave")

	// A workspace with no saved context yet: version 0, empty document,
	// editable reflects the caller's own standing.
	empty, err := contextStore.CurrentForREST(ctx, alice, "ws_alpha")
	if err != nil {
		t.Fatalf("read empty context: %v", err)
	}
	if empty.Number != 0 || empty.ContentHash != "" || !empty.Editable || len(empty.Document.Rules) != 0 {
		t.Fatalf("unexpected empty context: %+v", empty)
	}
	emptyForMember, err := contextStore.CurrentForREST(ctx, dave, "ws_alpha")
	if err != nil {
		t.Fatalf("member read of empty context: %v", err)
	}
	if emptyForMember.Editable {
		t.Fatalf("a MEMBER must never be reported editable")
	}

	// A stranger (a different organization entirely) may not even prove the
	// workspace exists.
	if _, err := contextStore.CurrentForREST(ctx, bob, "ws_alpha"); workspacecontext.CodeOf(err) != workspacecontext.CodeAccessDenied {
		t.Fatalf("cross-organization read code=%q err=%v", workspacecontext.CodeOf(err), err)
	}

	// A MEMBER may read but never write.
	if _, err := contextStore.Save(ctx, dave, "ws_alpha", workspacecontext.Document{Description: "member edit"},
		"sha256:empty", modelContextTestIdempotencyKey("member-write")); workspacecontext.CodeOf(err) != workspacecontext.CodeNotEditor {
		t.Fatalf("member write code=%q err=%v", workspacecontext.CodeOf(err), err)
	}

	// OWNER saves version 1.
	documentV1 := workspacecontext.Document{
		Description: "Стандартные правила ответа",
		Rules:       []workspacecontext.Rule{{Text: "Всегда указывай период"}},
		Glossary:    []workspacecontext.Term{{Term: "МНО", Synonyms: []string{"мед. орг."}, Definition: "Медицинская организация"}},
	}
	key1 := modelContextTestIdempotencyKey("save-v1")
	v1, err := contextStore.Save(ctx, alice, "ws_alpha", documentV1, "sha256:empty", key1)
	if err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if v1.Number != 1 || v1.ContentHash == "" || !v1.Editable || len(v1.Document.Rules) != 1 || v1.Document.Rules[0].ID == "" {
		t.Fatalf("unexpected v1: %+v", v1)
	}
	if len(v1.Document.Glossary) != 1 || v1.Document.Glossary[0].ID == "" {
		t.Fatalf("v1 glossary id was not minted: %+v", v1.Document.Glossary)
	}

	// Exact idempotent replay (same actor, same key, same raw document)
	// returns the cached v1 without minting a second version, even though the
	// supplied If-Match is now stale.
	replayed, err := contextStore.Save(ctx, alice, "ws_alpha", documentV1, "sha256:empty", key1)
	if err != nil {
		t.Fatalf("idempotent replay of save v1: %v", err)
	}
	if replayed.Number != 1 || replayed.ContentHash != v1.ContentHash {
		t.Fatalf("idempotent replay minted a new version: %+v", replayed)
	}

	// The same key with a materially different request is a conflict, not a
	// silent second version.
	if _, err := contextStore.Save(ctx, alice, "ws_alpha", workspacecontext.Document{Description: "different"},
		"sha256:empty", key1); workspacecontext.CodeOf(err) != workspacecontext.CodeIdempotencyConflict {
		t.Fatalf("idempotency key reuse code=%q err=%v", workspacecontext.CodeOf(err), err)
	}

	// A stale If-Match (still the empty sentinel, now that v1 exists) is a
	// 412-equivalent conflict, not a silent overwrite.
	if _, err := contextStore.Save(ctx, carol, "ws_alpha", workspacecontext.Document{Description: "stale"},
		"sha256:empty", modelContextTestIdempotencyKey("stale-save")); workspacecontext.CodeOf(err) != workspacecontext.CodeRevisionConflict {
		t.Fatalf("stale If-Match code=%q err=%v", workspacecontext.CodeOf(err), err)
	}

	// MANAGER saves version 2 with the correct current hash.
	documentV2 := workspacecontext.Document{Description: "Обновлённое описание", Rules: []workspacecontext.Rule{{Text: "Правило 2"}}}
	v2, err := contextStore.Save(ctx, carol, "ws_alpha", documentV2, v1.ContentHash, modelContextTestIdempotencyKey("save-v2"))
	if err != nil {
		t.Fatalf("save v2: %v", err)
	}
	if v2.Number != 2 {
		t.Fatalf("expected version 2, got %d", v2.Number)
	}

	// Restore v1 as the new version 3: byte-identical document, change_kind
	// RESTORE, a fresh monotonic version number.
	v3, err := contextStore.Restore(ctx, alice, "ws_alpha", 1, v2.ContentHash, modelContextTestIdempotencyKey("restore-v1"))
	if err != nil {
		t.Fatalf("restore v1 as v3: %v", err)
	}
	if v3.Number != 3 || v3.ContentHash != v1.ContentHash || v3.Document.Description != documentV1.Description {
		t.Fatalf("restore did not reproduce v1 byte-for-byte: %+v", v3)
	}

	// Restoring an unknown version is content-free not-found, not a panic or
	// a silent no-op.
	if _, err := contextStore.Restore(ctx, alice, "ws_alpha", 99, v3.ContentHash,
		modelContextTestIdempotencyKey("restore-unknown")); workspacecontext.CodeOf(err) != workspacecontext.CodeVersionNotFound {
		t.Fatalf("restore unknown version code=%q err=%v", workspacecontext.CodeOf(err), err)
	}

	// The exact-version read is always non-editable, whatever the caller's
	// own standing, and is audited.
	historical, err := contextStore.VersionAtForREST(ctx, alice, "ws_alpha", 2)
	if err != nil {
		t.Fatalf("read historical version 2: %v", err)
	}
	if historical.Editable {
		t.Fatalf("a historical version must never report editable")
	}
	if historical.Document.Description != documentV2.Description {
		t.Fatalf("historical version 2 content mismatch: %+v", historical.Document)
	}

	// History is newest-first and paginates.
	page, nextCursor, err := contextStore.Versions(ctx, alice, "ws_alpha", 2, 0)
	if err != nil {
		t.Fatalf("list versions page 1: %v", err)
	}
	if len(page) != 2 || page[0].Version != 3 || page[1].Version != 2 || nextCursor != 2 {
		t.Fatalf("unexpected first page: %+v cursor=%d", page, nextCursor)
	}
	if page[0].ChangeKind != "RESTORE" || page[1].ChangeKind != "EDIT" {
		t.Fatalf("unexpected change_kind sequence: %+v", page)
	}
	rest, nextCursor2, err := contextStore.Versions(ctx, alice, "ws_alpha", 2, nextCursor)
	if err != nil {
		t.Fatalf("list versions page 2: %v", err)
	}
	if len(rest) != 1 || rest[0].Version != 1 || nextCursor2 != 0 {
		t.Fatalf("unexpected second page: %+v cursor=%d", rest, nextCursor2)
	}

	// --- Audit: exactly one content-free event per revision and per audited
	// read, no more, no less. Idempotent replay above must not have minted an
	// extra event.
	assertModelContextAuditCount(t, ctx, admin, "org_alpha", "workspace.model_context_revised", "WORKSPACE_MODEL_CONTEXT", 3)
	// Reads recorded above: the two CurrentForREST calls (empty as alice,
	// empty as dave) and the two VersionAtForREST calls (historical v2) --
	// exactly 3 (the cross-org denial and the plain Current/Save/Restore
	// calls are unaudited or denied before any event could be appended).
	assertModelContextAuditCount(t, ctx, admin, "org_alpha", "workspace.model_context_read", "WORKSPACE_MODEL_CONTEXT", 3)
	assertModelContextEventsContentFree(t, ctx, admin, "org_alpha")
}

func modelContextTestIdempotencyKey(label string) string {
	return workspaceIdempotencyKey("model-context:" + label)
}

func assertModelContextAuditCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, action, resourceType string, want int) {
	t.Helper()
	var got int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.audit_event
		WHERE organization_id = $1 AND action = $2 AND resource_type = $3
	`, organizationID, action, resourceType).Scan(&got); err != nil {
		t.Fatalf("count audit events action=%s: %v", action, err)
	}
	if got != want {
		t.Fatalf("audit event count for action=%s = %d, want %d", action, got, want)
	}
}

// assertModelContextEventsContentFree proves every WORKSPACE_MODEL_CONTEXT
// audit_event row carries no metadata, no evidence ids and no policy
// decision -- the action, the outcome and the named workspace are the whole
// content-free story, exactly as internal/audit/model_context.go's
// validModelContextProjection requires.
func assertModelContextEventsContentFree(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) {
	t.Helper()
	rows, err := admin.Query(ctx, `
		SELECT metadata_json::text, referenced_evidence_ids_json::text, policy_decision_id, resource_id, workspace_id
		FROM public.audit_event
		WHERE organization_id = $1 AND resource_type = 'WORKSPACE_MODEL_CONTEXT'
	`, organizationID)
	if err != nil {
		t.Fatalf("query model context audit events: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var metadataJSON, evidenceJSON, resourceID string
		var policyDecisionID, workspaceID *string
		if err := rows.Scan(&metadataJSON, &evidenceJSON, &policyDecisionID, &resourceID, &workspaceID); err != nil {
			t.Fatalf("scan model context audit event: %v", err)
		}
		if metadataJSON != "{}" {
			t.Fatalf("model context audit event carries metadata: %s", metadataJSON)
		}
		if evidenceJSON != "[]" {
			t.Fatalf("model context audit event carries evidence ids: %s", evidenceJSON)
		}
		if policyDecisionID != nil {
			t.Fatalf("model context audit event carries a policy decision id")
		}
		if workspaceID == nil || *workspaceID != resourceID {
			t.Fatalf("model context audit event resource_id=%q workspace_id=%v, want them equal (the workspace id)", resourceID, workspaceID)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatalf("expected at least one model context audit event to inspect")
	}
}

// TestWorkspaceModelContextVersionAndPointerAreImmutableAndRLSFailsClosed is
// the direct-SQL proof no Go-level check alone would catch a regression in:
// the two immutability triggers reject every UPDATE/DELETE even for the
// table-owner admin connection, the RLS SELECT/INSERT split holds for the
// knowvault_app runtime role itself (not only through the Store's own
// pre-check), another organization's rows are invisible, and DELETE is
// granted to nobody at all.
func TestWorkspaceModelContextVersionAndPointerAreImmutableAndRLSFailsClosed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_dave', 'org_alpha', 'USER', 'Dave', 'ACTIVE')
	`); err != nil {
		t.Fatalf("insert dave principal: %v", err)
	}

	contextStore, workspaceStore, _ := newModelContextTestStore(t, ctx)
	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_mc_immut_alice"}
	addModelContextMember(t, ctx, workspaceStore, alice, "org_alpha", "ws_alpha", "usr_dave", "Dave", workspace.RoleMember, "mc-immut-add-dave")

	if _, err := contextStore.Save(ctx, alice, "ws_alpha", workspacecontext.Document{Description: "v1"},
		"sha256:empty", modelContextTestIdempotencyKey("immut-v1")); err != nil {
		t.Fatalf("save v1: %v", err)
	}

	// No Go-level path can ever update or delete a version row: the trigger
	// rejects it even for the admin (table-owner) connection.
	if _, err := admin.Exec(ctx, `UPDATE public.workspace_model_context_version SET document = '{}'::jsonb WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND version=1`); err == nil {
		t.Fatal("version row UPDATE succeeded; must be rejected by the immutability trigger")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.workspace_model_context_version WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND version=1`); err == nil {
		t.Fatal("version row DELETE succeeded; must be rejected by the immutability trigger")
	}
	// The pointer can never be rewritten to the same (non-advancing) version
	// or deleted.
	if _, err := admin.Exec(ctx, `UPDATE public.workspace_model_context SET current_version = 1 WHERE organization_id='org_alpha' AND workspace_id='ws_alpha'`); err == nil {
		t.Fatal("pointer UPDATE to a non-advancing version succeeded; must be rejected")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.workspace_model_context WHERE organization_id='org_alpha' AND workspace_id='ws_alpha'`); err == nil {
		t.Fatal("pointer DELETE succeeded; must be rejected by the immutability trigger")
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	// RLS read: a MEMBER (dave) can see the version row through the runtime
	// role itself, not only through the Store's own pre-check.
	readTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, readTx, "org_alpha", "usr_dave")
	var seenVersion int64
	if err := readTx.QueryRow(ctx, `SELECT version FROM public.workspace_model_context_version WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND version=1`).Scan(&seenVersion); err != nil {
		t.Fatalf("member could not read version row under RLS: %v", err)
	}
	if seenVersion != 1 {
		t.Fatalf("unexpected version %d", seenVersion)
	}
	_ = readTx.Rollback(ctx)

	// A MEMBER's raw INSERT attempt at a new version is refused by the RLS
	// INSERT policy (OWNER/MANAGER only), independent of any application
	// check.
	writeTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, writeTx, "org_alpha", "usr_dave")
	zeroHash := "sha256:" + strings.Repeat("0", 64)
	_, insertErr := writeTx.Exec(ctx, `
		INSERT INTO public.workspace_model_context_version (
			organization_id, workspace_id, version, document, content_hash, change_kind, created_by
		) VALUES ('org_alpha', 'ws_alpha', 2, '{}'::jsonb, $1, 'EDIT', 'usr_dave')
	`, zeroHash)
	_ = writeTx.Rollback(ctx)
	if insertErr == nil {
		t.Fatal("member raw INSERT into version history succeeded; RLS must restrict INSERT to OWNER/MANAGER")
	}

	// Cross-organization invisibility at the raw SQL layer too.
	crossTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, crossTx, "org_beta", "usr_bob")
	var crossCount int
	if err := crossTx.QueryRow(ctx, `SELECT count(*) FROM public.workspace_model_context_version WHERE workspace_id='ws_alpha'`).Scan(&crossCount); err != nil {
		t.Fatalf("cross-org scoped query failed: %v", err)
	}
	if crossCount != 0 {
		t.Fatalf("org_beta saw %d rows of ws_alpha's context history", crossCount)
	}
	_ = crossTx.Rollback(ctx)

	// DELETE is granted to nobody, independent of RLS.
	for _, table := range []string{"workspace_model_context_version", "workspace_model_context", "workspace_model_context_command"} {
		var hasDeleteGrant bool
		if err := admin.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.role_table_grants
				WHERE table_schema = 'public' AND table_name = $1
				  AND grantee = 'knowvault_app' AND privilege_type = 'DELETE'
			)
		`, table).Scan(&hasDeleteGrant); err != nil {
			t.Fatal(err)
		}
		if hasDeleteGrant {
			t.Fatalf("knowvault_app must never hold DELETE on %s", table)
		}
	}
}
