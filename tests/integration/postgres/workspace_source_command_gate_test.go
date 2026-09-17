package postgres_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	commandGateScopeID         = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	commandGateBindingID       = "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	commandGateSecondScopeID   = "scope_01BX5ZZKBKACTAV9WEVGEMMVRZ"
	commandGateSecondBindingID = "binding_01BX5ZZKBKACTAV9WEVGEMMVRZ"
)

func TestWorkspaceSourceClosedIDValidatorExposesOnlyBindingAndScope(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	for signature, want := range map[string]bool{
		"app.source_generated_id_is_valid(text,text)":           false,
		"app.workspace_source_generated_id_is_valid(text,text)": true,
	} {
		var got bool
		if err := admin.QueryRow(ctx, `SELECT has_function_privilege('knowvault_app',$1,'EXECUTE')`, signature).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("runtime EXECUTE %s=%v, want %v", signature, got, want)
		}
	}
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
	var bindingOK, scopeOK, unknownOK bool
	if err := tx.QueryRow(ctx, `SELECT
		app.workspace_source_generated_id_is_valid($1,'binding'),
		app.workspace_source_generated_id_is_valid($2,'scope'),
		app.workspace_source_generated_id_is_valid('anything','.*')`,
		commandGateBindingID, commandGateScopeID).Scan(&bindingOK, &scopeOK, &unknownOK); err != nil {
		t.Fatal(err)
	}
	if !bindingOK || !scopeOK || unknownOK {
		t.Fatalf("closed ID validator binding/scope/unknown=%v/%v/%v", bindingOK, scopeOK, unknownOK)
	}
	if _, err := tx.Exec(ctx, `SELECT app.source_generated_id_is_valid('anything','.*')`); err == nil {
		t.Fatal("runtime executed caller-prefix source ID validator")
	}
}

func TestWorkspaceSourceCommandGateAllowsOneExactAddAndKeepsScopeDraft(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", "")

	var currentRevision int64
	var sourceRows, projectionRows int
	var connectionActive, scopeActive any
	var scopeStatus, activationStatus string
	if err := admin.QueryRow(ctx, `
		SELECT current_revision FROM public.workspace
		WHERE organization_id = 'org_alpha' AND id = 'ws_alpha'
	`).Scan(&currentRevision); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_source WHERE organization_id = 'org_alpha'`).Scan(&sourceRows); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_source WHERE organization_id = 'org_alpha' AND workspace_revision = 2 AND enabled`).Scan(&projectionRows); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT connection.active_revision, scope.active_revision, scope.status, activation.status
		FROM public.source_scope AS scope
		JOIN public.source_connection AS connection
		  ON connection.organization_id = scope.organization_id AND connection.id = scope.connection_id
		JOIN public.source_scope_activation AS activation
		  ON activation.organization_id = scope.organization_id
		 AND activation.source_scope_id = scope.id
		 AND activation.source_scope_revision = 1
		WHERE scope.organization_id = 'org_alpha' AND scope.id = $1
	`, commandGateScopeID).Scan(&connectionActive, &scopeActive, &scopeStatus, &activationStatus); err != nil {
		t.Fatal(err)
	}
	if currentRevision != 2 || sourceRows != 1 || projectionRows != 1 {
		t.Fatalf("revision/lineage/projection=%d/%d/%d, want 2/1/1", currentRevision, sourceRows, projectionRows)
	}
	if connectionActive != nil || scopeActive != nil || scopeStatus != "DRAFT" || activationStatus != "DRAFT" {
		t.Fatalf("configuration mutation created authority: connection=%v scope=%v status=%s/%s",
			connectionActive, scopeActive, scopeStatus, activationStatus)
	}
}

func TestWorkspaceSourceRemoveAndReAddReuseStableLineage(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", "")
	commitWorkspaceSourceToggle(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", false, "")
	commitWorkspaceSourceToggle(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", true, "")

	var lineages, disabledAtThree, enabledAtFour int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_source
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha'`).Scan(&lineages); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_source
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND workspace_revision=3 AND NOT enabled`).Scan(&disabledAtThree); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_source
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND workspace_revision=4 AND enabled`).Scan(&enabledAtFour); err != nil {
		t.Fatal(err)
	}
	if lineages != 1 || disabledAtThree != 1 || enabledAtFour != 1 {
		t.Fatalf("lineage/remove/re-add=%d/%d/%d, want 1/1/1", lineages, disabledAtThree, enabledAtFour)
	}
}

func TestWorkspaceSourceCommandRejectsCanonicalMutableAndPointerSmuggling(t *testing.T) {
	for _, fault := range []string{"canonical_smuggle", "mutable_row_smuggle", "omitted_pointer"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
			app := openApplicationPool(t, ctx, testDatabaseURL(t))
			commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", fault)
			var revision int64
			var lineages int
			if err := admin.QueryRow(ctx, `SELECT current_revision FROM public.workspace
				WHERE organization_id='org_alpha' AND id='ws_alpha'`).Scan(&revision); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_source
				WHERE organization_id='org_alpha'`).Scan(&lineages); err != nil {
				t.Fatal(err)
			}
			if revision != 1 || lineages != 0 {
				t.Fatalf("fault %s left revision/lineage=%d/%d", fault, revision, lineages)
			}
		})
	}
}

func TestWorkspaceSourceCommandRejectsReadOnlyAndArchivedBase(t *testing.T) {
	for _, status := range []workspace.Status{workspace.StatusReadOnly, workspace.StatusArchived} {
		t.Run(string(status), func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			installWorkspaceStatusRevision(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha", status)
			insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
			app := openApplicationPool(t, ctx, testDatabaseURL(t))
			commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", "inactive_base")

			var revision int64
			var persistedStatus string
			var lineages int
			if err := admin.QueryRow(ctx, `SELECT current_revision,status FROM public.workspace
				WHERE organization_id='org_alpha' AND id='ws_alpha'`).Scan(&revision, &persistedStatus); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_source
				WHERE organization_id='org_alpha'`).Scan(&lineages); err != nil {
				t.Fatal(err)
			}
			if revision != 2 || persistedStatus != string(status) || lineages != 0 {
				t.Fatalf("inactive base drifted revision/status/lineage=%d/%s/%d", revision, persistedStatus, lineages)
			}
		})
	}
}

func TestWorkspaceSourceCommandRejectsStaleBaseSnapshot(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", "")
	commitWorkspaceSourceToggle(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", false, "stale_base")

	var revision int64
	if err := admin.QueryRow(ctx, `SELECT current_revision FROM public.workspace
		WHERE organization_id='org_alpha' AND id='ws_alpha'`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision != 2 {
		t.Fatalf("stale source command advanced workspace to revision %d", revision)
	}
}

func TestWorkspaceSourceCommandRejectsUndeclaredSecondBindingChange(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", "")
	installSecondWorkspaceBinding(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	commitWorkspaceSourceToggle(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", false, "two_binding_smuggle")

	var revision int64
	var enabled int
	if err := admin.QueryRow(ctx, `SELECT current_revision FROM public.workspace
		WHERE organization_id='org_alpha' AND id='ws_alpha'`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_source
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha'
		  AND workspace_revision=3 AND enabled`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if revision != 3 || enabled != 2 {
		t.Fatalf("two-binding smuggle changed base revision/enabled=%d/%d", revision, enabled)
	}
}

func TestOrdinaryWorkspaceCommandsCarryNonEmptySourceProjectionExactly(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", "")

	var revisionTwoHash string
	if err := admin.QueryRow(ctx, `SELECT configuration_hash FROM public.workspace_revision
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND revision=2`).Scan(&revisionTwoHash); err != nil {
		t.Fatal(err)
	}
	config := database.DefaultConfig()
	config.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := workspaceStore.Update(ctx, database.AccessContext{
		OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_source_carry_update",
	}, workspacerepository.UpdateRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-carry-update"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: revisionTwoHash, Name: "ws_alpha_renamed", Description: "",
	})
	if err != nil {
		t.Fatalf("ordinary metadata update with source projection: %v", err)
	}
	if updated.Revision != 3 || len(updated.SourceBindings) != 1 || !updated.SourceBindings[0].Enabled {
		t.Fatalf("updated source snapshot = %#v", updated)
	}

	var exactCarry bool
	if err := admin.QueryRow(ctx, `
		SELECT old.workspace_source_id = fresh.workspace_source_id
		   AND old.source_scope_id = fresh.source_scope_id
		   AND old.source_scope_revision = fresh.source_scope_revision
		   AND old.scope_config_hash = fresh.scope_config_hash
		   AND old.access_mode = fresh.access_mode
		   AND old.enabled = fresh.enabled
		FROM public.workspace_revision_source AS old
		JOIN public.workspace_revision_source AS fresh
		  ON fresh.organization_id=old.organization_id AND fresh.workspace_id=old.workspace_id
		WHERE old.organization_id='org_alpha' AND old.workspace_id='ws_alpha'
		  AND old.workspace_revision=2 AND fresh.workspace_revision=3
	`).Scan(&exactCarry); err != nil {
		t.Fatal(err)
	}
	if !exactCarry {
		t.Fatal("ordinary workspace command drifted source projection")
	}
}

func TestWorkspaceSourceLineageRequiresFreshExactAddReceipt(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_source (
			organization_id, id, workspace_id, source_scope_id, added_by
		) VALUES ('org_alpha', $1, 'ws_alpha', $2, 'usr_alice')
	`, commandGateBindingID, commandGateScopeID); err != nil {
		t.Fatalf("insert is deferred to proof gate: %v", err)
	}
	assertWorkspaceSourcePGError(t, tx.Commit(ctx), "23514", "", "workspace source lineage lacks fresh exact add receipt")
}

func TestWorkspaceSourceCommandReceiptKeepsOriginalReceiptChecks(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	// The migration replaces only the four closed-vocabulary constraints. These
	// representative attacks prove the original hash, result and terminal-shape
	// checks were not accidentally discarded while extending the receipt.
	for name, statement := range map[string]string{
		"raw idempotency key": `INSERT INTO public.workspace_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, command_workspace_id,
			command_resource_type, command_resource_id, operation, canonical_request_hash
		) VALUES ('org_alpha','usr_alice','raw-key','ws_alpha','WORKSPACE','ws_alpha','WORKSPACE_UPDATE',$$sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff$$)`,
		"partial result": `INSERT INTO public.workspace_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, command_workspace_id,
			command_resource_type, command_resource_id, operation, canonical_request_hash,
			result_workspace_id
		) VALUES ('org_alpha','usr_alice',$$sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$$,
			'ws_alpha','WORKSPACE','ws_alpha','WORKSPACE_UPDATE',$$sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff$$,'ws_alpha')`,
		"terminal pending fields": `INSERT INTO public.workspace_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, command_workspace_id,
			command_resource_type, command_resource_id, operation, canonical_request_hash,
			audit_event_id
		) VALUES ('org_alpha','usr_alice',$$sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb$$,
			'ws_alpha','WORKSPACE','ws_alpha','WORKSPACE_UPDATE',$$sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff$$,'audit_bad')`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, statement); err == nil {
				t.Fatalf("receipt invariant accepted %s", name)
			}
		})
	}
}

func TestWorkspaceSourceFailureReceiptsAreTerminalWithoutMutation(t *testing.T) {
	for _, testCase := range []struct {
		status, outcome, code, keyCharacter string
	}{
		{"DENIED", "DENIED", "WORKSPACE_DENIED", "a"},
		{"NOT_FOUND", "DENIED", "WORKSPACE_NOT_FOUND", "b"},
		{"PRECONDITION_FAILED", "FAILED", "WORKSPACE_REVISION_CONFLICT", "c"},
	} {
		t.Run(testCase.status, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
			app := openApplicationPool(t, ctx, testDatabaseURL(t))
			tx, err := app.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
			keyHash := "sha256:" + strings.Repeat(testCase.keyCharacter, 64)
			if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_command_receipt (
				organization_id,actor_principal_id,idempotency_key_hash,gate_version,
				command_workspace_id,command_resource_type,command_resource_id,operation,
				canonical_request_hash,source_expected_workspace_revision,source_expected_configuration_hash,
				command_workspace_source_id,command_source_scope_id,command_source_scope_revision,
				command_scope_config_hash,command_access_mode
			) SELECT 'org_alpha','usr_alice',$1,2,'ws_alpha','WORKSPACE_SOURCE',$2,'WORKSPACE_SOURCE_ADD',
			         $3,1,configuration_hash,$2,$4,1,$5,'SOURCE_ENFORCED'
			    FROM public.workspace_revision
			   WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND revision=1`,
				keyHash, commandGateBindingID, "sha256:"+strings.Repeat("f", 64), commandGateScopeID, "sha256:"+strings.Repeat("6", 64)); err != nil {
				t.Fatal(err)
			}
			errorCode := testCase.code
			auditID := "audit_source_" + strings.ToLower(testCase.status)
			appendWorkspaceSourceAuditInTx(t, ctx, tx, "org_alpha", "usr_alice", "ws_alpha", nil, auditID, 1, true, testCase.outcome, &errorCode)
			if _, err := tx.Exec(ctx, `UPDATE public.workspace_command_receipt
				SET status=$4,audit_event_id=$5,terminal_at=transaction_timestamp()
				WHERE organization_id=$1 AND actor_principal_id=$2 AND idempotency_key_hash=$3`,
				"org_alpha", "usr_alice", keyHash, testCase.status, auditID); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit %s source receipt: %v", testCase.status, err)
			}
			var revisions, lineages int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision WHERE organization_id='org_alpha' AND workspace_id='ws_alpha'`).Scan(&revisions); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_source WHERE organization_id='org_alpha'`).Scan(&lineages); err != nil {
				t.Fatal(err)
			}
			if revisions != 1 || lineages != 0 {
				t.Fatalf("failure receipt mutated workspace: revisions/lineages=%d/%d", revisions, lineages)
			}
		})
	}
}

func TestWorkspaceMemberCannotInsertSourceConfiguration(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id,organization_id,type,display_name,status)
		VALUES ('usr_bob','org_alpha','USER','Bob','ACTIVE');
		INSERT INTO public.workspace_member (
			id,organization_id,workspace_id,principal_id,role,valid_from_revision,added_by
		) VALUES ('wsm_bob','org_alpha','ws_alpha','usr_bob','MEMBER',1,'usr_alice')
	`); err != nil {
		t.Fatal(err)
	}
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_bob")
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_source (
		organization_id,id,workspace_id,source_scope_id,added_by
	) VALUES ('org_alpha',$1,'ws_alpha',$2,'usr_bob')`, commandGateBindingID, commandGateScopeID); err == nil {
		t.Fatal("MEMBER inserted source configuration")
	}
}

func TestManagerSelfRemovalCarriesSourcesOnceThenLosesInsertAuthority(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (
		id,organization_id,type,display_name,status
	) VALUES ('usr_bob','org_alpha','USER','Bob','ACTIVE')`); err != nil {
		t.Fatal(err)
	}
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	commitWorkspaceSourceAdd(t, ctx, app, "org_alpha", "usr_alice", "ws_alpha", "")

	config := database.DefaultConfig()
	config.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	var revisionTwoHash string
	if err := admin.QueryRow(ctx, `SELECT configuration_hash FROM public.workspace_revision
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND revision=2`).Scan(&revisionTwoHash); err != nil {
		t.Fatal(err)
	}
	withManager, err := workspaceStore.AddMember(ctx, database.AccessContext{
		OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_add_manager_with_source",
	}, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("add-manager-with-source"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: revisionTwoHash, PrincipalID: "usr_bob", Role: workspace.RoleManager,
	})
	if err != nil {
		t.Fatalf("add manager: %v", err)
	}
	withManagerHash, err := workspace.ConfigurationHash(withManager)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := workspaceStore.RemoveMember(ctx, database.AccessContext{
		OrganizationID: "org_alpha", PrincipalID: "usr_bob", RequestID: "req_manager_self_remove_with_source",
	}, workspacerepository.RemoveMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("manager-self-remove-with-source"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: withManagerHash, PrincipalID: "usr_bob",
	})
	if err != nil {
		t.Fatalf("manager self-removal with source projection: %v", err)
	}
	if removed.Revision != 4 || len(removed.SourceBindings) != 1 {
		t.Fatalf("self-removal snapshot = %#v", removed)
	}

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_bob")
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_source (
		organization_id,workspace_id,workspace_revision,workspace_configuration_hash,
		workspace_source_id,source_scope_id,source_scope_revision,scope_config_hash,access_mode,enabled
	) VALUES ('org_alpha','ws_alpha',5,$1,$2,$3,1,$4,'SOURCE_ENFORCED',true)`,
		"sha256:"+strings.Repeat("e", 64), commandGateBindingID, commandGateScopeID,
		"sha256:"+strings.Repeat("6", 64)); err == nil {
		t.Fatal("previously removed manager retained source projection INSERT authority")
	}
}

func installSecondWorkspaceBinding(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, workspaceID string) {
	t.Helper()
	const scopeHash = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	artifactID := "artifact_scope_config_second"
	var scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1,$2,1)`,
		organizationID, commandGateSecondScopeID).Scan(&scopeResourceID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.encrypted_artifact (
		organization_id,id,owner_table,owner_column,resource_type,resource_id,field_name,
		ciphertext,size_bytes,nonce,wrapped_dek,wrapped_dek_hash,kek_reference,kek_version,
		aad_hash,plaintext_hash
	) VALUES ($1,$2,'source_scope_revision','scope_config_artifact_id','SOURCE_SCOPE_CONFIG',$3,'SCOPE_CONFIG',
		decode(repeat('ab',17),'hex'),1,decode(repeat('35',12),'hex'),decode('77726170706564','hex'),
		$4,'kms://tenant',1,$5,$6)`, organizationID, artifactID, scopeResourceID,
		"sha256:"+strings.Repeat("8", 64), "sha256:"+strings.Repeat("9", 64), scopeHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_scope (
		organization_id,id,connection_id,discovered_scope_id,source_type,latest_revision,created_by
	) SELECT organization_id,$2,connection_id,discovered_scope_id,source_type,1,$3
	  FROM public.source_scope WHERE organization_id=$1 AND id=$4`,
		organizationID, commandGateSecondScopeID, ownerID, commandGateScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_scope_revision (
		organization_id,source_scope_id,revision,connection_id,connection_revision,discovered_scope_id,
		discovered_identity_digest,discovered_identity_digest_key_version,source_type,
		scope_config_artifact_id,scope_config_hash,scope_contract_version,access_mode,
		sync_interval_seconds,content_freshness_sla_seconds,acl_freshness_sla_seconds,
		object_limit,byte_limit,max_object_bytes,created_by
	) SELECT organization_id,$2,1,connection_id,connection_revision,discovered_scope_id,
	         discovered_identity_digest,discovered_identity_digest_key_version,source_type,
	         $3,scope_config_hash,scope_contract_version,access_mode,
	         sync_interval_seconds,content_freshness_sla_seconds,acl_freshness_sla_seconds,
	         object_limit,byte_limit,max_object_bytes,$4
	    FROM public.source_scope_revision
	   WHERE organization_id=$1 AND source_scope_id=$5 AND revision=1`,
		organizationID, commandGateSecondScopeID, artifactID, ownerID, commandGateScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_scope_activation (
		organization_id,source_scope_id,source_scope_revision,revision,status
	) VALUES ($1,$2,1,1,'DRAFT')`, organizationID, commandGateSecondScopeID); err != nil {
		t.Fatal(err)
	}

	var currentRevision int64
	var currentCanonical []byte
	if err := tx.QueryRow(ctx, `SELECT workspace.current_revision,snapshot.canonical_bytes
		FROM public.workspace
		JOIN public.workspace_revision_snapshot AS snapshot
		  ON snapshot.organization_id=workspace.organization_id AND snapshot.workspace_id=workspace.id
		 AND snapshot.revision=workspace.current_revision
		WHERE workspace.organization_id=$1 AND workspace.id=$2`, organizationID, workspaceID).Scan(&currentRevision, &currentCanonical); err != nil {
		t.Fatal(err)
	}
	current, err := workspace.ParseCanonicalSnapshot(currentCanonical)
	if err != nil || currentRevision != 2 {
		t.Fatalf("second binding base revision=%d err=%v", currentRevision, err)
	}
	next := current
	next.Revision++
	next.SourceBindings = append(append([]workspace.SourceBinding(nil), current.SourceBindings...), workspace.SourceBinding{
		SourceScopeID: commandGateSecondScopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeHash, Enabled: true,
	})
	next, err = workspace.Normalize(next)
	if err != nil {
		t.Fatal(err)
	}
	nextHash, err := workspace.ConfigurationHash(next)
	if err != nil {
		t.Fatal(err)
	}
	nextCanonical, err := workspace.CanonicalSnapshot(next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_source (
		organization_id,id,workspace_id,source_scope_id,added_by
	) VALUES ($1,$2,$3,$4,$5)`, organizationID, commandGateSecondBindingID,
		workspaceID, commandGateSecondScopeID, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision (
		organization_id,workspace_id,revision,configuration_hash,created_by
	) VALUES ($1,$2,3,$3,$4)`, organizationID, workspaceID, nextHash, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_snapshot (
		organization_id,workspace_id,revision,configuration_hash,canonical_bytes
	) VALUES ($1,$2,3,$3,$4)`, organizationID, workspaceID, nextHash, nextCanonical); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_source (
		organization_id,workspace_id,workspace_revision,workspace_configuration_hash,
		workspace_source_id,source_scope_id,source_scope_revision,scope_config_hash,access_mode,enabled
	) SELECT organization_id,workspace_id,3,$3,workspace_source_id,source_scope_id,
	         source_scope_revision,scope_config_hash,access_mode,enabled
	    FROM public.workspace_revision_source
	   WHERE organization_id=$1 AND workspace_id=$2 AND workspace_revision=2`,
		organizationID, workspaceID, nextHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_source (
		organization_id,workspace_id,workspace_revision,workspace_configuration_hash,
		workspace_source_id,source_scope_id,source_scope_revision,scope_config_hash,access_mode,enabled
	) VALUES ($1,$2,3,$3,$4,$5,1,$6,'SOURCE_ENFORCED',true)`,
		organizationID, workspaceID, nextHash, commandGateSecondBindingID, commandGateSecondScopeID, scopeHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.workspace SET current_revision=3,updated_at=transaction_timestamp()
		WHERE organization_id=$1 AND id=$2`, organizationID, workspaceID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("install second exact binding: %v", err)
	}
}

func installWorkspaceStatusRevision(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, workspaceID string, status workspace.Status) {
	t.Helper()
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 2, Name: workspaceID,
		Status: status, OwnerPrincipalID: ownerID,
		Members: []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision (
		organization_id,workspace_id,revision,configuration_hash,created_by
	) VALUES ($1,$2,2,$3,$4)`, organizationID, workspaceID, hash, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_snapshot (
		organization_id,workspace_id,revision,configuration_hash,canonical_bytes
	) VALUES ($1,$2,2,$3,$4)`, organizationID, workspaceID, hash, canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.workspace
		SET status=$3,current_revision=2,updated_at=transaction_timestamp()
		WHERE organization_id=$1 AND id=$2`, organizationID, workspaceID, string(status)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("install %s workspace revision: %v", status, err)
	}
}

func commitWorkspaceSourceAdd(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, actorID, workspaceID, fault string) {
	t.Helper()
	const scopeHash = "sha256:6666666666666666666666666666666666666666666666666666666666666666"

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, actorID)
	var currentRevision int64
	var currentHash string
	var currentCanonical []byte
	if err := tx.QueryRow(ctx, `
		SELECT workspace.current_revision, revision.configuration_hash, snapshot.canonical_bytes
		FROM public.workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id=workspace.organization_id AND revision.workspace_id=workspace.id
		 AND revision.revision=workspace.current_revision
		JOIN public.workspace_revision_snapshot AS snapshot
		  ON snapshot.organization_id=revision.organization_id AND snapshot.workspace_id=revision.workspace_id
		 AND snapshot.revision=revision.revision AND snapshot.configuration_hash=revision.configuration_hash
		WHERE workspace.organization_id=$1 AND workspace.id=$2
		FOR UPDATE OF workspace
	`, organizationID, workspaceID).Scan(&currentRevision, &currentHash, &currentCanonical); err != nil {
		t.Fatal(err)
	}
	current, err := workspace.ParseCanonicalSnapshot(currentCanonical)
	if err != nil || current.Revision != currentRevision {
		t.Fatalf("load current workspace source base: revision=%d err=%v", currentRevision, err)
	}
	next := current
	next.Revision++
	next.SourceBindings = append(append([]workspace.SourceBinding(nil), current.SourceBindings...), workspace.SourceBinding{
		SourceScopeID: commandGateScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: scopeHash, Enabled: true,
	})
	if fault == "canonical_smuggle" {
		next.Name = workspaceID + "_canonical_smuggled"
	}
	next, err = workspace.Normalize(next)
	if err != nil {
		t.Fatal(err)
	}
	nextHash, err := workspace.ConfigurationHash(next)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := workspace.CanonicalSnapshot(next)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := "sha256:" + strings.Repeat("a", 64)
	requestHash := "sha256:" + strings.Repeat("b", 64)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, gate_version,
			command_workspace_id, command_resource_type, command_resource_id, operation,
			canonical_request_hash, source_expected_workspace_revision,
			source_expected_configuration_hash, command_workspace_source_id,
			command_source_scope_id, command_source_scope_revision,
			command_scope_config_hash, command_access_mode
		) VALUES ($1,$2,$3,2,$4,'WORKSPACE_SOURCE',$5,'WORKSPACE_SOURCE_ADD',$6,
		          $7,$8,$5,$9,1,$10,'SOURCE_ENFORCED')
	`, organizationID, actorID, keyHash, workspaceID, commandGateBindingID, requestHash,
		currentRevision, currentHash, commandGateScopeID, scopeHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_source (
		organization_id,id,workspace_id,source_scope_id,added_by
	) VALUES ($1,$2,$3,$4,$5)`, organizationID, commandGateBindingID, workspaceID, commandGateScopeID, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision (
		organization_id,workspace_id,revision,configuration_hash,created_by
	) VALUES ($1,$2,$3,$4,$5)`, organizationID, workspaceID, next.Revision, nextHash, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_snapshot (
		organization_id,workspace_id,revision,configuration_hash,canonical_bytes
	) VALUES ($1,$2,$3,$4,$5)`, organizationID, workspaceID, next.Revision, nextHash, canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_source (
		organization_id,workspace_id,workspace_revision,workspace_configuration_hash,
		workspace_source_id,source_scope_id,source_scope_revision,scope_config_hash,access_mode,enabled
	) VALUES ($1,$2,$3,$4,$5,$6,1,$7,'SOURCE_ENFORCED',true)`, organizationID, workspaceID,
		next.Revision, nextHash, commandGateBindingID, commandGateScopeID, scopeHash); err != nil {
		t.Fatal(err)
	}
	if fault != "omitted_pointer" {
		if fault == "mutable_row_smuggle" {
			if _, err := tx.Exec(ctx, `UPDATE public.workspace
				SET name=$3,current_revision=$4,updated_at=transaction_timestamp()
				WHERE organization_id=$1 AND id=$2`, organizationID, workspaceID,
				workspaceID+"_mutable_smuggled", next.Revision); err != nil {
				t.Fatal(err)
			}
		} else if _, err := tx.Exec(ctx, `UPDATE public.workspace SET current_revision=$3, updated_at=transaction_timestamp()
			WHERE organization_id=$1 AND id=$2`, organizationID, workspaceID, next.Revision); err != nil {
			t.Fatal(err)
		}
	}
	auditID := "audit_source_add"
	appendWorkspaceSourceAuditInTx(t, ctx, tx, organizationID, actorID, workspaceID, &workspaceID, auditID, next.Revision, true, "SUCCESS", nil)
	if _, err := tx.Exec(ctx, `UPDATE public.workspace_command_receipt
		SET status='SUCCESS', result_workspace_id=$4, result_workspace_revision=$5,
		    result_configuration_hash=$6, audit_event_id=$7, terminal_at=transaction_timestamp()
		WHERE organization_id=$1 AND actor_principal_id=$2 AND idempotency_key_hash=$3`,
		organizationID, actorID, keyHash, workspaceID, next.Revision, nextHash, auditID); err != nil {
		t.Fatal(err)
	}
	commitErr := tx.Commit(ctx)
	expectedMessage := map[string]string{
		"canonical_smuggle":   "workspace source command changed non-source configuration",
		"mutable_row_smuggle": "workspace source command did not install exact mutable projection",
		"omitted_pointer":     "workspace source command did not install exact mutable projection",
		"inactive_base":       "workspace source command requires ACTIVE base",
	}[fault]
	if expectedMessage != "" {
		assertWorkspaceSourcePGError(t, commitErr, "23514", "", expectedMessage)
		return
	} else if commitErr != nil {
		t.Fatalf("commit exact source add: %v", commitErr)
	}
}

func commitWorkspaceSourceToggle(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, actorID, workspaceID string, enabled bool, fault string) {
	t.Helper()
	const scopeHash = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, actorID)
	var currentRevision int64
	var currentHash string
	var currentCanonical []byte
	if err := tx.QueryRow(ctx, `
		SELECT workspace.current_revision, revision.configuration_hash, snapshot.canonical_bytes
		FROM public.workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id=workspace.organization_id AND revision.workspace_id=workspace.id
		 AND revision.revision=workspace.current_revision
		JOIN public.workspace_revision_snapshot AS snapshot
		  ON snapshot.organization_id=revision.organization_id AND snapshot.workspace_id=revision.workspace_id
		 AND snapshot.revision=revision.revision AND snapshot.configuration_hash=revision.configuration_hash
		WHERE workspace.organization_id=$1 AND workspace.id=$2 FOR UPDATE OF workspace
	`, organizationID, workspaceID).Scan(&currentRevision, &currentHash, &currentCanonical); err != nil {
		t.Fatal(err)
	}
	current, err := workspace.ParseCanonicalSnapshot(currentCanonical)
	if err != nil {
		t.Fatal(err)
	}
	target := workspace.SourceBinding{
		SourceScopeID: commandGateScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: scopeHash, Enabled: enabled,
	}
	var next workspace.Snapshot
	if enabled {
		next, err = workspace.NextSourceBindingEnabled(current, target)
	} else {
		next, err = workspace.NextSourceBindingDisabled(current, target)
	}
	if err != nil {
		t.Fatal(err)
	}
	if fault == "two_binding_smuggle" {
		found := false
		for index := range next.SourceBindings {
			if next.SourceBindings[index].SourceScopeID == commandGateSecondScopeID {
				next.SourceBindings[index].Enabled = false
				found = true
				break
			}
		}
		if !found {
			t.Fatal("two-binding smuggle fixture has no second binding")
		}
		next, err = workspace.Normalize(next)
		if err != nil {
			t.Fatal(err)
		}
	}
	nextHash, err := workspace.ConfigurationHash(next)
	if err != nil {
		t.Fatal(err)
	}
	nextCanonical, err := workspace.CanonicalSnapshot(next)
	if err != nil {
		t.Fatal(err)
	}
	operation := "WORKSPACE_SOURCE_REMOVE"
	keyCharacter := "c"
	if enabled {
		operation = "WORKSPACE_SOURCE_ADD"
		keyCharacter = "d"
	}
	keyHash := "sha256:" + strings.Repeat(keyCharacter, 64)
	requestHash := "sha256:" + strings.Repeat("e", 64)
	receiptExpectedRevision := currentRevision
	receiptExpectedHash := currentHash
	if fault == "stale_base" {
		receiptExpectedRevision--
		if receiptExpectedRevision < 1 {
			t.Fatal("stale-base fixture requires a prior workspace revision")
		}
		if err := tx.QueryRow(ctx, `SELECT configuration_hash
			FROM public.workspace_revision
			WHERE organization_id=$1 AND workspace_id=$2 AND revision=$3`,
			organizationID, workspaceID, receiptExpectedRevision).Scan(&receiptExpectedHash); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_command_receipt (
		organization_id,actor_principal_id,idempotency_key_hash,gate_version,
		command_workspace_id,command_resource_type,command_resource_id,operation,
		canonical_request_hash,source_expected_workspace_revision,source_expected_configuration_hash,
		command_workspace_source_id,command_source_scope_id,command_source_scope_revision,
		command_scope_config_hash,command_access_mode
	) VALUES ($1,$2,$3,2,$4,'WORKSPACE_SOURCE',$5,$6,$7,$8,$9,$5,$10,1,$11,'SOURCE_ENFORCED')`,
		organizationID, actorID, keyHash, workspaceID, commandGateBindingID, operation,
		requestHash, receiptExpectedRevision, receiptExpectedHash, commandGateScopeID, scopeHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision (
		organization_id,workspace_id,revision,configuration_hash,created_by
	) VALUES ($1,$2,$3,$4,$5)`, organizationID, workspaceID, next.Revision, nextHash, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_snapshot (
		organization_id,workspace_id,revision,configuration_hash,canonical_bytes
	) VALUES ($1,$2,$3,$4,$5)`, organizationID, workspaceID, next.Revision, nextHash, nextCanonical); err != nil {
		t.Fatal(err)
	}
	for _, binding := range next.SourceBindings {
		bindingID := commandGateBindingID
		if binding.SourceScopeID == commandGateSecondScopeID {
			bindingID = commandGateSecondBindingID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_source (
			organization_id,workspace_id,workspace_revision,workspace_configuration_hash,
			workspace_source_id,source_scope_id,source_scope_revision,scope_config_hash,access_mode,enabled
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'SOURCE_ENFORCED',$9)`, organizationID, workspaceID,
			next.Revision, nextHash, bindingID, binding.SourceScopeID, binding.SourceScopeRevision,
			binding.ScopeConfigHash, binding.Enabled); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE public.workspace SET current_revision=$3,updated_at=transaction_timestamp()
		WHERE organization_id=$1 AND id=$2`, organizationID, workspaceID, next.Revision); err != nil {
		t.Fatal(err)
	}
	auditID := "audit_source_toggle_" + keyCharacter
	appendWorkspaceSourceAuditInTx(t, ctx, tx, organizationID, actorID, workspaceID, &workspaceID,
		auditID, next.Revision, enabled, "SUCCESS", nil)
	if _, err := tx.Exec(ctx, `UPDATE public.workspace_command_receipt
		SET status='SUCCESS',result_workspace_id=$4,result_workspace_revision=$5,
		    result_configuration_hash=$6,audit_event_id=$7,terminal_at=transaction_timestamp()
		WHERE organization_id=$1 AND actor_principal_id=$2 AND idempotency_key_hash=$3`,
		organizationID, actorID, keyHash, workspaceID, next.Revision, nextHash, auditID); err != nil {
		t.Fatal(err)
	}
	commitErr := tx.Commit(ctx)
	expectedMessage := map[string]string{
		"stale_base":          "workspace source command has stale base snapshot",
		"two_binding_smuggle": "workspace source command changed undeclared bindings",
	}[fault]
	if expectedMessage != "" {
		assertWorkspaceSourcePGError(t, commitErr, "23514", "", expectedMessage)
		return
	}
	if commitErr != nil {
		t.Fatalf("commit source toggle enabled=%v: %v", enabled, commitErr)
	}
}

func appendWorkspaceSourceAuditInTx(t *testing.T, ctx context.Context, tx pgx.Tx, organizationID, actorID, commandWorkspaceID string, auditWorkspaceID *string, auditID string, revision int64, enabled bool, outcome string, errorCode *string) {
	t.Helper()
	metadata := map[string]any{
		"workspace_revision": revision, "workspace_source_id": commandGateBindingID,
		"source_scope_id": commandGateScopeID, "source_scope_revision": int64(1),
		"scope_config_hash": "sha256:" + strings.Repeat("6", 64),
		"access_mode":       "SOURCE_ENFORCED", "enabled": enabled,
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	action := audit.ActionWorkspaceSourceAdded
	if !enabled {
		action = audit.ActionWorkspaceSourceRemoved
	}
	scopeRevision := int64(1)
	scopeHash := "sha256:" + strings.Repeat("6", 64)
	accessMode := "SOURCE_ENFORCED"
	var headSequence int64
	var headHash string
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT last_sequence FROM public.audit_chain_head WHERE organization_id=$1),0),
		       COALESCE((SELECT last_event_hash FROM public.audit_chain_head WHERE organization_id=$1),
		                'sha256:' || repeat('0',64))
	`, organizationID).Scan(&headSequence, &headHash); err != nil {
		t.Fatal(err)
	}
	event, err := audit.Build(organizationID, audit.EventInput{
		EventID: auditID, WorkspaceID: auditWorkspaceID, ActorType: audit.ActorHuman,
		ActorPrincipalID: &actorID, Action: action, ResourceType: audit.ResourceWorkspaceSource,
		ResourceID: commandGateBindingID, RequestID: "req_" + auditID,
		Outcome: audit.Outcome(outcome), ErrorCode: errorCode,
		Metadata: audit.Metadata{
			WorkspaceRevision: &revision, WorkspaceSourceID: ptr(commandGateBindingID),
			SourceScopeID: ptr(commandGateScopeID), SourceScopeRevision: &scopeRevision,
			ScopeConfigHash: &scopeHash, AccessMode: &accessMode, Enabled: &enabled,
		}, OccurredAt: time.Now().UTC(),
	}, headSequence, headHash)
	if err != nil {
		t.Fatalf("build source audit: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.audit_event (
		id,schema_version,organization_id,sequence,workspace_id,actor_type,actor_principal_id,
		action,resource_type,resource_id,request_id,outcome,error_code,referenced_evidence_ids_json,
		metadata_json,canonical_bytes,previous_event_hash,event_hash,occurred_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'[]'::jsonb,$14,$15,$16,$17,$18)`,
		event.EventID, event.SchemaVersion, organizationID, event.Sequence, event.WorkspaceID,
		string(event.ActorType), actorID, string(event.Action), string(event.ResourceType), event.ResourceID,
		event.RequestID, string(event.Outcome), errorCode, metadataJSON, event.CanonicalBytes,
		event.PreviousEventHash, event.EventHash, event.OccurredAt); err != nil {
		t.Fatal(err)
	}
}
