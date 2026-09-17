package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/workspace"
)

const testWorkspaceBindingID = "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV"

func TestWorkspaceSourceSnapshotUsesCanonicalEmptyArrayForEmptyProjection(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	var sourceBindingsType string
	var rows int
	if err := admin.QueryRow(ctx, `SELECT jsonb_typeof(
		convert_from(canonical_bytes,'UTF8')::jsonb -> 'source_bindings')
		FROM public.workspace_revision_snapshot
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND revision=1`).Scan(&sourceBindingsType); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_source
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND workspace_revision=1`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if sourceBindingsType != "array" || rows != 0 {
		t.Fatalf("canonical empty projection type/rows=%s/%d, want array/0", sourceBindingsType, rows)
	}
}

func TestWorkspaceSourceSnapshotIsTenantIsolatedReadOnlyAndInert(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	insertSourceScopeDraftChain(t, ctx, admin, "org_beta", "usr_bob", "beta", "workspace_managed")
	insertWorkspaceSourceSnapshot(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha", "")
	insertWorkspaceSourceSnapshot(t, ctx, admin, "org_beta", "usr_bob", "ws_beta", "workspace_managed")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_eve', 'org_alpha', 'USER', 'Eve', 'ACTIVE')
	`); err != nil {
		t.Fatal(err)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	for _, tableName := range []string{"workspace_source", "workspace_revision_source"} {
		var unscoped int
		if err := app.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&unscoped); err != nil {
			t.Fatal(err)
		}
		if unscoped != 0 {
			t.Fatalf("unscoped %s returned %d rows", tableName, unscoped)
		}
		tx, err := app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal(err)
		}
		setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
		var scoped int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&scoped); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if scoped != 1 {
			t.Fatalf("scoped %s returned %d rows, want 1", tableName, scoped)
		}
		for privilege, want := range map[string]bool{
			"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		} {
			var got bool
			if err := admin.QueryRow(ctx,
				"SELECT has_table_privilege('knowvault_app', $1, $2)",
				"public."+tableName, privilege).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("knowvault_app %s on %s = %v, want %v", privilege, tableName, got, want)
			}
		}
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity
			FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tableName).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s does not FORCE RLS", tableName)
		}
	}
	outsider, err := app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outsider.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, outsider, "org_alpha", "usr_eve")
	for _, tableName := range []string{"workspace_source", "workspace_revision_source"} {
		var count int
		if err := outsider.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("same-tenant workspace outsider saw %d %s rows", count, tableName)
		}
	}
	if err := outsider.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var canExecute bool
	if err := admin.QueryRow(ctx,
		"SELECT has_function_privilege('knowvault_app', 'app.workspace_source_snapshot_exact_guard()', 'EXECUTE')").Scan(&canExecute); err != nil {
		t.Fatal(err)
	}
	if canExecute {
		t.Fatal("runtime role unexpectedly executes workspace source snapshot validator")
	}

	var scopeStatus, activationStatus string
	var connectionActive, scopeActive any
	if err := admin.QueryRow(ctx, `
		SELECT c.active_revision, s.active_revision, s.status, a.status
		FROM public.workspace_revision_source AS wrs
		JOIN public.source_scope AS s
		  ON s.organization_id = wrs.organization_id AND s.id = wrs.source_scope_id
		JOIN public.source_scope_activation AS a
		  ON a.organization_id = wrs.organization_id
		 AND a.source_scope_id = wrs.source_scope_id
		 AND a.source_scope_revision = wrs.source_scope_revision
		JOIN public.source_connection AS c
		  ON c.organization_id = s.organization_id AND c.id = s.connection_id
		WHERE wrs.organization_id = 'org_alpha'
	`).Scan(&connectionActive, &scopeActive, &scopeStatus, &activationStatus); err != nil {
		t.Fatal(err)
	}
	if connectionActive != nil || scopeActive != nil || scopeStatus != "DRAFT" || activationStatus != "DRAFT" {
		t.Fatalf("binding accidentally created authority: connection=%v scope=%v statuses=%s/%s",
			connectionActive, scopeActive, scopeStatus, activationStatus)
	}
}

func TestWorkspaceSourceSnapshotRejectsTupleAndCanonicalSetForgery(t *testing.T) {
	for _, fault := range []string{
		"missing_row", "extra_row", "enabled_mismatch", "wrong_hash",
		"wrong_revision", "wrong_access_mode", "binding_tuple_swap",
	} {
		fault := fault
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			insertErr := insertWorkspaceSourceSnapshotInTx(ctx, tx, "org_alpha", "usr_alice", "ws_alpha", fault)
			switch fault {
			case "missing_row", "extra_row", "enabled_mismatch":
				if insertErr != nil {
					t.Fatalf("%s failed before deferred set validator: %v", fault, insertErr)
				}
				assertWorkspaceSourcePGError(t, tx.Commit(ctx), "23514", "", "workspace source rows do not exactly equal canonical source bindings")
			case "wrong_hash", "wrong_revision", "wrong_access_mode":
				assertWorkspaceSourcePGError(t, insertErr, "23503", "workspace_revision_source_exact_scope_revision_fk", "")
			case "binding_tuple_swap":
				assertWorkspaceSourcePGError(t, insertErr, "23503", "workspace_revision_source_exact_binding_fk", "")
			}
		})
	}
}

func TestWorkspaceSourceRowsAreImmutableAndDeleteChildFirst(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	insertWorkspaceSourceSnapshot(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha", "")

	if _, err := admin.Exec(ctx, `UPDATE public.workspace_revision_source SET enabled = false WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("workspace revision source mutation unexpectedly succeeded")
	}
	if _, err := admin.Exec(ctx, `UPDATE public.workspace_source SET added_at = added_at + interval '1 second' WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("workspace source mutation unexpectedly succeeded")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.workspace_revision_source WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("binding snapshot deleted for active tenant")
	}
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET status = 'DELETING' WHERE id = 'org_alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.workspace_source WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("binding lineage deleted before revision snapshot")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM public.workspace_revision_source WHERE organization_id = 'org_alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.workspace_source WHERE organization_id = 'org_alpha'`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("child-first hard delete: %v", err)
	}
}

func insertWorkspaceSourceSnapshot(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, workspaceID, fault string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertWorkspaceSourceSnapshotInTx(ctx, tx, organizationID, ownerID, workspaceID, fault); err != nil {
		t.Fatalf("insert workspace source snapshot: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit workspace source snapshot: %v", err)
	}
}

func insertWorkspaceSourceSnapshotInTx(ctx context.Context, tx pgx.Tx, organizationID, ownerID, workspaceID, fault string) error {
	scopeID := "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	scopeRevision := int64(1)
	scopeHash := "sha256:" + strings.Repeat("6", 64)
	accessMode := "SOURCE_ENFORCED"
	rowEnabled := true
	rowBindingID := testWorkspaceBindingID
	canonicalBindings := []workspace.SourceBinding{{
		SourceScopeID: scopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeHash, Enabled: true,
	}}
	insertRow := true
	bindingScopeID := scopeID
	switch fault {
	case "workspace_managed":
		accessMode = "WORKSPACE_MANAGED"
	case "missing_row":
		insertRow = false
	case "extra_row":
		canonicalBindings = []workspace.SourceBinding{}
	case "enabled_mismatch":
		rowEnabled = false
	case "wrong_hash":
		scopeHash = "sha256:" + strings.Repeat("7", 64)
	case "wrong_revision":
		scopeRevision = 2
	case "wrong_access_mode":
		accessMode = "WORKSPACE_MANAGED"
	case "binding_tuple_swap":
		rowBindingID = "binding_01BX5ZZKBKACTAV9WEVGEMMVRZ"
	}

	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 2,
		Name: workspaceID, Status: workspace.StatusActive, OwnerPrincipalID: ownerID,
		Members:        []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}},
		SourceBindings: canonicalBindings,
	})
	if err != nil {
		return err
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		return err
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_source (
			organization_id, id, workspace_id, source_scope_id, added_by
		) VALUES ($1, $2, $3, $4, $5)
	`, organizationID, testWorkspaceBindingID, workspaceID, bindingScopeID, ownerID); err != nil {
		return err
	}
	if fault == "binding_tuple_swap" {
		otherWorkspaceID := "ws_other"
		otherHash := "sha256:" + strings.Repeat("8", 64)
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id)
			VALUES ($1, $2, $1, 'ACTIVE', $3)
		`, otherWorkspaceID, organizationID, ownerID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_revision (
				organization_id, workspace_id, revision, configuration_hash, created_by
			) VALUES ($1, $2, 1, $3, $4)
		`, organizationID, otherWorkspaceID, otherHash, ownerID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_member (
				id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by
			) VALUES ('wsm_other', $1, $2, $3, 'OWNER', 1, $3)
		`, organizationID, otherWorkspaceID, ownerID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_source (
				organization_id, id, workspace_id, source_scope_id, added_by
			) VALUES ($1, $2, $3, $4, $5)
		`, organizationID, rowBindingID, otherWorkspaceID, scopeID, ownerID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision (
			organization_id, workspace_id, revision, configuration_hash, created_by
		) VALUES ($1, $2, 2, $3, $4)
	`, organizationID, workspaceID, configurationHash, ownerID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision_snapshot (
			organization_id, workspace_id, revision, configuration_hash, canonical_bytes
		) VALUES ($1, $2, 2, $3, $4)
	`, organizationID, workspaceID, configurationHash, canonicalBytes); err != nil {
		return err
	}
	if insertRow {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_revision_source (
				organization_id, workspace_id, workspace_revision,
				workspace_configuration_hash, workspace_source_id,
				source_scope_id, source_scope_revision, scope_config_hash,
				access_mode, enabled
			) VALUES ($1, $2, 2, $3, $4, $5, $6, $7, $8, $9)
		`, organizationID, workspaceID, configurationHash, rowBindingID,
			scopeID, scopeRevision, scopeHash, accessMode, rowEnabled); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `
		UPDATE public.workspace
		SET current_revision = 2, updated_at = transaction_timestamp()
		WHERE organization_id = $1 AND id = $2
	`, organizationID, workspaceID)
	return err
}

func assertWorkspaceSourcePGError(t *testing.T, err error, code, constraint, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PostgreSQL error %s/%s", code, constraint)
	}
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) {
		t.Fatalf("expected PostgreSQL error, got %T: %v", err, err)
	}
	if pgError.Code != code || (constraint != "" && pgError.ConstraintName != constraint) ||
		(message != "" && pgError.Message != message) {
		t.Fatalf("unexpected PostgreSQL error code=%s constraint=%s message=%q",
			pgError.Code, pgError.ConstraintName, pgError.Message)
	}
}
