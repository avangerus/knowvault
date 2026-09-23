package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedMetricDefinitionVersion inserts one metric_definition + version with an
// explicit status and returns nothing. All binding columns are left absent so
// the legacy shape is exercised. Data is content-free and local.
func seedMetricDefinitionVersion(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, workspaceID, ownerID, definitionID string, version int64, status string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
INSERT INTO public.metric_definition (
organization_id, workspace_id, id, owner_principal_id, current_version, created_by
) VALUES ($1, $2, $3, $4, $5, $4)
ON CONFLICT (organization_id, workspace_id, id) DO UPDATE
SET current_version = GREATEST(public.metric_definition.current_version, EXCLUDED.current_version)`,
		organizationID, workspaceID, definitionID, ownerID, version); err != nil {
		t.Fatalf("seed metric_definition: %v", err)
	}
	approvedBy, approvedAt := "NULL", "NULL"
	if status == "APPROVED" {
		approvedBy = fmt.Sprintf("'%s'", ownerID)
		approvedAt = "transaction_timestamp()"
	}
	statement := fmt.Sprintf(`
INSERT INTO public.metric_definition_version (
organization_id, workspace_id, definition_id, version, status,
name, source_connection_id, projection_version, entity_key, grain,
owner_principal_id, created_by, approved_by, approved_at
) VALUES ($1, $2, $3, $4, '%s', 'm', 'conn_m', 1, 'k', 'MONTH', $5, $5, %s, %s)`,
		status, approvedBy, approvedAt)
	if _, err := tx.Exec(ctx, statement, organizationID, workspaceID, definitionID, version, ownerID); err != nil {
		t.Fatalf("seed metric_definition_version: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func bindingColumn(t *testing.T, ctx context.Context, admin *pgxpool.Pool, column string) (string, string) {
	t.Helper()
	var dataType, isNullable string
	if err := admin.QueryRow(ctx, `
SELECT data_type, is_nullable
  FROM information_schema.columns
 WHERE table_schema = 'public'
   AND table_name = 'metric_definition_version'
   AND column_name = $1`, column).Scan(&dataType, &isNullable); err != nil {
		t.Fatalf("read information_schema for %s: %v", column, err)
	}
	return dataType, isNullable
}

func bindingHash(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

// TestMetricDefinitionBindingMigration is the focused real-PostgreSQL proof of
// the additive dataset binding schema. resetStage1Database replays the canonical
// history through 000109, and the test then asserts the five nullable columns,
// the all-or-nothing CHECK, the opaque id / sha256 / execution_mode fences, and
// that the existing guard + RLS already protect the new fields without any new
// authority.
func TestMetricDefinitionBindingMigration(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)

	seedOrganization(t, ctx, admin, "org_bind_alpha", "usr_bind_alice", "ws_bind_alpha")
	seedOrganization(t, ctx, admin, "org_bind_beta", "usr_bind_bob", "ws_bind_beta")

	// (1) All five columns exist, are nullable, and carry the intended types.
	for column, expectedType := range map[string]string{
		"dataset_id":      "text",
		"profile_version": "bigint",
		"profile_hash":    "text",
		"measure_id":      "text",
		"execution_mode":  "text",
	} {
		dataType, isNullable := bindingColumn(t, ctx, admin, column)
		if dataType != expectedType {
			t.Fatalf("column %s type=%q want %q", column, dataType, expectedType)
		}
		if isNullable != "YES" {
			t.Fatalf("column %s nullable=%q want YES", column, isNullable)
		}
	}

	// (2) A legacy row is accepted with all five binding fields NULL.
	seedMetricDefinitionVersion(t, ctx, admin, "org_bind_alpha", "ws_bind_alpha", "usr_bind_alice", "metric_legacy", 1, "DRAFT")
	var legacyNulls int
	if err := admin.QueryRow(ctx, `
SELECT (dataset_id IS NULL)::int + (profile_version IS NULL)::int + (profile_hash IS NULL)::int +
       (measure_id IS NULL)::int + (execution_mode IS NULL)::int
  FROM public.metric_definition_version
 WHERE organization_id = 'org_bind_alpha' AND workspace_id = 'ws_bind_alpha'
   AND definition_id = 'metric_legacy' AND version = 1`).Scan(&legacyNulls); err != nil {
		t.Fatalf("read legacy row: %v", err)
	}
	if legacyNulls != 5 {
		t.Fatalf("legacy row binding NULL count=%d want 5", legacyNulls)
	}

	// (3) A complete valid DRAFT binding round-trips, at the 256-char boundary.
	boundary := strings.Repeat("d", 256)
	measureBoundary := strings.Repeat("m", 256)
	seedMetricDefinitionVersion(t, ctx, admin, "org_bind_alpha", "ws_bind_alpha", "usr_bind_alice", "metric_bound", 2, "DRAFT")
	if _, err := admin.Exec(ctx, `
UPDATE public.metric_definition_version
   SET dataset_id = $1, profile_version = $2, profile_hash = $3, measure_id = $4, execution_mode = 'LIVE'
 WHERE organization_id = 'org_bind_alpha' AND workspace_id = 'ws_bind_alpha'
   AND definition_id = 'metric_bound' AND version = 2`,
		boundary, int64(9007199254740991), bindingHash("a"), measureBoundary); err != nil {
		t.Fatalf("valid complete binding rejected: %v", err)
	}
	var readDataset, readHash, readMeasure, readMode string
	var readVersion int64
	if err := admin.QueryRow(ctx, `
SELECT dataset_id, profile_version, profile_hash, measure_id, execution_mode
  FROM public.metric_definition_version
 WHERE organization_id = 'org_bind_alpha' AND workspace_id = 'ws_bind_alpha'
   AND definition_id = 'metric_bound' AND version = 2`).
		Scan(&readDataset, &readVersion, &readHash, &readMeasure, &readMode); err != nil {
		t.Fatalf("read bound row: %v", err)
	}
	if readDataset != boundary || readVersion != 9007199254740991 || readHash != bindingHash("a") || readMeasure != measureBoundary || readMode != "LIVE" {
		t.Fatalf("bound row round-trip mismatch: dataset=%d version=%d hash=%q measure=%d mode=%q",
			len(readDataset), readVersion, readHash, len(readMeasure), readMode)
	}

	// (4) Rejections. Each runs in its own transaction so a failed statement
	// cannot poison later cases.
	// reject seeds a fresh version, runs one complete all-present binding update
	// in its own transaction, and requires the exact CHECK violation: the binding
	// shape constraint with SQLSTATE 23514. A generic or differently-shaped error
	// (constraint name, SQLSTATE) is never accepted.
	reject := func(name string, seedVersion int64, statement string, args []any) {
		t.Helper()
		seedMetricDefinitionVersion(t, ctx, admin, "org_bind_alpha", "ws_bind_alpha", "usr_bind_alice",
			"metric_reject", seedVersion, "DRAFT")
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, statement, args...)
		if err == nil {
			t.Fatalf("invalid binding %q was accepted", name)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			t.Fatalf("invalid binding %q error type %T want *pgconn.PgError: %v", name, err, err)
		}
		if pgErr.Code != "23514" {
			t.Fatalf("invalid binding %q SQLSTATE %q want 23514", name, pgErr.Code)
		}
		if pgErr.ConstraintName != "metric_definition_version_dataset_binding_shape" {
			t.Fatalf("invalid binding %q constraint %q want metric_definition_version_dataset_binding_shape",
				name, pgErr.ConstraintName)
		}
	}

	// complete builds a full all-present binding update with fixed column names and
	// bound args, varying only the two label columns. Every invalid case starts from
	// a fully populated binding so PostgreSQL CHECK NULL semantics cannot mask it.
	complete := `UPDATE public.metric_definition_version
	   SET dataset_id = $1, profile_version = $2, profile_hash = $3, measure_id = $4, execution_mode = 'LIVE'
	 WHERE organization_id = 'org_bind_alpha' AND workspace_id = 'ws_bind_alpha'
	   AND definition_id = 'metric_reject'`

	idValid := strings.Repeat("a", 8)
	measureValid := strings.Repeat("m", 8)
	binding := func(datasetID, measureID string) (string, []any) {
		return complete, []any{datasetID, int64(1), bindingHash("b"), measureID}
	}
	rejectID := func(name string, seedVersion int64, datasetID, measureID string) {
		statement, args := binding(datasetID, measureID)
		reject(name, seedVersion, statement, args)
	}

	// (4a) Partial non-null is its own shape case: a single populated column is a
	// mixed all-or-nothing violation, not a label-validation case.
	reject("partial-non-null", 10, `UPDATE public.metric_definition_version SET dataset_id = 'ds_partial'
	 WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_reject'`, nil)

	// (4b) version / hash / mode fences, always from a complete binding.
	reject("profile-version-zero", 11, `UPDATE public.metric_definition_version
	   SET dataset_id=$1, profile_version=0, profile_hash=$2, measure_id=$3, execution_mode='LIVE'
	 WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_reject'`,
		[]any{idValid, bindingHash("b"), measureValid})
	reject("profile-version-negative", 12, `UPDATE public.metric_definition_version
	   SET dataset_id=$1, profile_version=-1, profile_hash=$2, measure_id=$3, execution_mode='LIVE'
	 WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_reject'`,
		[]any{idValid, bindingHash("b"), measureValid})
	reject("profile-version-above-max", 13, `UPDATE public.metric_definition_version
	   SET dataset_id=$1, profile_version=9007199254740992, profile_hash=$2, measure_id=$3, execution_mode='LIVE'
	 WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_reject'`,
		[]any{idValid, bindingHash("b"), measureValid})
	reject("hash-missing", 21, complete, []any{idValid, int64(1), nil, measureValid})
	reject("hash-wrong-prefix", 22, complete, []any{idValid, int64(1), "sha512:" + strings.Repeat("b", 64), measureValid})
	reject("hash-uppercase", 23, complete, []any{idValid, int64(1), "sha256:" + strings.Repeat("B", 64), measureValid})
	reject("hash-short", 24, complete, []any{idValid, int64(1), "sha256:" + strings.Repeat("b", 63), measureValid})
	reject("hash-long", 25, complete, []any{idValid, int64(1), "sha256:" + strings.Repeat("b", 65), measureValid})
	reject("hash-noncanonical", 26, complete, []any{idValid, int64(1), "sha256-" + strings.Repeat("b", 64), measureValid})
	reject("execution-mode-null", 27, `UPDATE public.metric_definition_version
	   SET dataset_id=$1, profile_version=1, profile_hash=$2, measure_id=$3, execution_mode=NULL
	 WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_reject'`,
		[]any{idValid, bindingHash("b"), measureValid})
	reject("execution-mode-lowercase", 28, `UPDATE public.metric_definition_version
	   SET dataset_id=$1, profile_version=1, profile_hash=$2, measure_id=$3, execution_mode='live'
	 WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_reject'`,
		[]any{idValid, bindingHash("b"), measureValid})
	reject("execution-mode-replay", 29, `UPDATE public.metric_definition_version
	   SET dataset_id=$1, profile_version=1, profile_hash=$2, measure_id=$3, execution_mode='REPLAY'
	 WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_reject'`,
		[]any{idValid, bindingHash("b"), measureValid})

	// (4c) ASCII label boundaries, complete bindings: empty, 257 octets, trimmed.
	rejectID("dataset-empty", 14, "", measureValid)
	rejectID("dataset-too-long", 15, strings.Repeat("d", 257), measureValid)
	rejectID("dataset-trimmed", 16, " ds_trim ", measureValid)
	rejectID("measure-empty", 18, idValid, "")
	rejectID("measure-too-long", 118, idValid, strings.Repeat("m", 257))
	rejectID("measure-trimmed", 19, idValid, " m_trim ")

	// (4d) Multibyte length: 129 x U+00E9 is 258 octets but only 129 runes, so the
	// octet fence (258 > 256).
	multibyte := strings.Repeat("\u00e9", 129)
	rejectID("dataset-multibyte-over-256-bytes", 115, multibyte, measureValid)
	rejectID("measure-multibyte-over-256-bytes", 215, idValid, multibyte)

	// (4e) Body controls for both IDs: one C0 and one C1 code point inside the value.
	rejectID("dataset-c0-control", 17, "ds\u0001ctrl", measureValid)
	rejectID("dataset-c1-control", 117, "ds\u0085ctrl", measureValid)
	rejectID("measure-c0-control", 217, idValid, "m\u0001ctrl")
	rejectID("measure-c1-control", 20, idValid, "m\u0085ctrl")

	// (4f) Go TrimSpace edge set at both ends, for both IDs: every code point that
	// strings.TrimSpace strips must be rejected as leading and as trailing content.
	trimEdges := []struct {
		name string
		code rune
	}{
		{"u0085", '\u0085'},
		{"u00a0", '\u00a0'},
		{"u1680", '\u1680'},
		{"u2000", '\u2000'},
		{"u2001", '\u2001'},
		{"u2002", '\u2002'},
		{"u2003", '\u2003'},
		{"u2004", '\u2004'},
		{"u2005", '\u2005'},
		{"u2006", '\u2006'},
		{"u2007", '\u2007'},
		{"u2008", '\u2008'},
		{"u2009", '\u2009'},
		{"u200a", '\u200a'},
		{"u2028", '\u2028'},
		{"u2029", '\u2029'},
		{"u202f", '\u202f'},
		{"u205f", '\u205f'},
		{"u3000", '\u3000'},
	}
	seedVersion := int64(1000)
	for _, edge := range trimEdges {
		for _, side := range []string{"leading", "trailing"} {
			value := string(edge.code) + "id_body"
			if side == "trailing" {
				value = "id_body" + string(edge.code)
			}
			seedVersion++
			rejectID("dataset-trim-"+edge.name+"-"+side, seedVersion, value, measureValid)
			seedVersion++
			rejectID("measure-trim-"+edge.name+"-"+side, seedVersion, idValid, value)
		}
	}

	// (5) DRAFT normal edit: all-NULL legacy row updated to one complete binding.
	seedMetricDefinitionVersion(t, ctx, admin, "org_bind_alpha", "ws_bind_alpha", "usr_bind_alice", "metric_draft_edit", 30, "DRAFT")
	if _, err := admin.Exec(ctx, `
UPDATE public.metric_definition_version
   SET dataset_id = 'ds_draft', profile_version = 4, profile_hash = $1, measure_id = 'measure_draft', execution_mode = 'LIVE'
 WHERE organization_id = 'org_bind_alpha' AND workspace_id = 'ws_bind_alpha'
   AND definition_id = 'metric_draft_edit' AND version = 30`, bindingHash("c")); err != nil {
		t.Fatalf("draft all-NULL to complete binding edit rejected: %v", err)
	}

	// (6) APPROVED and RETIRED rows cannot be updated or deleted, including the
	// new binding fields, and the existing trigger keeps the guard.
	for _, status := range []string{"APPROVED", "RETIRED"} {
		seedMetricDefinitionVersion(t, ctx, admin, "org_bind_alpha", "ws_bind_alpha", "usr_bind_alice", "metric_frozen_"+status, 31, status)
		for name, statement := range map[string]string{
			"dataset_id": `UPDATE public.metric_definition_version SET dataset_id = 'ds_mutate'
WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_frozen_` + status + `'`,
			"profile_hash": `UPDATE public.metric_definition_version SET dataset_id='ds_ok', profile_version=1, profile_hash='` + bindingHash("d") + `', measure_id='m_ok', execution_mode='LIVE'
WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_frozen_` + status + `'`,
			"delete": `DELETE FROM public.metric_definition_version
WHERE organization_id='org_bind_alpha' AND workspace_id='ws_bind_alpha' AND definition_id='metric_frozen_` + status + `'`,
		} {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, statement); err == nil {
				_ = tx.Rollback(ctx)
				t.Fatalf("%s %s mutation was accepted", status, name)
			}
			_ = tx.Rollback(ctx)
		}
	}

	// (7) RLS is forced and cross-tenant context cannot read or mutate another
	// tenant's binding row.
	var forced bool
	if err := admin.QueryRow(ctx, `
SELECT relforcerowsecurity FROM pg_class WHERE oid = 'public.metric_definition_version'::regclass`).Scan(&forced); err != nil {
		t.Fatalf("read relforcerowsecurity: %v", err)
	}
	if !forced {
		t.Fatal("metric_definition_version RLS is not forced")
	}

	seedMetricDefinitionVersion(t, ctx, admin, "org_bind_beta", "ws_bind_beta", "usr_bind_bob", "metric_beta", 32, "DRAFT")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	// The application role is subject to forced RLS, so the beta binding must be
	// written inside a transaction whose app.organization_id/principal_id context
	// matches the row; a bare pool Exec has no tenant context and would be denied.
	betaSeedTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, betaSeedTx, "org_bind_beta", "usr_bind_bob")
	if _, err := betaSeedTx.Exec(ctx, `
UPDATE public.metric_definition_version
   SET dataset_id = 'ds_beta', profile_version = 1, profile_hash = $1, measure_id = 'm_beta', execution_mode = 'LIVE'
 WHERE organization_id = 'org_bind_beta' AND workspace_id = 'ws_bind_beta'
   AND definition_id = 'metric_beta' AND version = 32`, bindingHash("e")); err != nil {
		t.Fatalf("precondition: beta binding write: %v", err)
	}
	if err := betaSeedTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	betaTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = betaTx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, betaTx, "org_bind_beta", "usr_bind_bob")
	var betaCount int
	if err := betaTx.QueryRow(ctx, `
SELECT count(*) FROM public.metric_definition_version
 WHERE organization_id = 'org_bind_beta' AND definition_id = 'metric_beta'`).Scan(&betaCount); err != nil {
		t.Fatalf("beta self read: %v", err)
	}
	if betaCount != 1 {
		t.Fatalf("beta self read count=%d want 1", betaCount)
	}
	if err := betaTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	cross, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cross.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, cross, "org_bind_alpha", "usr_bind_alice")
	var crossCount int
	if err := cross.QueryRow(ctx, `
SELECT count(*) FROM public.metric_definition_version
 WHERE organization_id = 'org_bind_beta' AND definition_id = 'metric_beta'`).Scan(&crossCount); err != nil {
		t.Fatalf("cross-tenant read: %v", err)
	}
	if crossCount != 0 {
		t.Fatalf("cross-tenant read saw %d beta rows", crossCount)
	}
	// Under alpha context the RLS USING clause hides the beta row, so this UPDATE
	// legitimately touches zero rows with no SQL error. Assert zero rows affected
	// rather than demanding an error.
	crossTag, err := cross.Exec(ctx, `
UPDATE public.metric_definition_version SET dataset_id = 'ds_cross'
 WHERE organization_id = 'org_bind_beta' AND definition_id = 'metric_beta'`)
	if err != nil {
		t.Fatalf("cross-tenant binding update errored: %v", err)
	}
	if got := crossTag.RowsAffected(); got != 0 {
		t.Fatalf("cross-tenant binding update affected %d rows want 0", got)
	}
	_ = cross.Rollback(ctx)

	// The beta binding survived the cross-tenant attempt untouched.
	var postDataset string
	if err := admin.QueryRow(ctx, `
SELECT dataset_id FROM public.metric_definition_version
 WHERE organization_id='org_bind_beta' AND workspace_id='ws_bind_beta'
   AND definition_id='metric_beta' AND version=32`).Scan(&postDataset); err != nil {
		t.Fatalf("post cross-tenant read: %v", err)
	}
	if postDataset != "ds_beta" {
		t.Fatalf("beta binding mutated to %q want ds_beta", postDataset)
	}
}
