package postgres_test

// B2.2b3a — the access-mode boundary of the typed source authority lookup
// (Store.ResolvePostgreSQLAuthorityRequest).
//
// The lookup reads one workspace source status row and turns it into a
// candidate identity. The row's access mode is server data, so the lookup must
// distinguish the legitimate modes it may see from a mode the database should
// never have returned, rather than folding every non-served mode into one
// deliberate unavailability:
//
//   - WORKSPACE_MANAGED is the mode this execution path serves, so the
//     untouched admitted row still resolves to the exact admitted request;
//   - SOURCE_ENFORCED is a legitimate workspace source this path cannot serve,
//     so it is deliberately unavailable: the zero candidate and the exact
//     content-free NOT_FOUND surface, identical to every other unavailable
//     lookup;
//   - UNKNOWN, empty, wrong-case and whitespace-padded access modes are
//     malformed server facts, so they must fail closed with the exact
//     content-free PERSISTENCE surface instead of borrowing that deliberate
//     unavailability.
//
// The production function is read through its own pooled read transaction, so
// an uncommitted or transaction-local replacement would be invisible to the
// Store. The proof therefore installs one committed, test-only fault fixture
// in the disposable integration database:
//
//  1. the exact live definition (pg_get_functiondef) and body (pg_proc.prosrc)
//     are saved under admin access;
//  2. one uniquely named ordinary table in schema app is created under
//     transaction-local organization/principal settings in two statements of a
//     single admin transaction: CREATE TABLE ... AS SELECT * FROM
//     app.workspace_source_status_v3(NULL::text) WITH NO DATA, because a
//     PostgreSQL utility statement cannot consume a bind parameter, and then
//     the separate parameterized DML statement INSERT INTO ... SELECT * FROM
//     app.workspace_source_status_v3($1). The copy is asserted to have inserted
//     exactly one row and to hold the six admitted candidate fields;
//  3. the saved definition is re-issued with exactly one substitution of the
//     saved body for a body selecting all columns of that table, so the
//     original signature, return columns, security-definer mode and search path
//     are carried over unchanged and CREATE OR REPLACE keeps ownership and ACL;
//  4. the table and the replacement are committed before the Store is called;
//  5. the restore is registered before the replacement exists, runs on a fresh
//     context, restores the exact saved definition and drops only the test-only
//     table; the definition is also restored explicitly after the cases and the
//     original positive lookup is re-run afterwards.
//
// The application role is never granted access to the test-only table: the
// replacement projects it under the function owner's authority, which the
// positive case and the direct denial control below both prove. One further
// direct-control fact asserts the retained function owner is the owner of the
// test-only table, so the security-definer projection cannot be reading it as
// anyone else.
//
// The fixture is newAdmittedAuthorityFixture from
// source_authority_admission_negative_test.go, and the exact connection identity
// is the direct-control fact the existing lookup test reads from
// public.source_scope.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// authorityLookupPersistenceSurface requires one failed lookup to be exactly
// the content-free persistence denial — the zero candidate, the exact
// PERSISTENCE code as the whole error text, no unwrap/cause chain and no leaked
// table, identifier, hash, SQL or credential fact — and returns its canonical
// observable surface. It is the persistence twin of
// authorityLookupDenialSurface, whose signature pins NOT_FOUND and therefore
// cannot express the malformed-access-mode distinction this card adds.
func authorityLookupPersistenceSurface(
	t *testing.T,
	label string,
	candidate workspacerepository.PostgreSQLAuthorityRequest,
	err error,
	identifiers ...string,
) string {
	t.Helper()
	if candidate != (workspacerepository.PostgreSQLAuthorityRequest{}) {
		t.Fatalf("%s: candidate = %#v, want the zero candidate", label, candidate)
	}
	if err == nil {
		t.Fatalf("%s: lookup unexpectedly resolved a candidate", label)
	}
	if got := workspacerepository.CodeOf(err); got != workspacerepository.CodePersistence {
		t.Fatalf("%s: failure code = %q, want %q", label, got, workspacerepository.CodePersistence)
	}
	if err.Error() != string(workspacerepository.CodePersistence) {
		t.Fatalf("%s: failure text = %q, want %q", label, err.Error(), workspacerepository.CodePersistence)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("%s: failure retained an unwrap/cause chain: %v", label, unwrapped)
	}
	var repositoryError *workspacerepository.Error
	if !errors.As(err, &repositoryError) {
		t.Fatalf("%s: failure is not a repository error: %#v", label, err)
	}
	// %#v renders the repository error's private code and cause, so a retained
	// cause would become visible here even though the error text stays
	// content-free; the surface therefore also proves no cause was kept.
	surface := fmt.Sprintf("candidate=%#v error_type=%T error_value=%#v error_text=%q",
		candidate, err, repositoryError, err.Error())
	forbidden := append([]string{
		authorityCredentialSentinel,
		authorityDSNSentinel,
		authoritySQLSentinel,
		"postgres://",
		"postgresql://",
		"password",
		"credential",
		"dsn",
		"select ",
		"insert ",
		"update ",
		"delete ",
		"permission",
	}, identifiers...)
	lower := strings.ToLower(surface)
	for _, marker := range forbidden {
		if marker != "" && strings.Contains(lower, strings.ToLower(marker)) {
			t.Fatalf("%s: denial surface leaked %q: %s", label, marker, surface)
		}
	}
	return surface
}

func TestPostgreSQLSourceAuthorityLookupDistinguishesUnsupportedAndMalformedAccessModes(t *testing.T) {
	ctx := context.Background()
	fixture := newAdmittedAuthorityFixture(t)

	// The exact connection identity is one direct-control fact, read from the
	// exact scope row rather than derived from the fixture or pinned as a
	// literal — the same pattern source_authority_lookup_test.go uses.
	var directConnectionID string
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id
		FROM public.source_scope
		WHERE organization_id = $1 AND id = $2`,
		regOrg, fixture.request.SourceScopeID).Scan(&directConnectionID); err != nil {
		t.Fatalf("direct control read of the source scope connection: %v", err)
	}
	if directConnectionID == "" {
		t.Fatal("direct control read returned an empty connection id")
	}

	lookup := workspacerepository.PostgreSQLAuthorityLookup{
		WorkspaceID:   fixture.request.WorkspaceID,
		SourceScopeID: fixture.request.SourceScopeID,
		ConnectionID:  directConnectionID,
	}

	// 1. Save the exact live definition and body under admin access: they are
	// both the restore source and the source of the derived replacement.
	var savedDefinition, savedBody string
	if err := fixture.admin.QueryRow(ctx, `
		SELECT pg_get_functiondef('app.workspace_source_status_v3(text)'::regprocedure),
		       projection.prosrc
		  FROM pg_proc AS projection
		 WHERE projection.oid = 'app.workspace_source_status_v3(text)'::regprocedure`).
		Scan(&savedDefinition, &savedBody); err != nil {
		t.Fatalf("save the app.workspace_source_status_v3 definition: %v", err)
	}
	if savedDefinition == "" || savedBody == "" {
		t.Fatal("the saved app.workspace_source_status_v3 definition or body is empty")
	}

	// 2. Copy the production projection itself into one test-only ordinary
	// table. The copy runs under transaction-local organization/principal
	// settings, so the production function authorizes it exactly as it
	// authorizes the lookup. PostgreSQL utility statements cannot consume bind
	// parameters, so the table is created from the projection with WITH NO DATA
	// in one statement and the admitted row is inserted by a separate
	// parameterized DML statement; the workspace id is never interpolated into
	// SQL. The name is a fixed lowercase prefix plus the current UTC nanosecond
	// count: a plain unquoted identifier that cannot collide with a reviewed
	// relation and carries no caller-controlled text.
	tableName := fmt.Sprintf("source_authority_lookup_fault_%d", time.Now().UTC().UnixNano())
	copyTransaction, err := fixture.admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin the copied-row transaction: %v", err)
	}
	defer func() { _ = copyTransaction.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, copyTransaction, regOrg, regOwner)
	if _, err := copyTransaction.Exec(ctx,
		`CREATE TABLE app.`+tableName+` AS SELECT * FROM app.workspace_source_status_v3(NULL::text) WITH NO DATA`); err != nil {
		t.Fatalf("create the test-only copy of the workspace source status projection: %v", err)
	}
	inserted, err := copyTransaction.Exec(ctx,
		`INSERT INTO app.`+tableName+` SELECT * FROM app.workspace_source_status_v3($1)`,
		fixture.request.WorkspaceID)
	if err != nil {
		t.Fatalf("copy the workspace source status row: %v", err)
	}
	if inserted.RowsAffected() != 1 {
		t.Fatalf("copying the workspace source status row inserted %d rows, want exactly 1",
			inserted.RowsAffected())
	}
	if err := copyTransaction.Commit(ctx); err != nil {
		t.Fatalf("commit the copied workspace source status row: %v", err)
	}

	// The copied row is the only fault surface. It must hold exactly the one
	// admitted row, and all six candidate fields must already be the admitted
	// facts before any case changes the mode.
	var copiedRows int
	if err := fixture.admin.QueryRow(ctx, `SELECT count(*) FROM app.`+tableName).Scan(&copiedRows); err != nil {
		t.Fatalf("count the copied workspace source status rows: %v", err)
	}
	if copiedRows != 1 {
		t.Fatalf("copied workspace source status rows = %d, want exactly 1", copiedRows)
	}
	var (
		copiedWorkspaceSourceID string
		copiedSourceScopeID     string
		copiedConnectionID      string
		copiedScopeRevision     int64
		copiedScopeConfigHash   string
		copiedAccessMode        string
	)
	if err := fixture.admin.QueryRow(ctx, `
		SELECT workspace_source_id, source_scope_id, connection_id,
		       source_scope_revision, scope_config_hash, access_mode
		  FROM app.`+tableName).Scan(
		&copiedWorkspaceSourceID, &copiedSourceScopeID, &copiedConnectionID,
		&copiedScopeRevision, &copiedScopeConfigHash, &copiedAccessMode); err != nil {
		t.Fatalf("control read of the copied workspace source status row: %v", err)
	}
	if copiedWorkspaceSourceID != fixture.request.WorkspaceSourceID ||
		copiedSourceScopeID != fixture.request.SourceScopeID ||
		copiedConnectionID != directConnectionID ||
		copiedScopeRevision != fixture.request.SourceScopeRevision ||
		copiedScopeConfigHash != fixture.request.ScopeConfigHash ||
		copiedAccessMode != fixture.request.AccessMode {
		t.Fatalf("copied candidate fields = %q/%q/%q/%d/%q/%q, want the admitted fixture %q/%q/%q/%d/%q/%q",
			copiedWorkspaceSourceID, copiedSourceScopeID, copiedConnectionID, copiedScopeRevision,
			copiedScopeConfigHash, copiedAccessMode,
			fixture.request.WorkspaceSourceID, fixture.request.SourceScopeID, directConnectionID,
			fixture.request.SourceScopeRevision, fixture.request.ScopeConfigHash, fixture.request.AccessMode)
	}

	// 3. Derive the replacement from the saved definition itself: exactly one
	// substitution of the exact saved body, so the original signature, return
	// columns, volatility, security-definer mode and search path are carried
	// over unchanged.
	if strings.Count(savedDefinition, savedBody) != 1 {
		t.Fatalf("the saved function body occurs %d times in the saved definition, want exactly 1",
			strings.Count(savedDefinition, savedBody))
	}
	replacementBody := "\n    SELECT * FROM app." + tableName + "\n"
	replacementDefinition := strings.Replace(savedDefinition, savedBody, replacementBody, 1)
	if replacementDefinition == savedDefinition || strings.Count(replacementDefinition, replacementBody) != 1 {
		t.Fatal("the derived replacement definition did not replace the saved body exactly once")
	}

	// 4. Register the restore before the replacement exists, so any later
	// failure still restores the production definition and drops only the
	// test-only table. Cleanup uses a fresh context because the test context
	// may already be cancelled by the time it runs.
	t.Cleanup(func() {
		restoreContext := context.Background()
		if _, err := fixture.admin.Exec(restoreContext, savedDefinition); err != nil {
			t.Errorf("cleanup: restore the app.workspace_source_status_v3 definition: %v", err)
		}
		if _, err := fixture.admin.Exec(restoreContext, `DROP TABLE IF EXISTS app.`+tableName); err != nil {
			t.Errorf("cleanup: drop the test-only table: %v", err)
		}
		var restoredDefinition, restoredBody string
		if err := fixture.admin.QueryRow(restoreContext, `
			SELECT pg_get_functiondef('app.workspace_source_status_v3(text)'::regprocedure),
			       projection.prosrc
			  FROM pg_proc AS projection
			 WHERE projection.oid = 'app.workspace_source_status_v3(text)'::regprocedure`).
			Scan(&restoredDefinition, &restoredBody); err != nil {
			t.Errorf("cleanup: read the restored app.workspace_source_status_v3 definition: %v", err)
			return
		}
		if restoredDefinition != savedDefinition || restoredBody != savedBody {
			t.Error("cleanup: the restored app.workspace_source_status_v3 definition differs from the saved definition")
		}
	})

	// 5. Install the replacement. The production read runs in its own pooled
	// read transaction, so only a committed definition is visible.
	if _, err := fixture.admin.Exec(ctx, replacementDefinition); err != nil {
		t.Fatalf("install the test-only app.workspace_source_status_v3 replacement: %v", err)
	}
	var deployedBody string
	if err := fixture.admin.QueryRow(ctx, `
		SELECT projection.prosrc
		  FROM pg_proc AS projection
		 WHERE projection.oid = 'app.workspace_source_status_v3(text)'::regprocedure`).
		Scan(&deployedBody); err != nil {
		t.Fatalf("control read of the installed replacement body: %v", err)
	}
	if deployedBody != replacementBody {
		t.Fatalf("installed replacement body = %q, want the derived body", deployedBody)
	}

	// Direct control: CREATE OR REPLACE retains the function owner, and the
	// security-definer replacement may read the test-only table only under that
	// owner's authority. The retained function owner must therefore be the
	// owner of the test-only table, which is what makes the positive case below
	// a proof of the projection's authority rather than of a widened grant.
	var functionOwner, testTableOwner string
	if err := fixture.admin.QueryRow(ctx, `
		SELECT (SELECT projection.proowner::regrole::text
		          FROM pg_proc AS projection
		         WHERE projection.oid = 'app.workspace_source_status_v3(text)'::regprocedure),
		       (SELECT relation.relowner::regrole::text
		          FROM pg_class AS relation
		         WHERE relation.oid = 'app.`+tableName+`'::regclass)`).
		Scan(&functionOwner, &testTableOwner); err != nil {
		t.Fatalf("direct control read of the retained function and test-only table owners: %v", err)
	}
	if functionOwner == "" || functionOwner != testTableOwner {
		t.Fatalf("retained function owner = %q, test-only table owner = %q, want the retained function owner to own the test-only table",
			functionOwner, testTableOwner)
	}

	// 6. The untouched WORKSPACE_MANAGED row still resolves to the exact
	// admitted request: the fault fixture changed only where the projection
	// reads, never what it says.
	positive, err := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access, lookup)
	if err != nil {
		t.Fatalf("positive lookup through the copied projection: %v", err)
	}
	if positive != fixture.request {
		t.Fatalf("positive lookup candidate = %#v, want the exact admitted request %#v", positive, fixture.request)
	}

	// The replacement projects the test-only table under the function owner's
	// authority. This control read proves the application role itself still has
	// no access to that table, so the positive case above cannot have come from
	// a widened grant. The check requires the exact insufficient-privilege
	// SQLSTATE: a connection that never reached the table would not pass.
	applicationPool := openApplicationPool(t, ctx, testDatabaseURL(t))
	var applicationRows int
	applicationErr := applicationPool.QueryRow(ctx, `SELECT count(*) FROM app.`+tableName).Scan(&applicationRows)
	var applicationDatabaseError *pgconn.PgError
	if !errors.As(applicationErr, &applicationDatabaseError) || applicationDatabaseError.Code != "42501" {
		t.Fatalf("the application role read of the test-only table did not fail with insufficient privilege: %v", applicationErr)
	}

	// One parameterized admin UPDATE on the copied row is the only fault input,
	// and the row is put back before the next case starts so every case begins
	// from the admitted WORKSPACE_MANAGED fact.
	setCopiedAccessMode := func(t *testing.T, accessMode string) {
		t.Helper()
		if _, err := fixture.admin.Exec(ctx,
			`UPDATE app.`+tableName+` SET access_mode = $1`, accessMode); err != nil {
			t.Fatalf("set the copied access mode to %q: %v", accessMode, err)
		}
		var stored string
		if err := fixture.admin.QueryRow(ctx,
			`SELECT access_mode FROM app.`+tableName).Scan(&stored); err != nil {
			t.Fatalf("control read of the copied access mode: %v", err)
		}
		if stored != accessMode {
			t.Fatalf("copied access mode = %q, want %q", stored, accessMode)
		}
	}
	probeAccessMode := func(accessMode string) (workspacerepository.PostgreSQLAuthorityRequest, error) {
		setCopiedAccessMode(t, accessMode)
		candidate, err := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access, lookup)
		setCopiedAccessMode(t, fixture.request.AccessMode)
		return candidate, err
	}
	leakIdentifiers := []string{
		tableName,
		"workspace_source_status_v3",
		directConnectionID,
		fixture.request.WorkspaceID,
		fixture.request.WorkspaceSourceID,
		fixture.request.SourceScopeID,
		fixture.request.ScopeConfigHash,
	}

	// 7. SOURCE_ENFORCED is legitimate but unservable here, so it collapses to
	// the zero candidate and the exact content-free NOT_FOUND surface every
	// other unavailable lookup returns.
	sourceEnforcedCandidate, sourceEnforcedErr := probeAccessMode("SOURCE_ENFORCED")
	authorityLookupDenialSurface(t, "SOURCE_ENFORCED access mode",
		sourceEnforcedCandidate, sourceEnforcedErr, leakIdentifiers...)

	// 8. Every other access-mode string is a malformed server fact. Each one
	// must fail closed with the exact content-free PERSISTENCE surface — never
	// the deliberate NOT_FOUND above — and leak no table, identifier, hash, SQL
	// or credential fact.
	for _, malformed := range []string{"UNKNOWN", "", "workspace_managed", "WORKSPACE_MANAGED "} {
		candidate, err := probeAccessMode(malformed)
		// The malformed fact itself is one more server value the content-free
		// failure must not echo.
		identifiers := append([]string{malformed}, leakIdentifiers...)
		authorityLookupPersistenceSurface(t, fmt.Sprintf("malformed access mode %q", malformed),
			candidate, err, identifiers...)
	}

	// 9. Restore the production definition explicitly after the cases, prove the
	// restore is byte-for-byte the saved definition, and re-run the original
	// positive lookup through the real projection.
	if _, err := fixture.admin.Exec(ctx, savedDefinition); err != nil {
		t.Fatalf("restore the app.workspace_source_status_v3 definition: %v", err)
	}
	var restoredDefinition, restoredBody string
	if err := fixture.admin.QueryRow(ctx, `
		SELECT pg_get_functiondef('app.workspace_source_status_v3(text)'::regprocedure),
		       projection.prosrc
		  FROM pg_proc AS projection
		 WHERE projection.oid = 'app.workspace_source_status_v3(text)'::regprocedure`).
		Scan(&restoredDefinition, &restoredBody); err != nil {
		t.Fatalf("read the restored app.workspace_source_status_v3 definition: %v", err)
	}
	if restoredDefinition != savedDefinition || restoredBody != savedBody {
		t.Fatal("the restored app.workspace_source_status_v3 definition differs from the saved definition")
	}
	restoredCandidate, err := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access, lookup)
	if err != nil {
		t.Fatalf("positive lookup after the explicit restore: %v", err)
	}
	if restoredCandidate != fixture.request {
		t.Fatalf("post-restore candidate = %#v, want the exact admitted request %#v", restoredCandidate, fixture.request)
	}
}
