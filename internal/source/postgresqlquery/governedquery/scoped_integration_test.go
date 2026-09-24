package governedquery

// scoped_integration_test.go is ADR-0097's real-PostgreSQL proof for the
// agent-authored SQL path. It runs against the card's pinned container
// (KNOWVAULT_TEST_POSTGRES_URL, database knowvault_test) and creates its own
// schema, tables, view, foreign schema and least-privilege query role; it
// touches no product schema.
//
// Two layers are proven:
//
//   - the plan walk against real EXPLAIN (VERBOSE, FORMAT JSON) output, so the
//     synthetic plans in scoped_test.go are anchored to the actual planner
//     shape (CTE, JOIN, subquery and view expansion inside the source;
//     pg_catalog, information_schema, a foreign schema and a function scan
//     outside it); and
//   - ExecuteScoped end to end, when the read-only role's TLS DSN and the CA
//     PEM are supplied (KNOWVAULT_TEST_POSTGRES_QUERY_URL,
//     KNOWVAULT_TEST_POSTGRES_CA_PEM): a successful SELECT, the closed
//     RELATION_NOT_IN_SOURCE / SQL_REJECTED_STATIC / DATABASE_REJECTED /
//     ROW_LIMIT / COST_LIMIT / TIMEOUT refusals, and that the query role cannot
//     read the column it was not granted.

import (
	"context"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	scopedIntegrationSchema    = "kv_s3_scope"
	scopedIntegrationForeign   = "kv_s3_other"
	scopedIntegrationQueryRole = "kv_s3_query"
	scopedIntegrationPassword  = "kvquerypass"
)

func scopedIntegrationScope() ScopedSchema {
	return scopedSchema(
		ScopedRelation{Schema: scopedIntegrationSchema, Table: "contracts", Columns: []string{"id", "status", "amount"}},
		ScopedRelation{Schema: scopedIntegrationSchema, Table: "customers", Columns: []string{"id", "name"}},
	)
}

// seedScopedIntegration creates the integration fixtures idempotently. It runs
// as the administrative connection only; the query role receives column-level
// SELECT on contracts (secret deliberately withheld), SELECT on customers and
// nothing else.
func seedScopedIntegration(t *testing.T, ctx context.Context, admin *pgx.Conn) {
	t.Helper()
	statements := []string{
		`CREATE SCHEMA IF NOT EXISTS ` + scopedIntegrationSchema,
		`CREATE SCHEMA IF NOT EXISTS ` + scopedIntegrationForeign,
		`CREATE TABLE IF NOT EXISTS ` + scopedIntegrationSchema + `.contracts (id int PRIMARY KEY, status text, amount numeric, secret text)`,
		`CREATE TABLE IF NOT EXISTS ` + scopedIntegrationSchema + `.customers (id int PRIMARY KEY, name text)`,
		`CREATE TABLE IF NOT EXISTS ` + scopedIntegrationForeign + `.foreign_rows (id int PRIMARY KEY, note text)`,
		`CREATE OR REPLACE VIEW ` + scopedIntegrationSchema + `.active_contracts AS SELECT id, status, amount FROM ` + scopedIntegrationSchema + `.contracts WHERE status = 'active'`,
		`DELETE FROM ` + scopedIntegrationSchema + `.contracts`,
		`DELETE FROM ` + scopedIntegrationSchema + `.customers`,
		`INSERT INTO ` + scopedIntegrationSchema + `.contracts (id, status, amount, secret) VALUES (1, 'active', 10, 's1'), (2, 'active', 20, 's2'), (3, 'closed', 30, 's3')`,
		`INSERT INTO ` + scopedIntegrationSchema + `.customers (id, name) VALUES (1, 'Acme')`,
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '` + scopedIntegrationQueryRole + `') THEN CREATE ROLE ` + scopedIntegrationQueryRole + ` LOGIN PASSWORD '` + scopedIntegrationPassword + `'; END IF; END $$`,
		`GRANT USAGE ON SCHEMA ` + scopedIntegrationSchema + ` TO ` + scopedIntegrationQueryRole,
		`GRANT USAGE ON SCHEMA ` + scopedIntegrationForeign + ` TO ` + scopedIntegrationQueryRole,
		`GRANT SELECT ON ` + scopedIntegrationSchema + `.active_contracts TO ` + scopedIntegrationQueryRole,
		`REVOKE ALL ON ` + scopedIntegrationSchema + `.contracts FROM ` + scopedIntegrationQueryRole,
		`GRANT SELECT (id, status, amount) ON ` + scopedIntegrationSchema + `.contracts TO ` + scopedIntegrationQueryRole,
		`REVOKE ALL ON ` + scopedIntegrationSchema + `.customers FROM ` + scopedIntegrationQueryRole,
		`GRANT SELECT ON ` + scopedIntegrationSchema + `.customers TO ` + scopedIntegrationQueryRole,
		`REVOKE ALL ON ` + scopedIntegrationForeign + `.foreign_rows FROM ` + scopedIntegrationQueryRole,
		`GRANT SELECT ON ` + scopedIntegrationForeign + `.foreign_rows TO ` + scopedIntegrationQueryRole,
	}
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}
}

// explainAsQueryRole runs EXPLAIN (VERBOSE, FORMAT JSON) with the query role's
// rights on the administrative connection, so the plan walk sees exactly the
// plan the real execution role would produce. search_path is reset to the
// source's schemas, mirroring prepareScopedTransaction.
func explainAsQueryRole(t *testing.T, ctx context.Context, admin *pgx.Conn, sqlText string) ([]byte, string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `SET ROLE `+scopedIntegrationQueryRole); err != nil {
		t.Fatalf("set role: %v", err)
	}
	defer func() { _, _ = admin.Exec(ctx, `RESET ROLE`) }()
	if _, err := admin.Exec(ctx, `SET search_path = `+scopedIntegrationSchema); err != nil {
		t.Fatalf("set search_path: %v", err)
	}
	var plan string
	err := admin.QueryRow(ctx, "EXPLAIN (VERBOSE, FORMAT JSON) "+sqlText).Scan(&plan)
	if err != nil {
		return nil, err.Error()
	}
	return []byte(plan), ""
}

func TestScopedPlanWalkOnRealPostgreSQLPlans(t *testing.T) {
	adminDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if adminDSN == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the ADR-0097 plan-walk proof")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close(ctx)
	seedScopedIntegration(t, ctx, admin)

	allowed := []string{
		`SELECT count(*) FROM ` + scopedIntegrationSchema + `.contracts`,
		`SELECT count(*) FROM contracts`,
		`WITH active AS (SELECT id, amount FROM ` + scopedIntegrationSchema + `.contracts WHERE status = 'active') SELECT count(*) FROM active`,
		`SELECT c.id, u.name FROM ` + scopedIntegrationSchema + `.contracts AS c JOIN ` + scopedIntegrationSchema + `.customers AS u ON u.id = c.id`,
		`SELECT id FROM (SELECT id FROM ` + scopedIntegrationSchema + `.contracts) AS inner_contracts`,
		`SELECT * FROM ` + scopedIntegrationSchema + `.active_contracts`,
	}
	for _, sqlText := range allowed {
		plan, failure := explainAsQueryRole(t, ctx, admin, sqlText)
		if failure != "" {
			t.Fatalf("allowed query %q failed to explain: %s", sqlText, failure)
		}
		if code := PlanScopeProblem(plan, scopedIntegrationScope()); code != "" {
			t.Fatalf("allowed query %q was refused with %s", sqlText, code)
		}
	}

	refused := []string{
		`SELECT count(*) FROM pg_catalog.pg_class`,
		`SELECT table_name FROM information_schema.tables`,
		`SELECT count(*) FROM ` + scopedIntegrationForeign + `.foreign_rows`,
		`SELECT * FROM generate_series(1, 3)`,
		`SELECT count(*) FROM ` + scopedIntegrationSchema + `.customers c JOIN ` + scopedIntegrationForeign + `.foreign_rows f ON f.id = c.id`,
	}
	for _, sqlText := range refused {
		plan, failure := explainAsQueryRole(t, ctx, admin, sqlText)
		if failure != "" {
			t.Fatalf("refused query %q failed to explain: %s", sqlText, failure)
		}
		if code := PlanScopeProblem(plan, scopedIntegrationScope()); code != CodeRelationNotInSource {
			t.Fatalf("query %q = %q, want %s", sqlText, code, CodeRelationNotInSource)
		}
	}
}

// scopedIntegrationConfig builds the governed connection for the read-only
// query role. It is only called when the TLS material is supplied, because the
// package's DSN policy requires sslmode=verify-full.
func scopedIntegrationConfig(t *testing.T, limits Limits) Config {
	t.Helper()
	queryDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_QUERY_URL"))
	caPEM := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_CA_PEM"))
	if queryDSN == "" || caPEM == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_QUERY_URL and KNOWVAULT_TEST_POSTGRES_CA_PEM for the ADR-0097 end-to-end proof")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatalf("KNOWVAULT_TEST_POSTGRES_CA_PEM is not a certificate")
	}
	return Config{
		ConnectionID: "conn_s3_2_query", DatabaseIdentity: "pgdb:s3_2_test", WorkspaceID: "ws_s3_2",
		DSN: queryDSN, TrustRoots: pool, Limits: limits,
	}
}

func TestExecuteScopedOnRealPostgreSQL(t *testing.T) {
	adminDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if adminDSN == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the ADR-0097 end-to-end proof")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close(ctx)
	seedScopedIntegration(t, ctx, admin)

	config := scopedIntegrationConfig(t, validLimits())
	scope := scopedIntegrationScope()

	result, attempt, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `SELECT count(*) FROM ` + scopedIntegrationSchema + `.contracts`, Purpose: "count contracts", Schema: scope})
	if err != nil {
		t.Fatalf("governed read failed: %v (code=%s)", err, CodeOf(err))
	}
	if attempt.Outcome != OutcomeSucceeded || result.RowCount != 1 || len(result.Columns) != 1 || result.Rows[0][0] == nil || *result.Rows[0][0] != "3" {
		t.Fatalf("governed read = %+v attempt %+v", result, attempt)
	}
	if attempt.SQLHash == "" || attempt.ResultDigest == "" || !VerifyTextTableResultDigest(result.Columns, result.RowCount, result.Rows, attempt.ResultDigest) {
		t.Fatalf("attempt did not carry a verifiable digest: %+v", attempt)
	}
	if result.ExecutionStartedAt.IsZero() || result.ExecutionCompletedAt.Before(result.ExecutionStartedAt) {
		t.Fatalf("execution window = %v..%v", result.ExecutionStartedAt, result.ExecutionCompletedAt)
	}

	// The query role was never granted the excluded column: PostgreSQL itself
	// refuses it, which the closed vocabulary reports as DATABASE_REJECTED.
	if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `SELECT secret FROM ` + scopedIntegrationSchema + `.contracts`, Schema: scope}); CodeOf(err) != CodeDatabaseRejected {
		t.Fatalf("ungranted column = %v, want %s", CodeOf(err), CodeDatabaseRejected)
	}
	// A write is refused before any connection is dialled.
	if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `INSERT INTO ` + scopedIntegrationSchema + `.contracts (id) VALUES (99)`, Schema: scope}); CodeOf(err) != CodeSQLRejectedStatic {
		t.Fatalf("insert = %v, want %s", CodeOf(err), CodeSQLRejectedStatic)
	}
	// A relation outside the source is refused by the plan walk.
	if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `SELECT count(*) FROM ` + scopedIntegrationForeign + `.foreign_rows`, Schema: scope}); CodeOf(err) != CodeRelationNotInSource {
		t.Fatalf("foreign relation = %v, want %s", CodeOf(err), CodeRelationNotInSource)
	}
	// A function scan is outside the relation scope.
	if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `SELECT * FROM generate_series(1, 3)`, Schema: scope}); CodeOf(err) != CodeRelationNotInSource {
		t.Fatalf("function scan = %v, want %s", CodeOf(err), CodeRelationNotInSource)
	}

	rowLimited := scopedIntegrationConfig(t, Limits{StatementTimeout: 5 * time.Second, MaxRows: 1, MaxResultBytes: 1 << 20, MaxCostEstimate: 1000})
	if _, _, err := ExecuteScoped(ctx, rowLimited, ScopedParams{SQLText: `SELECT id FROM ` + scopedIntegrationSchema + `.contracts`, Schema: scope}); CodeOf(err) != CodeRowLimit {
		t.Fatalf("row limit = %v, want %s", CodeOf(err), CodeRowLimit)
	}

	costLimited := scopedIntegrationConfig(t, Limits{StatementTimeout: 5 * time.Second, MaxRows: 100, MaxResultBytes: 1 << 20, MaxCostEstimate: 0.0001})
	if _, _, err := ExecuteScoped(ctx, costLimited, ScopedParams{SQLText: `SELECT count(*) FROM ` + scopedIntegrationSchema + `.contracts`, Schema: scope}); CodeOf(err) != CodeCostLimit {
		t.Fatalf("cost limit = %v, want %s", CodeOf(err), CodeCostLimit)
	}

	slow := scopedIntegrationConfig(t, Limits{StatementTimeout: time.Second, MaxRows: 100, MaxResultBytes: 1 << 20, MaxCostEstimate: 1000})
	if _, _, err := ExecuteScoped(ctx, slow, ScopedParams{SQLText: `SELECT pg_sleep(2)`, Schema: scope}); CodeOf(err) != CodeTimeout {
		t.Fatalf("statement timeout = %v, want %s", CodeOf(err), CodeTimeout)
	}
}

// TestScopedQueryRoleIsReadOnlyAndColumnScoped proves the database-side
// boundary independently of the Go path: the query role can read the granted
// columns, cannot read the withheld one and cannot write at all.
func TestScopedQueryRoleIsReadOnlyAndColumnScoped(t *testing.T) {
	adminDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if adminDSN == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the ADR-0097 grant proof")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close(ctx)
	seedScopedIntegration(t, ctx, admin)
	if _, err := admin.Exec(ctx, `SET ROLE `+scopedIntegrationQueryRole); err != nil {
		t.Fatalf("set role: %v", err)
	}
	defer func() { _, _ = admin.Exec(ctx, `RESET ROLE`) }()

	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM `+scopedIntegrationSchema+`.contracts`).Scan(&count); err != nil {
		t.Fatalf("granted read failed: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT secret FROM `+scopedIntegrationSchema+`.contracts LIMIT 1`).Scan(new(string)); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("withheld column read = %v, want a permission denial", err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO `+scopedIntegrationSchema+`.contracts (id) VALUES (999)`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("insert = %v, want a permission denial", err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM `+scopedIntegrationForeign+`.foreign_rows`).Scan(&count); err != nil {
		t.Fatalf("foreign schema read (fixture must be readable to prove the GO walk refuses it): %v", err)
	}
}
