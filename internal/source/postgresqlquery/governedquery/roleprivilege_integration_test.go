package governedquery

// roleprivilege_integration_test.go is S3 card 2c's real-PostgreSQL proof for
// the least-privilege role verification of ADR-0097 §3. It runs against the
// card's pinned container: the product database named by
// KNOWVAULT_TEST_POSTGRES_URL plus a separate customer-like database in the
// same container (created on demand, default name customer_db). The role-rule
// proofs need no TLS: they run a read-only transaction as the administrative
// connection, SET LOCAL ROLE to each fixture role and call VerifyQueryRole
// directly, which is exactly what the server does on the governed connection.
//
// The end-to-end proof additionally exercises ExecuteScoped against the
// customer database when the query DSN and CA are supplied
// (KNOWVAULT_TEST_POSTGRES_QUERY_URL, KNOWVAULT_TEST_POSTGRES_CA_PEM): an
// over-privileged role answers SOURCE_SQL_NOT_CONFIGURED and a canary proves no
// agent statement ran, while a properly scoped role cannot reach an excluded
// column, an out-of-scope table through query_to_xml, or a customer SECURITY
// DEFINER function.

import (
	"context"
	"crypto/x509"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	rolePrivilegeSchema    = "kv_s3_2c"
	rolePrivilegeOther     = "kv_s3_2c_other"
	rolePrivilegeExtension = "kv_s3_2c_ext"
	rolePrivilegePassword  = "kvrolepass"
)

// The fixture roles: one properly scoped role and one role per least-privilege
// rule, each differing from the properly scoped role in exactly one way.
const (
	rolePrivilegeOK       = "kv_s3_2c_ok"
	rolePrivilegeMissing  = "kv_s3_2c_missing"
	rolePrivilegeExcluded = "kv_s3_2c_excluded"
	rolePrivilegeExtra    = "kv_s3_2c_extra"
	rolePrivilegeWrite    = "kv_s3_2c_write"
	rolePrivilegeElevated = "kv_s3_2c_elevated"
	rolePrivilegeMember   = "kv_s3_2c_member"
	rolePrivilegeHelper   = "kv_s3_2c_helper"
	rolePrivilegeDefiner  = "kv_s3_2c_definer"
	rolePrivilegeRemote   = "kv_s3_2c_remote"
)

func rolePrivilegeRelations() []ScopedRelation {
	return []ScopedRelation{
		{Schema: rolePrivilegeSchema, Table: "contracts", Columns: []string{"id", "status", "amount"}},
		{Schema: rolePrivilegeSchema, Table: "customers", Columns: []string{"id", "name"}},
	}
}

// customerDatabaseURL returns an administrative DSN for the card's separate
// customer-like database in the same container, creating it when the
// administrative connection is allowed to. It derives the URL from
// KNOWVAULT_TEST_POSTGRES_URL so no extra address ever reaches the repository.
func customerDatabaseURL(t *testing.T) string {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if adminDSN == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the ADR-0097 least-privilege proof")
	}
	parsed, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse KNOWVAULT_TEST_POSTGRES_URL: %v", err)
	}
	const customerName = "customer_db"
	if strings.TrimPrefix(parsed.Path, "/") == customerName {
		return adminDSN
	}
	customer := *parsed
	customer.Path = "/" + customerName
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close(ctx)
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1)`, customerName).Scan(&exists); err != nil {
		t.Fatalf("inspect customer database: %v", err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+customerName); err != nil {
			t.Skipf("cannot create the customer-like database: %v", err)
		}
	}
	return customer.String()
}

// seedRolePrivilegeFixtures creates the schema, tables, canary, SECURITY DEFINER
// functions and all fixture roles idempotently. It runs as the administrative
// connection only.
func seedRolePrivilegeFixtures(t *testing.T, ctx context.Context, admin *pgx.Conn) bool {
	t.Helper()
	statements := []string{
		`CREATE SCHEMA IF NOT EXISTS ` + rolePrivilegeSchema,
		`CREATE SCHEMA IF NOT EXISTS ` + rolePrivilegeOther,
		`CREATE SCHEMA IF NOT EXISTS ` + rolePrivilegeExtension,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeSchema + `.contracts (id int PRIMARY KEY, status text, amount numeric, secret text)`,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeSchema + `.customers (id int PRIMARY KEY, name text)`,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeOther + `.rows (id int PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeSchema + `.canary (id int PRIMARY KEY)`,
		`CREATE OR REPLACE FUNCTION ` + rolePrivilegeSchema + `.leak() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, ` + rolePrivilegeSchema + ` AS $$ SELECT secret FROM ` + rolePrivilegeSchema + `.contracts LIMIT 1 $$`,
		`CREATE OR REPLACE FUNCTION ` + rolePrivilegeSchema + `.mark() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ` + rolePrivilegeSchema + ` AS $$ BEGIN INSERT INTO ` + rolePrivilegeSchema + `.canary (id) VALUES (1); RETURN 1; END $$`,
		`REVOKE ALL ON FUNCTION ` + rolePrivilegeSchema + `.leak() FROM PUBLIC`,
		`REVOKE ALL ON FUNCTION ` + rolePrivilegeSchema + `.mark() FROM PUBLIC`,
		`REVOKE ALL ON SCHEMA ` + rolePrivilegeExtension + ` FROM PUBLIC`,
		`TRUNCATE ` + rolePrivilegeSchema + `.canary`,
	}
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}
	roles := []string{
		rolePrivilegeOK, rolePrivilegeMissing, rolePrivilegeExcluded, rolePrivilegeExtra,
		rolePrivilegeWrite, rolePrivilegeElevated, rolePrivilegeMember, rolePrivilegeHelper,
		rolePrivilegeDefiner, rolePrivilegeRemote,
	}
	for _, role := range roles {
		for _, statement := range []string{
			`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '` + role + `') THEN EXECUTE 'DROP OWNED BY ' || quote_ident('` + role + `'); EXECUTE 'DROP ROLE ' || quote_ident('` + role + `'); END IF; END $$`,
			`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + rolePrivilegePassword + `' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`,
			`GRANT USAGE ON SCHEMA ` + rolePrivilegeSchema + ` TO ` + role,
			`GRANT SELECT (id, status, amount) ON ` + rolePrivilegeSchema + `.contracts TO ` + role,
			`GRANT SELECT ON ` + rolePrivilegeSchema + `.customers TO ` + role,
		} {
			if _, err := admin.Exec(ctx, statement); err != nil {
				t.Fatalf("seed role %s with %q: %v", role, statement, err)
			}
		}
	}
	// Exactly one rule broken per role.
	extras := []string{
		`REVOKE SELECT (amount) ON ` + rolePrivilegeSchema + `.contracts FROM ` + rolePrivilegeMissing,
		`GRANT SELECT (secret) ON ` + rolePrivilegeSchema + `.contracts TO ` + rolePrivilegeExcluded,
		`GRANT USAGE ON SCHEMA ` + rolePrivilegeOther + ` TO ` + rolePrivilegeExtra,
		`GRANT SELECT ON ` + rolePrivilegeOther + `.rows TO ` + rolePrivilegeExtra,
		`GRANT INSERT ON ` + rolePrivilegeSchema + `.contracts TO ` + rolePrivilegeWrite,
		`ALTER ROLE ` + rolePrivilegeElevated + ` CREATEDB`,
		`GRANT ` + rolePrivilegeHelper + ` TO ` + rolePrivilegeMember,
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.leak() TO ` + rolePrivilegeDefiner,
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.mark() TO ` + rolePrivilegeDefiner,
	}
	for _, statement := range extras {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("seed rule violation %q: %v", statement, err)
		}
	}
	// The remote-execution rule is proven only when dblink is installed in its
	// own schema; a fresh database has it nowhere.
	if _, err := admin.Exec(ctx, `DROP EXTENSION IF EXISTS dblink`); err != nil {
		t.Logf("dblink not droppable, skipping the remote-execution fixture: %v", err)
		return false
	}
	if _, err := admin.Exec(ctx, `CREATE EXTENSION dblink SCHEMA `+rolePrivilegeExtension); err != nil {
		t.Logf("dblink not installable, skipping the remote-execution fixture: %v", err)
		return false
	}
	if _, err := admin.Exec(ctx, `REVOKE ALL ON SCHEMA `+rolePrivilegeExtension+` FROM PUBLIC`); err != nil {
		t.Fatalf("restrict extension schema: %v", err)
	}
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA `+rolePrivilegeExtension+` TO `+rolePrivilegeRemote); err != nil {
		t.Fatalf("grant remote extension usage: %v", err)
	}
	return true
}

// verifyRole runs VerifyQueryRole in a read-only transaction whose current_user
// is the fixture role, exactly as the governed connection would.
func verifyRole(t *testing.T, ctx context.Context, admin *pgx.Conn, role string) error {
	t.Helper()
	transaction, err := admin.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin role transaction: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatalf("set role %s: %v", role, err)
	}
	return VerifyQueryRole(ctx, transaction, rolePrivilegeRelations())
}

func TestQueryRoleLeastPrivilegeRulesOnRealPostgreSQL(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	remoteAvailable := seedRolePrivilegeFixtures(t, ctx, admin)

	cases := []struct {
		role string
		want ErrorCode
	}{
		{rolePrivilegeOK, ""},
		{rolePrivilegeMissing, CodeQueryRoleMissingSelect},
		{rolePrivilegeExcluded, CodeQueryCredentialColumnPrivilege},
		{rolePrivilegeExtra, CodeQueryRoleExtraRelation},
		{rolePrivilegeWrite, CodeQueryRoleWritePrivilege},
		{rolePrivilegeElevated, CodeQueryRoleElevatedAttribute},
		{rolePrivilegeMember, CodeQueryRoleMembership},
		{rolePrivilegeDefiner, CodeQueryRoleSecurityDefiner},
	}
	if remoteAvailable {
		cases = append(cases, struct {
			role string
			want ErrorCode
		}{rolePrivilegeRemote, CodeQueryRoleRemoteExecution})
	}
	for _, testCase := range cases {
		t.Run(testCase.role, func(t *testing.T) {
			err := verifyRole(t, ctx, admin, testCase.role)
			if testCase.want == "" {
				if err != nil {
					t.Fatalf("properly scoped role refused: %v (%s)", err, CodeOf(err))
				}
				return
			}
			if CodeOf(err) != testCase.want {
				t.Fatalf("%s = %v (%s), want %s", testCase.role, err, CodeOf(err), testCase.want)
			}
		})
	}
}

// TestExecuteScopedRefusesOverPrivilegedRoleWithoutRunning proves the tool
// boundary, not only the verifier: an over-privileged role answers
// SOURCE_SQL_NOT_CONFIGURED and the agent's canary statement never runs.
func TestExecuteScopedRefusesOverPrivilegedRoleWithoutRunning(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	config := rolePrivilegeConfig(t, ctx, admin, rolePrivilegeDefiner)
	_, _, err = ExecuteScoped(ctx, config, ScopedParams{
		SQLText: `SELECT ` + rolePrivilegeSchema + `.mark()`, Schema: ScopedSchema{Relations: rolePrivilegeRelations()},
	})
	if CodeOf(err) != CodeSourceSQLNotConfigured {
		t.Fatalf("over-privileged role = %v (%s), want %s", err, CodeOf(err), CodeSourceSQLNotConfigured)
	}
	var canary int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM `+rolePrivilegeSchema+`.canary`).Scan(&canary); err != nil {
		t.Fatalf("read canary: %v", err)
	}
	if canary != 0 {
		t.Fatalf("an over-privileged role executed the agent statement: canary rows = %d", canary)
	}
}

// TestExecuteScopedRefusesOutOfScopeReadsWithScopedRole proves a properly
// scoped role reads nothing outside the projected columns through the three
// attack paths the card names.
func TestExecuteScopedRefusesOutOfScopeReadsWithScopedRole(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	config := rolePrivilegeConfig(t, ctx, admin, rolePrivilegeOK)
	scope := ScopedSchema{Relations: rolePrivilegeRelations()}
	attacks := map[string]string{
		"excluded column":                `SELECT secret FROM ` + rolePrivilegeSchema + `.contracts`,
		"query_to_xml over out of scope": `SELECT query_to_xml('SELECT * FROM ` + rolePrivilegeOther + `.rows', true, false, '')`,
		"customer security definer":      `SELECT ` + rolePrivilegeSchema + `.leak()`,
	}
	for name, sqlText := range attacks {
		t.Run(name, func(t *testing.T) {
			result, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: sqlText, Schema: scope})
			if err == nil {
				t.Fatalf("attack %q was allowed and returned %d rows", sqlText, result.RowCount)
			}
			switch CodeOf(err) {
			case CodeDatabaseRejected, CodeRelationNotInSource:
			default:
				t.Fatalf("attack %q = %v (%s), want a closed refusal", sqlText, err, CodeOf(err))
			}
		})
	}

	// A registered read still succeeds with the same role.
	result, _, err := ExecuteScoped(ctx, config, ScopedParams{
		SQLText: `SELECT count(*) FROM ` + rolePrivilegeSchema + `.contracts`, Schema: scope,
	})
	if err != nil || result.RowCount != 1 {
		t.Fatalf("registered read = %+v err=%v", result, err)
	}
}

// TestExecuteScopedRefusesWrongDatabaseIdentity proves the after-connect
// identity check: a credential repointed at another database is
// DATABASE_REJECTED and nothing runs.
func TestExecuteScopedRefusesWrongDatabaseIdentity(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	config := rolePrivilegeConfig(t, ctx, admin, rolePrivilegeOK)
	config.DatabaseIdentity = "pgdb:" + strings.Repeat("0", 64)
	if _, _, err := ExecuteScoped(ctx, config, ScopedParams{
		SQLText: `SELECT count(*) FROM ` + rolePrivilegeSchema + `.contracts`,
		Schema:  ScopedSchema{Relations: rolePrivilegeRelations()},
	}); CodeOf(err) != CodeDatabaseRejected {
		t.Fatalf("wrong database identity = %v (%s), want %s", err, CodeOf(err), CodeDatabaseRejected)
	}
}

// rolePrivilegeConfig builds the governed config for one fixture role,
// recomputing the registered database identity from the live database. It needs
// the TLS query DSN and CA; without them the caller's test is skipped.
func rolePrivilegeConfig(t *testing.T, ctx context.Context, admin *pgx.Conn, role string) Config {
	t.Helper()
	queryDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_QUERY_URL"))
	caPEM := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_CA_PEM"))
	if queryDSN == "" || caPEM == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_QUERY_URL and KNOWVAULT_TEST_POSTGRES_CA_PEM for the ADR-0097 execution proof")
	}
	base, err := url.Parse(queryDSN)
	if err != nil {
		t.Fatalf("parse query DSN: %v", err)
	}
	base.User = url.UserPassword(role, rolePrivilegePassword)
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin identity read: %v", err)
	}
	identity, err := queryCredentialDatabaseIdentity(ctx, transaction)
	_ = transaction.Rollback(ctx)
	if err != nil {
		t.Fatalf("read database identity: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatalf("KNOWVAULT_TEST_POSTGRES_CA_PEM is not a certificate")
	}
	return Config{
		ConnectionID: "conn_s3_2c_" + role, DatabaseIdentity: identity, WorkspaceID: "ws_s3_2c",
		DSN: base.String(), TrustRoots: pool, Limits: Limits{StatementTimeout: 5 * time.Second, MaxRows: 100, MaxResultBytes: 1 << 20, MaxCostEstimate: 100000},
	}
}
