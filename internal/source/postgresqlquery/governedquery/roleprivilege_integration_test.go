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
	"net"
	"net/url"
	"os"
	"strconv"
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
	// Card S3.2d's new rule fixtures.
	rolePrivilegeUnlimited     = "kv_s3_2d_unlimited"
	rolePrivilegeBigMem        = "kv_s3_2d_bigmem"
	rolePrivilegeLob           = "kv_s3_2d_lob"
	rolePrivilegeUntrusted     = "kv_s3_2d_untrusted"
	rolePrivilegeCatalogDefin  = "kv_s3_2d_catdefiner"
	rolePrivilegeDefinerOwner  = "kv_s3_2d_defowner"
	rolePrivilegeUntrustedLang = "kv_s3_2d_untrusted_lang"
	// Card S3.2e's trigger-function rule fixture: a role that differs from the
	// properly scoped one only by being able to EXECUTE a SECURITY DEFINER
	// trigger function owned by a non-bootstrap role.
	rolePrivilegeTrigger = "kv_s3_2e_trigger"
)

func rolePrivilegeRelations() []ScopedRelation {
	return []ScopedRelation{
		{Schema: rolePrivilegeSchema, Table: "contracts", Columns: []string{"id", "status", "amount"}},
		{Schema: rolePrivilegeSchema, Table: "customers", Columns: []string{"id", "name"}},
	}
}

// customerDatabaseURL returns the administrative DSN the card's real-PostgreSQL
// proofs run against. Card S3.2d runs every proof in the one pinned integration
// database named by KNOWVAULT_TEST_POSTGRES_URL (knowvault_test), so the
// admin-side identity computation and the query credential reach the same
// authority and a single KNOWVAULT_TEST_POSTGRES_QUERY_URL is enough. The
// fixtures live in dedicated schemas, never in the product schema.
func customerDatabaseURL(t *testing.T) string {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if adminDSN == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the ADR-0097 least-privilege proof")
	}
	return adminDSN
}

// seedRolePrivilegeFixtures creates the schema, tables, canary, SECURITY DEFINER
// functions and all fixture roles idempotently. It runs as the administrative
// connection only.
func seedRolePrivilegeFixtures(t *testing.T, ctx context.Context, admin *pgx.Conn) bool {
	t.Helper()
	// The non-bootstrap superuser that owns the dangerous SECURITY DEFINER
	// functions. Card S3.2d R4 exempts only bootstrap-superuser-owned
	// SECURITY DEFINER functions, so a function owned by this role must be
	// refused wherever it lives, including pg_catalog. It is created once and
	// kept: DROP OWNED cannot drop a role that still owns objects other roles
	// depend on.
	if _, err := admin.Exec(ctx, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '`+rolePrivilegeDefinerOwner+`') THEN CREATE ROLE `+rolePrivilegeDefinerOwner+` LOGIN PASSWORD '`+rolePrivilegePassword+`' SUPERUSER; END IF; END $$`); err != nil {
		t.Fatalf("create the non-bootstrap definer owner: %v", err)
	}
	statements := []string{
		`CREATE SCHEMA IF NOT EXISTS ` + rolePrivilegeSchema,
		`CREATE SCHEMA IF NOT EXISTS ` + rolePrivilegeOther,
		`CREATE SCHEMA IF NOT EXISTS ` + rolePrivilegeExtension,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeSchema + `.contracts (id int PRIMARY KEY, status text, amount numeric, secret text)`,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeSchema + `.customers (id int PRIMARY KEY, name text)`,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeOther + `.rows (id int PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS ` + rolePrivilegeSchema + `.canary (id int PRIMARY KEY)`,
		// mark() stays owned by the bootstrap superuser: it is the trusted
		// canary helper and the R4 exemption's positive control.
		`CREATE OR REPLACE FUNCTION ` + rolePrivilegeSchema + `.mark() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ` + rolePrivilegeSchema + ` AS $$ BEGIN INSERT INTO ` + rolePrivilegeSchema + `.canary (id) VALUES (1); RETURN 1; END $$`,
		// leak() is then handed to the non-bootstrap superuser.
		`CREATE OR REPLACE FUNCTION ` + rolePrivilegeSchema + `.leak() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, ` + rolePrivilegeSchema + ` AS $$ SELECT secret FROM ` + rolePrivilegeSchema + `.contracts LIMIT 1 $$`,
		`ALTER FUNCTION ` + rolePrivilegeSchema + `.leak() OWNER TO ` + rolePrivilegeDefinerOwner,
		`REVOKE ALL ON FUNCTION ` + rolePrivilegeSchema + `.leak() FROM PUBLIC`,
		`REVOKE ALL ON FUNCTION ` + rolePrivilegeSchema + `.mark() FROM PUBLIC`,
		// R4: a SECURITY DEFINER function in pg_catalog itself, owned by the
		// non-bootstrap superuser. The old rule skipped pg_catalog entirely.
		`CREATE OR REPLACE FUNCTION pg_catalog.kv_s3_2d_catalog_definer() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ SELECT 1 $$`,
		`ALTER FUNCTION pg_catalog.kv_s3_2d_catalog_definer() OWNER TO ` + rolePrivilegeDefinerOwner,
		`REVOKE ALL ON FUNCTION pg_catalog.kv_s3_2d_catalog_definer() FROM PUBLIC`,
		// R4: a real untrusted procedural language (handler reused, so the
		// catalog state is genuine: lanpltrusted = false) and one function in
		// it.
		`DROP LANGUAGE IF EXISTS ` + rolePrivilegeUntrustedLang + ` CASCADE`,
		`CREATE PROCEDURAL LANGUAGE ` + rolePrivilegeUntrustedLang + ` HANDLER plpgsql_call_handler`,
		`CREATE FUNCTION ` + rolePrivilegeSchema + `.untrusted_fn() RETURNS int LANGUAGE ` + rolePrivilegeUntrustedLang + ` AS $$ BEGIN RETURN 1; END $$`,
		`REVOKE ALL ON FUNCTION ` + rolePrivilegeSchema + `.untrusted_fn() FROM PUBLIC`,
		// Card S3.2e R4: SECURITY DEFINER trigger functions cannot be called
		// from a SELECT. trigger_untrusted exercises the owner exemption (it is
		// created by the bootstrap superuser, in an untrusted language);
		// trigger_definer exercises the language exemption (a non-bootstrap
		// owner, but plpgsql); trigger_event proves the event_trigger type is
		// exempt too.
		`CREATE OR REPLACE FUNCTION ` + rolePrivilegeSchema + `.trigger_untrusted() RETURNS trigger LANGUAGE ` + rolePrivilegeUntrustedLang + ` SECURITY DEFINER AS $$ BEGIN RETURN NEW; END $$`,
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.trigger_untrusted() TO PUBLIC`,
		`CREATE OR REPLACE FUNCTION ` + rolePrivilegeSchema + `.trigger_event() RETURNS event_trigger LANGUAGE ` + rolePrivilegeUntrustedLang + ` SECURITY DEFINER AS $$ BEGIN END $$`,
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.trigger_event() TO PUBLIC`,
		`CREATE OR REPLACE FUNCTION ` + rolePrivilegeSchema + `.trigger_definer() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$ BEGIN RETURN NEW; END $$`,
		`ALTER FUNCTION ` + rolePrivilegeSchema + `.trigger_definer() OWNER TO ` + rolePrivilegeDefinerOwner,
		`REVOKE ALL ON FUNCTION ` + rolePrivilegeSchema + `.trigger_definer() FROM PUBLIC`,
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
		rolePrivilegeDefiner, rolePrivilegeRemote, rolePrivilegeUnlimited, rolePrivilegeBigMem,
		rolePrivilegeLob, rolePrivilegeUntrusted, rolePrivilegeCatalogDefin, rolePrivilegeTrigger,
	}
	for _, role := range roles {
		for _, statement := range []string{
			// The fixture roles persist across runs (a role with dependencies in
			// another database cannot be dropped from here); reset their
			// attributes, memberships and in-database privileges instead.
			`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '` + role + `') THEN CREATE ROLE ` + role + ` LOGIN PASSWORD '` + rolePrivilegePassword + `' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $$`,
			`ALTER ROLE ` + role + ` NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`,
			`DROP OWNED BY ` + role,
			`REVOKE pg_read_all_data FROM ` + role,
			`GRANT USAGE ON SCHEMA ` + rolePrivilegeSchema + ` TO ` + role,
			`GRANT SELECT (id, status, amount) ON ` + rolePrivilegeSchema + `.contracts TO ` + role,
			`GRANT SELECT ON ` + rolePrivilegeSchema + `.customers TO ` + role,
		} {
			if _, err := admin.Exec(ctx, statement); err != nil {
				t.Fatalf("seed role %s with %q: %v", role, statement, err)
			}
		}
	}
	// Card S3.2d R2: the DBA pins work_mem and temp_file_limit on the role.
	// rolePrivilegeUnlimited keeps PostgreSQL's default temp_file_limit = -1 and
	// rolePrivilegeBigMem gets an over-large work_mem; every other fixture role
	// is pinned so its intended rule is the one that fires.
	for _, role := range []string{
		rolePrivilegeOK, rolePrivilegeMissing, rolePrivilegeExcluded, rolePrivilegeExtra,
		rolePrivilegeWrite, rolePrivilegeElevated, rolePrivilegeMember, rolePrivilegeHelper,
		rolePrivilegeDefiner, rolePrivilegeRemote, rolePrivilegeLob, rolePrivilegeUntrusted,
		rolePrivilegeCatalogDefin, rolePrivilegeBigMem, rolePrivilegeTrigger,
	} {
		for _, statement := range []string{
			`ALTER ROLE ` + role + ` SET temp_file_limit = '512MB'`,
			`ALTER ROLE ` + role + ` SET work_mem = '16MB'`,
		} {
			if _, err := admin.Exec(ctx, statement); err != nil {
				t.Fatalf("pin resource limits on %s with %q: %v", role, statement, err)
			}
		}
	}
	if _, err := admin.Exec(ctx, `ALTER ROLE `+rolePrivilegeBigMem+` SET work_mem = '128MB'`); err != nil {
		t.Fatalf("oversize work_mem on the bigmem fixture: %v", err)
	}
	// Exactly one rule broken per role.
	extras := []string{
		`REVOKE ` + rolePrivilegeHelper + ` FROM ` + rolePrivilegeMember,
		`REVOKE SELECT (amount) ON ` + rolePrivilegeSchema + `.contracts FROM ` + rolePrivilegeMissing,
		`GRANT SELECT (secret) ON ` + rolePrivilegeSchema + `.contracts TO ` + rolePrivilegeExcluded,
		`GRANT USAGE ON SCHEMA ` + rolePrivilegeOther + ` TO ` + rolePrivilegeExtra,
		`GRANT SELECT ON ` + rolePrivilegeOther + `.rows TO ` + rolePrivilegeExtra,
		`GRANT INSERT ON ` + rolePrivilegeSchema + `.contracts TO ` + rolePrivilegeWrite,
		`ALTER ROLE ` + rolePrivilegeElevated + ` CREATEDB`,
		`GRANT ` + rolePrivilegeHelper + ` TO ` + rolePrivilegeMember,
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.leak() TO ` + rolePrivilegeDefiner,
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.mark() TO ` + rolePrivilegeDefiner,
		// The trusted canary helper stays executable by the properly scoped
		// role: R1's "the agent statement never ran" control.
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.mark() TO ` + rolePrivilegeOK,
		`GRANT EXECUTE ON FUNCTION pg_catalog.kv_s3_2d_catalog_definer() TO ` + rolePrivilegeCatalogDefin,
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.untrusted_fn() TO ` + rolePrivilegeUntrusted,
		// Card S3.2e R4: the reviewed-language trigger function, owned by the
		// non-bootstrap superuser, is the language branch of the exemption.
		`GRANT EXECUTE ON FUNCTION ` + rolePrivilegeSchema + `.trigger_definer() TO ` + rolePrivilegeTrigger,
	}
	for _, statement := range extras {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("seed rule violation %q: %v", statement, err)
		}
	}
	// R3: one real large object readable by one fixture role.
	if _, err := admin.Exec(ctx, `DO $$
		DECLARE loid oid;
		BEGIN
			SELECT pg_catalog.lo_from_bytea(0, 'kv-s3-2d-secret'::bytea) INTO loid;
			EXECUTE format('GRANT SELECT, UPDATE ON LARGE OBJECT %s TO %I', loid, '`+rolePrivilegeLob+`');
		END $$`); err != nil {
		t.Fatalf("seed the large-object fixture: %v", err)
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
// is the fixture role, exactly as the governed connection would. SET ROLE does
// not apply the role's own ALTER ROLE ... SET values, so the transaction first
// pins the same bounded work_mem and temp_file_limit the fixture role carries;
// the role's real login-time values are proven separately by verifyRoleAsLogin.
func verifyRole(t *testing.T, ctx context.Context, admin *pgx.Conn, role string) error {
	t.Helper()
	transaction, err := admin.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin role transaction: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	for _, statement := range []string{
		`SET LOCAL temp_file_limit = '512MB'`,
		`SET LOCAL work_mem = '16MB'`,
	} {
		if _, err := transaction.Exec(ctx, statement); err != nil {
			t.Fatalf("pin %q: %v", statement, err)
		}
	}
	if _, err := transaction.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatalf("set role %s: %v", role, err)
	}
	return VerifyQueryRole(ctx, transaction, rolePrivilegeRelations())
}

// verifyRoleAsLogin opens a real connection as the fixture role, so PostgreSQL
// applies exactly the role's own ALTER ROLE ... SET resource bounds, and runs
// the proof there. It is the faithful test for card S3.2d R2's effective
// temp_file_limit/work_mem rule.
func verifyRoleAsLogin(t *testing.T, ctx context.Context, admin *pgx.Conn, role string) error {
	t.Helper()
	connection := dialAsRole(t, ctx, admin, role)
	defer connection.Close(ctx)
	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin role transaction as %s: %v", role, err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	return VerifyQueryRole(ctx, transaction, rolePrivilegeRelations())
}

// dialAsRole opens one real connection as the fixture role against the card's
// customer-like database, so PostgreSQL applies the role's own login-time
// settings.
func dialAsRole(t *testing.T, ctx context.Context, admin *pgx.Conn, role string) *pgx.Conn {
	t.Helper()
	parsed, err := url.Parse(admin.Config().ConnString())
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	parsed.User = url.UserPassword(role, rolePrivilegePassword)
	connection, err := pgx.Connect(ctx, parsed.String())
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	return connection
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

// rolePrivilegeAlternatePort is the card container's second published host
// port, used to reach the same server through a different authority so R8's
// host/port binding can be proven without a second server.
const rolePrivilegeAlternatePort = "55479"

// rolePrivilegeAlternateAuthority rewrites one verified DSN to the container's
// second published port.
func rolePrivilegeAlternateAuthority(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	host, _, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split DSN host: %v", err)
	}
	parsed.Host = net.JoinHostPort(host, rolePrivilegeAlternatePort)
	return parsed.String()
}

// identityForDSN connects a real role session and recomputes the database
// identity from it, exactly as the execution path does. It dials through the
// package's own trust-rooted transport, because the DSN policy requires
// sslmode=verify-full.
func identityForDSN(t *testing.T, ctx context.Context, dsn string) string {
	t.Helper()
	config := Config{
		ConnectionID: "conn_s3_2d_identity", DatabaseIdentity: "pgdb:identity-probe", WorkspaceID: "ws_s3_2d",
		DSN: dsn, TrustRoots: rolePrivilegeTrustRoots(t),
		Limits: Limits{StatementTimeout: 5 * time.Second, MaxRows: 100, MaxResultBytes: 1 << 20, MaxCostEstimate: 100000},
	}
	connection, err := dial(ctx, config)
	if err != nil {
		t.Skipf("alternate authority is unreachable: %v", err)
	}
	defer connection.Close(ctx)
	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin identity transaction: %v", err)
	}
	identity, err := queryCredentialDatabaseIdentity(ctx, transaction)
	_ = transaction.Rollback(ctx)
	if err != nil {
		t.Fatalf("recompute identity: %v", err)
	}
	return identity
}

// TestQueryRoleResourceLimitsOnRealPostgreSQL proves card S3.2d R2: a role with
// PostgreSQL's default unlimited temp_file_limit (or an over-large work_mem)
// fails the proof, while the pinned role passes. The roles log in for real so
// PostgreSQL applies their ALTER ROLE ... SET values.
func TestQueryRoleResourceLimitsOnRealPostgreSQL(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	cases := map[string]struct {
		role string
		want ErrorCode
	}{
		"pinned values pass":           {rolePrivilegeOK, ""},
		"unlimited temp_file_limit":    {rolePrivilegeUnlimited, CodeQueryRoleResourceLimit},
		"work_mem above sixty-four MB": {rolePrivilegeBigMem, CodeQueryRoleResourceLimit},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			err := verifyRoleAsLogin(t, ctx, admin, testCase.role)
			if testCase.want == "" {
				if err != nil {
					t.Fatalf("pinned role refused: %v (%s)", err, CodeOf(err))
				}
				return
			}
			if CodeOf(err) != testCase.want {
				t.Fatalf("%s = %v (%s), want %s", testCase.role, err, CodeOf(err), testCase.want)
			}
		})
	}
}

// TestQueryRoleLargeObjectOnRealPostgreSQL proves card S3.2d R3: a role that
// can read a real large object fails the proof.
func TestQueryRoleLargeObjectOnRealPostgreSQL(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	if err := verifyRoleAsLogin(t, ctx, admin, rolePrivilegeLob); CodeOf(err) != CodeQueryRoleLargeObject {
		t.Fatalf("large-object role = %v (%s), want %s", err, CodeOf(err), CodeQueryRoleLargeObject)
	}
	if err := verifyRoleAsLogin(t, ctx, admin, rolePrivilegeOK); err != nil {
		t.Fatalf("a role without large-object access was refused: %v (%s)", err, CodeOf(err))
	}
}

// TestQueryRoleUntrustedLanguageOnRealPostgreSQL proves card S3.2d R4's
// property rule: a role that can EXECUTE a function in an untrusted procedural
// language fails the proof even though the language is not one of the named
// extension languages.
func TestQueryRoleUntrustedLanguageOnRealPostgreSQL(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	if err := verifyRoleAsLogin(t, ctx, admin, rolePrivilegeUntrusted); CodeOf(err) != CodeQueryRoleUntrustedLanguage {
		t.Fatalf("untrusted-language role = %v (%s), want %s", err, CodeOf(err), CodeQueryRoleUntrustedLanguage)
	}
}

// TestQueryRoleSecurityDefinerOwnershipOnRealPostgreSQL proves card S3.2d R4's
// owner property: a SECURITY DEFINER function owned by a non-bootstrap
// superuser is refused in pg_catalog exactly as it is in a user schema, while a
// bootstrap-superuser-owned SECURITY DEFINER helper the role may execute does
// not refuse an otherwise least-privilege role.
func TestQueryRoleSecurityDefinerOwnershipOnRealPostgreSQL(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	// rolePrivilegeCatalogDefin can EXECUTE the pg_catalog function owned by the
	// non-bootstrap superuser.
	if err := verifyRole(t, ctx, admin, rolePrivilegeCatalogDefin); CodeOf(err) != CodeQueryRoleSecurityDefiner {
		t.Fatalf("pg_catalog definer = %v (%s), want %s", err, CodeOf(err), CodeQueryRoleSecurityDefiner)
	}
	// The properly scoped role can EXECUTE the bootstrap-owned canary helper and
	// must still pass, so the exemption is not a blanket admission.
	if err := verifyRole(t, ctx, admin, rolePrivilegeOK); err != nil {
		t.Fatalf("the bootstrap-owned definer exemption refused the scoped role: %v (%s)", err, CodeOf(err))
	}
}

// TestQueryRoleTriggerFunctionsDoNotBlockTheProof is card S3.2e R4 on real
// PostgreSQL. A SECURITY DEFINER trigger function in an untrusted language and
// owned by the bootstrap superuser, executable by PUBLIC, must not fail the
// proof; the same holds for a non-bootstrap-owned trigger function written in a
// reviewed trigger language. A SECURITY DEFINER non-trigger function still
// fails it, so the exemption is exactly the trigger return type.
func TestQueryRoleTriggerFunctionsDoNotBlockTheProof(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	// The owner branch is only proven when the fixture is genuinely owned by the
	// bootstrap superuser.
	var ownerOID int
	if err := admin.QueryRow(ctx, `
		SELECT procedure.proowner::int
		FROM pg_catalog.pg_proc AS procedure
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
		WHERE namespace.nspname = $1 AND procedure.proname = 'trigger_untrusted'`,
		rolePrivilegeSchema).Scan(&ownerOID); err != nil {
		t.Fatalf("read the trigger fixture owner: %v", err)
	}
	if ownerOID != bootstrapSuperuserOID {
		t.Fatalf("bootstrap-owned trigger fixture owner = %d, want %d", ownerOID, bootstrapSuperuserOID)
	}

	// The scoped role can EXECUTE the bootstrap-owned SECURITY DEFINER trigger
	// functions through PUBLIC and must pass.
	if err := verifyRole(t, ctx, admin, rolePrivilegeOK); err != nil {
		t.Fatalf("the bootstrap-owned trigger function refused the scoped role: %v (%s)", err, CodeOf(err))
	}
	// The scoped role can EXECUTE the plpgsql trigger owned by the non-bootstrap
	// superuser and must pass too.
	if err := verifyRole(t, ctx, admin, rolePrivilegeTrigger); err != nil {
		t.Fatalf("the reviewed-language trigger function refused the scoped role: %v (%s)", err, CodeOf(err))
	}
	// A SECURITY DEFINER non-trigger function still fails the proof.
	if err := verifyRole(t, ctx, admin, rolePrivilegeDefiner); CodeOf(err) != CodeQueryRoleSecurityDefiner {
		t.Fatalf("non-trigger definer = %v (%s), want %s", err, CodeOf(err), CodeQueryRoleSecurityDefiner)
	}
	// A non-trigger function in the untrusted language still fails the proof.
	if err := verifyRole(t, ctx, admin, rolePrivilegeUntrusted); CodeOf(err) != CodeQueryRoleUntrustedLanguage {
		t.Fatalf("non-trigger untrusted function = %v (%s), want %s", err, CodeOf(err), CodeQueryRoleUntrustedLanguage)
	}
}

// TestExecuteScopedReprovesRoleOnEveryCall is card S3.2d R1: the proof runs in
// the statement's own read-only transaction every time, so a proof recorded for
// the exact scope/credential pair can never authorize a later statement after
// the role widens. Each scenario grants the role one new capability, the next
// call is SOURCE_SQL_NOT_CONFIGURED, zero rows come back, the statement was
// never planned (no cost) and the canary proves it never ran.
func TestExecuteScopedReprovesRoleOnEveryCall(t *testing.T) {
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

	// Baseline: prove and execute successfully, which records the proof cache
	// row for this exact pair. R1 forbids reusing it below.
	result, _, err := ExecuteScoped(ctx, config, ScopedParams{
		SQLText: `SELECT count(*) FROM ` + rolePrivilegeSchema + `.contracts`, Schema: scope,
	})
	if err != nil || result.RowCount != 1 {
		t.Fatalf("baseline registered read = %+v err=%v", result, err)
	}

	scenarios := []struct {
		name    string
		mutate  string
		restore string
	}{
		{
			name:    "excluded column granted",
			mutate:  `GRANT SELECT (secret) ON ` + rolePrivilegeSchema + `.contracts TO ` + rolePrivilegeOK,
			restore: `REVOKE SELECT (secret) ON ` + rolePrivilegeSchema + `.contracts FROM ` + rolePrivilegeOK,
		},
		{
			name:    "pg_read_all_data membership added",
			mutate:  `GRANT pg_read_all_data TO ` + rolePrivilegeOK,
			restore: `REVOKE pg_read_all_data FROM ` + rolePrivilegeOK,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, scenario.mutate); err != nil {
				t.Fatalf("mutate %s: %v", scenario.name, err)
			}
			defer func() {
				if _, err := admin.Exec(ctx, scenario.restore); err != nil {
					t.Fatalf("restore %s: %v", scenario.name, err)
				}
			}()
			next, attempt, err := ExecuteScoped(ctx, config, ScopedParams{
				SQLText: `SELECT count(*) FROM ` + rolePrivilegeSchema + `.contracts`, Schema: scope,
			})
			if CodeOf(err) != CodeSourceSQLNotConfigured {
				t.Fatalf("next call after %s = %v (%s), want %s", scenario.name, err, CodeOf(err), CodeSourceSQLNotConfigured)
			}
			if next.RowCount != 0 || attempt.CostEstimate != 0 {
				t.Fatalf("refused call ran the statement: rows=%d cost=%v", next.RowCount, attempt.CostEstimate)
			}
			// The canary statement must not have run.
			if _, err := admin.Exec(ctx, `TRUNCATE `+rolePrivilegeSchema+`.canary`); err != nil {
				t.Fatalf("reset canary: %v", err)
			}
			if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `SELECT ` + rolePrivilegeSchema + `.mark()`, Schema: scope}); CodeOf(err) != CodeSourceSQLNotConfigured {
				t.Fatalf("canary after %s = %v (%s)", scenario.name, err, CodeOf(err))
			}
			var canary int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM `+rolePrivilegeSchema+`.canary`).Scan(&canary); err != nil {
				t.Fatalf("read canary: %v", err)
			}
			if canary != 0 {
				t.Fatalf("the agent statement ran after %s: canary rows = %d", scenario.name, canary)
			}
		})
	}

	t.Run("mounted DSN repointed to a broader role", func(t *testing.T) {
		broader := rolePrivilegeConfig(t, ctx, admin, rolePrivilegeExtra)
		if _, _, err := ExecuteScoped(ctx, broader, ScopedParams{
			SQLText: `SELECT count(*) FROM ` + rolePrivilegeSchema + `.contracts`, Schema: scope,
		}); CodeOf(err) != CodeSourceSQLNotConfigured {
			t.Fatalf("broader role = %v (%s), want %s", err, CodeOf(err), CodeSourceSQLNotConfigured)
		}
	})

	// Card S3.2d R2 at the execution boundary: the role's configured
	// work_mem/temp_file_limit are proven before prepareScopedTransaction pins
	// the transaction's own 16 MB work_mem, so the violation is still caught.
	for _, resourceRole := range []string{rolePrivilegeUnlimited, rolePrivilegeBigMem} {
		t.Run("resource bound "+resourceRole, func(t *testing.T) {
			resourceConfig := rolePrivilegeConfig(t, ctx, admin, resourceRole)
			if _, _, err := ExecuteScoped(ctx, resourceConfig, ScopedParams{
				SQLText: `SELECT count(*) FROM ` + rolePrivilegeSchema + `.contracts`, Schema: scope,
			}); CodeOf(err) != CodeSourceSQLNotConfigured {
				t.Fatalf("%s = %v (%s), want %s", resourceRole, err, CodeOf(err), CodeSourceSQLNotConfigured)
			}
		})
	}
}

// TestExecuteScopedRefusesCrossSessionFunctions proves card S3.2d R3 at the
// execution boundary: every cross-session, file and large-object family is
// refused before any connection, and two role sessions cannot see or cancel one
// another through the tool.
func TestExecuteScopedRefusesCrossSessionFunctions(t *testing.T) {
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
	for _, sqlText := range []string{
		`SELECT query FROM pg_stat_activity WHERE pid = 1`,
		`SELECT pg_cancel_backend(1)`,
		`SELECT pg_terminate_backend(1)`,
		`SELECT pg_backend_pid()`,
		`SELECT pg_advisory_lock(1)`,
		`SELECT pg_sleep(1)`,
		`SELECT lo_get(1)`,
		`SELECT pg_read_file('/etc/passwd')`,
		`SELECT query_to_xml('SELECT 1', true, false, '')`,
	} {
		if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: sqlText, Schema: scope}); CodeOf(err) != CodeSQLRejectedStatic {
			t.Fatalf("%q = %v (%s), want %s", sqlText, err, CodeOf(err), CodeSQLRejectedStatic)
		}
	}

	// Two real sessions of the same query role on the same connection: A runs a
	// long statement and B tries to inspect and cancel it through the tool.
	first := dialAsRole(t, ctx, admin, rolePrivilegeOK)
	defer first.Close(ctx)
	var firstPID int
	if err := first.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
		t.Fatalf("read first session pid: %v", err)
	}
	firstDone := make(chan error, 1)
	go func() {
		var slept string
		firstDone <- first.QueryRow(ctx, `SELECT pg_sleep(2)::text`).Scan(&slept)
	}()
	// Give A a moment to start its statement.
	deadline := time.Now().Add(2 * time.Second)
	for {
		var active bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND state = 'active')`, firstPID).Scan(&active); err != nil {
			t.Fatalf("inspect first session: %v", err)
		}
		if active || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// B's tool attempts are both refused before any server call, so workspace B
	// can neither read A's query text nor signal A's backend.
	if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `SELECT query FROM pg_stat_activity WHERE pid = ` + strconv.Itoa(firstPID), Schema: scope}); CodeOf(err) != CodeSQLRejectedStatic {
		t.Fatalf("session B inspecting A = %v (%s), want %s", err, CodeOf(err), CodeSQLRejectedStatic)
	}
	if _, _, err := ExecuteScoped(ctx, config, ScopedParams{SQLText: `SELECT pg_cancel_backend(` + strconv.Itoa(firstPID) + `)`, Schema: scope}); CodeOf(err) != CodeSQLRejectedStatic {
		t.Fatalf("session B cancelling A = %v (%s), want %s", err, CodeOf(err), CodeSQLRejectedStatic)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("session A was cancelled: %v", err)
	}
}

// TestQueryCredentialIdentityBindsHostAndPort proves card S3.2d R8: the
// database identity binds the connected host and port, so reaching the same
// database name and oid through another authority is a mismatch and the
// execution boundary refuses it.
func TestQueryCredentialIdentityBindsHostAndPort(t *testing.T) {
	ctx := context.Background()
	adminDSN := customerDatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect customer database: %v", err)
	}
	defer admin.Close(ctx)
	seedRolePrivilegeFixtures(t, ctx, admin)

	config := rolePrivilegeConfig(t, ctx, admin, rolePrivilegeOK)
	onQueryAuthority := identityForDSN(t, ctx, config.DSN)
	if onQueryAuthority != config.DatabaseIdentity {
		t.Fatalf("identity derivation differs between discovery and query authorities: %q vs %q", onQueryAuthority, config.DatabaseIdentity)
	}
	alternate := rolePrivilegeAlternateAuthority(t, config.DSN)
	onAlternateAuthority := identityForDSN(t, ctx, alternate)
	if onAlternateAuthority == config.DatabaseIdentity {
		t.Fatalf("another authority produced the same identity %q", onAlternateAuthority)
	}
	repointed := config
	repointed.DSN = alternate
	if _, _, err := ExecuteScoped(ctx, repointed, ScopedParams{
		SQLText: `SELECT count(*) FROM ` + rolePrivilegeSchema + `.contracts`,
		Schema:  ScopedSchema{Relations: rolePrivilegeRelations()},
	}); CodeOf(err) != CodeDatabaseRejected {
		t.Fatalf("repointed authority = %v (%s), want %s", err, CodeOf(err), CodeDatabaseRejected)
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
			case CodeDatabaseRejected, CodeRelationNotInSource, CodeSQLRejectedStatic:
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

// rolePrivilegeTrustRoots parses the mounted CA PEM the query DSNs are verified
// against.
func rolePrivilegeTrustRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	caPEM := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_CA_PEM"))
	if caPEM == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_CA_PEM for the ADR-0097 execution proof")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatalf("KNOWVAULT_TEST_POSTGRES_CA_PEM is not a certificate")
	}
	return pool
}

// rolePrivilegeConfig builds the governed config for one fixture role,
// recomputing the registered database identity from the live database. It needs
// the TLS query DSN and CA; without them the caller's test is skipped.
func rolePrivilegeConfig(t *testing.T, ctx context.Context, admin *pgx.Conn, role string) Config {
	t.Helper()
	queryDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_QUERY_URL"))
	if queryDSN == "" {
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
	return Config{
		ConnectionID: "conn_s3_2c_" + role, DatabaseIdentity: identity, WorkspaceID: "ws_s3_2c",
		DSN: base.String(), TrustRoots: rolePrivilegeTrustRoots(t), Limits: Limits{StatementTimeout: 5 * time.Second, MaxRows: 100, MaxResultBytes: 1 << 20, MaxCostEstimate: 100000},
	}
}
