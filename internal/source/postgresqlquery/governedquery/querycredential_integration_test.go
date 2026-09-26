package governedquery

// querycredential_integration_test.go is S3 card 2b's real-PostgreSQL proof for
// the candidate query-credential checks. It reuses the card's pinned scoped
// fixtures (KNOWVAULT_TEST_POSTGRES_URL, KNOWVAULT_TEST_POSTGRES_QUERY_URL and
// KNOWVAULT_TEST_POSTGRES_CA_PEM) and proves, on the real database:
//
//   - an accepted credential reaches the exact registered database identity and
//     is refused when it points at another identity;
//   - a role that can read a column outside the registered projection is
//     refused with the column-privilege code; and
//   - a missing relation or an unauthenticated connection is refused with the
//     connection-rejected code.

import (
	"context"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func queryCredentialIntegrationConfig(t *testing.T) (Config, QueryCredentialParams) {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if adminDSN == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the ADR-0097 query-credential proof")
	}
	queryDSN := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_QUERY_URL"))
	caPEM := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_CA_PEM"))
	if queryDSN == "" || caPEM == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_QUERY_URL and KNOWVAULT_TEST_POSTGRES_CA_PEM for the query-credential proof")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })
	seedScopedIntegration(t, ctx, admin)
	// Card S3.2c: VerifyQueryCredential now runs the full least-privilege proof,
	// so the candidate role must hold exactly the registered projection.
	hardenScopedIntegrationRole(t, ctx, admin)

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
	config := Config{
		ConnectionID: "conn_s3_2b_check", DatabaseIdentity: identity, WorkspaceID: "ws_s3_2b",
		DSN: queryDSN, TrustRoots: pool, Limits: validLimits(),
	}
	params := QueryCredentialParams{Relations: []ScopedRelation{
		{Schema: scopedIntegrationSchema, Table: "contracts", Columns: []string{"id", "status", "amount"}},
		{Schema: scopedIntegrationSchema, Table: "customers", Columns: []string{"id", "name"}},
	}}
	return config, params
}

func TestVerifyQueryCredentialOnRealPostgreSQL(t *testing.T) {
	config, params := queryCredentialIntegrationConfig(t)
	ctx := context.Background()

	if err := VerifyQueryCredential(ctx, config, params); err != nil {
		t.Fatalf("accepted credential was refused: %v (%s)", err, CodeOf(err))
	}

	mismatch := config
	mismatch.DatabaseIdentity = "pgdb:" + strings.Repeat("0", 64)
	if err := VerifyQueryCredential(ctx, mismatch, params); CodeOf(err) != CodeQueryCredentialDatabaseMismatch {
		t.Fatalf("wrong database identity = %v (%s), want %s", err, CodeOf(err), CodeQueryCredentialDatabaseMismatch)
	}

	// The role can SELECT customers.name, so a projection of the full registered
	// scope that excludes it is exactly the column-privilege refusal. Both
	// registered relations stay in the scope so the extra-relation rule (which
	// runs first) cannot mask the column rule.
	excluded := QueryCredentialParams{Relations: []ScopedRelation{
		{Schema: scopedIntegrationSchema, Table: "contracts", Columns: []string{"id", "status", "amount"}},
		{Schema: scopedIntegrationSchema, Table: "customers", Columns: []string{"id"}},
	}}
	if err := VerifyQueryCredential(ctx, config, excluded); CodeOf(err) != CodeQueryCredentialColumnPrivilege {
		t.Fatalf("readable excluded column = %v (%s), want %s", err, CodeOf(err), CodeQueryCredentialColumnPrivilege)
	}

	missing := QueryCredentialParams{Relations: []ScopedRelation{
		{Schema: scopedIntegrationSchema, Table: "contracts", Columns: []string{"id", "status", "amount"}},
		{Schema: scopedIntegrationSchema, Table: "customers", Columns: []string{"id", "name"}},
		{Schema: scopedIntegrationSchema, Table: "missing_relation", Columns: []string{"id"}},
	}}
	if err := VerifyQueryCredential(ctx, config, missing); CodeOf(err) != CodeQueryCredentialRejected {
		t.Fatalf("missing relation = %v (%s), want %s", err, CodeOf(err), CodeQueryCredentialRejected)
	}

	badCredentials := config
	badCredentials.DSN = strings.Replace(config.DSN, scopedIntegrationPassword, "wrong-password", 1)
	if badCredentials.DSN == config.DSN {
		t.Fatalf("fixture DSN did not carry the query role password")
	}
	if err := VerifyQueryCredential(ctx, badCredentials, params); CodeOf(err) != CodeQueryCredentialRejected {
		t.Fatalf("unauthenticated connection = %v (%s), want %s", err, CodeOf(err), CodeQueryCredentialRejected)
	}
}
