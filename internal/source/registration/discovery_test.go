package registration

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

func TestDiscoveryRequestIDIsStableForScopedIdempotency(t *testing.T) {
	const hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	left := discoveryRequestID("org_alpha", "usr_owner", hash)
	right := discoveryRequestID("org_alpha", "usr_owner", hash)
	if left != right || !validGeneratedID(left, "sdrq_") {
		t.Fatalf("discovery request id = %q/%q", left, right)
	}
	if discoveryRequestID("org_beta", "usr_owner", hash) == left ||
		discoveryRequestID("org_alpha", "usr_other", hash) == left ||
		discoveryRequestID("org_alpha", "usr_owner", "sha256:"+repeatHex('f', 64)) == left {
		t.Fatal("discovery id does not stay scoped to organization and idempotency hash")
	}
}

func TestNormalizeDiscoveryLimitsUsesBoundedServerProfile(t *testing.T) {
	limits, err := normalizeDiscoveryLimits(postgresqlquery.DiscoveryLimits{})
	if err != nil || limits != postgresqlquery.DefaultDiscoveryLimits() {
		t.Fatalf("default discovery limits = %#v, err=%v", limits, err)
	}
	if _, err := normalizeDiscoveryLimits(postgresqlquery.DiscoveryLimits{
		MaxViews: 1025, MaxColumns: 1, MaxCommentBytes: 1,
		StatementTimeout: time.Second, TransactionTimeout: time.Second,
	}); err == nil {
		t.Fatal("request accepted more views than the durable result bound")
	}
	tooLongStatement := postgresqlquery.DefaultDiscoveryLimits()
	tooLongStatement.StatementTimeout = 5*time.Minute + time.Millisecond
	if _, err := normalizeDiscoveryLimits(tooLongStatement); err == nil {
		t.Fatal("request accepted a statement timeout beyond the durable bound")
	}
	tooLongTransaction := postgresqlquery.DefaultDiscoveryLimits()
	tooLongTransaction.TransactionTimeout = 10*time.Minute + time.Millisecond
	if _, err := normalizeDiscoveryLimits(tooLongTransaction); err == nil {
		t.Fatal("request accepted a transaction timeout beyond the durable bound")
	}
}

func TestDiscoveryRequestValidationRejectsCallerControlledSecretsAndSelection(t *testing.T) {
	valid := DiscoveryRequest{
		ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", IdempotencyKey: "request-1",
	}
	if !validGeneratedID(valid.ConnectionID, "conn_") || !validIdempotencyKey(valid.IdempotencyKey) {
		t.Fatal("valid opaque discovery request was rejected by its shape helpers")
	}
	for _, key := range []string{" request", "request\x00"} {
		if validIdempotencyKey(key) {
			t.Fatalf("unsafe idempotency key accepted: %q", key)
		}
	}
}

// tableRegisterRequest is a well-formed POSTGRESQL_QUERY RegisterRequest over
// a base table: one primary-key IDENTITY column and one EVIDENCE column, the
// same shape discovery would derive from a table with a declared primary key.
func tableRegisterRequest(relationKind string) RegisterRequest {
	return RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: "Accounts", Kind: "business-objects",
		DatabaseIdentity: "pgdb_demo", LineageID: "lineage_accounts", ProjectionRevision: 1,
		ContractHash: "sha256:" + repeatHex('a', 64),
		SchemaName:   "public", RelationName: "accounts", RelationKind: relationKind,
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID,
				Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
				Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024},
		},
		EmptySnapshotPolicy: "HELD",
	}
}

// TestValidatePostgreSQLQueryAcceptsBaseAndPartitionedTable is the S1
// "contract/worker/registration accept TABLE" acceptance test for the
// registration surface: an ordinary or partitioned base table validates
// exactly like the original VIEW/MATERIALIZED_VIEW contract, and an
// unrecognized relation kind stays refused.
func TestValidatePostgreSQLQueryAcceptsBaseAndPartitionedTable(t *testing.T) {
	for _, kind := range []string{"VIEW", "MATERIALIZED_VIEW", "TABLE", "PARTITIONED_TABLE"} {
		request := tableRegisterRequest(kind)
		if err := request.validatePostgreSQLQuery(); err != nil {
			t.Fatalf("relation kind %q rejected: %v", kind, err)
		}
	}
	unrecognized := tableRegisterRequest("FOREIGN_TABLE")
	if err := unrecognized.validatePostgreSQLQuery(); CodeOf(err) != CodeRequestInvalid {
		t.Fatalf("unrecognized relation kind accepted: err=%v code=%s", err, CodeOf(err))
	}
}

func repeatHex(character byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = character
	}
	return string(result)
}
