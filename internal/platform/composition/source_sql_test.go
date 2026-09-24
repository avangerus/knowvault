package composition

// S3 card 2b focused tests for the composition boundary of the SQL query
// credential control: the closed refusal-code vocabulary and the fail-closed
// behaviour when the capability is not mounted. The real checks against a
// PostgreSQL source are proven by the governedquery integration test and by the
// repository integration test.

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

func TestSourceQueryCredentialRefusalCodeVocabulary(t *testing.T) {
	// The transport's closed codes are exactly the governed executor's own, so
	// an operator sees one vocabulary across every layer.
	for _, code := range []string{
		workspaceapi.SourceQueryCredentialUnresolved,
		string(governedquery.CodeQueryCredentialDatabaseMismatch),
		string(governedquery.CodeQueryCredentialColumnPrivilege),
		string(governedquery.CodeQueryCredentialRejected),
	} {
		if code != "SOURCE_QUERY_CREDENTIAL_UNRESOLVED" && code != "SOURCE_QUERY_CREDENTIAL_DATABASE_MISMATCH" &&
			code != "SOURCE_QUERY_CREDENTIAL_COLUMN_PRIVILEGE" && code != "SOURCE_QUERY_CREDENTIAL_DATABASE_REJECTED" {
			t.Fatalf("unexpected closed credential code %q", code)
		}
	}
	// A plain error and a nil error both fold into the connection-rejected code
	// rather than leaking a driver message.
	if got := sourceQueryCredentialRefusalCode(context.Canceled); got != string(governedquery.CodeQueryCredentialRejected) {
		t.Fatalf("plain error code = %q, want %q", got, governedquery.CodeQueryCredentialRejected)
	}
	if got := sourceQueryCredentialRefusalCode(nil); got != string(governedquery.CodeQueryCredentialRejected) {
		t.Fatalf("nil error code = %q, want %q", got, governedquery.CodeQueryCredentialRejected)
	}
}

func TestSourceQueryCredentialFailsClosedWithoutMount(t *testing.T) {
	var executor sourceSQLExecutor
	access := database.AccessContext{OrganizationID: "org_test", PrincipalID: "usr_test", RequestID: "req_test"}
	err := executor.SetSourceQueryCredential(context.Background(), access, "ws_test", "conn_test", "cred_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if workspaceapi.SourceQueryCredentialRefusalCode(err) != string(governedquery.CodeQueryCredentialRejected) {
		t.Fatalf("unmounted credential control = %v, want the rejected code", err)
	}
	if err := executor.ReauthorizeSourceSQLAttempt(context.Background(), access, "ws_test", question.SourceSQLAttemptDisclosure{ConnectionID: "conn_test"}); err == nil {
		t.Fatal("unmounted source SQL reauthorization must fail closed")
	}
}
