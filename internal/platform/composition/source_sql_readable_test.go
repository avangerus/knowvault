package composition

// Card D-18 result 3: finding out whether a workspace database can be read is
// an access to that database like any other. These focused tests use the same
// closed fake workspace, auditor and resolver the load-limit tests use, so they
// need no database: the readiness check takes the shared load limit before any
// credential is resolved (an over-limit check opens no connection), appends
// exactly one content-free governed-query attempt record naming the connection
// and the asking user, and counts as failed -- never as readable -- when that
// record cannot be written.

import (
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

func TestSourceReadableTakesTheSharedLoadLimit(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	resolver := &fakeSourceSQLResolver{dsn: "postgres://user:pass@db.example/customer?sslmode=verify-full"}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	// Take both per-source slots the shared limiter has.
	firstRelease, firstCode := executor.limiter.acquire(target.SourceID, hardeningAccess().PrincipalID)
	secondRelease, secondCode := executor.limiter.acquire(target.SourceID, hardeningAccess().PrincipalID)
	if firstCode != "" || secondCode != "" {
		t.Fatalf("holding the limit = %q, %q, want admission", firstCode, secondCode)
	}
	defer firstRelease()
	defer secondRelease()

	err := executor.SourceReadable(context.Background(), hardeningAccess(), "ws_alpha", target.SourceID)
	if !errors.Is(err, workspacetools.ErrSourceBusy) {
		t.Fatalf("over-limit readiness check = %v, want ErrSourceBusy", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("an over-limit check resolved the credential %d times, want no connection", resolver.calls)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("over-limit check audited %d events, want exactly 1", len(auditor.events))
	}
	if code := auditor.events[0].ErrorCode; code == nil || *code != string(governedquery.CodeSourceSQLConcurrencyLimited) {
		t.Fatalf("over-limit audit error code = %v, want %s", code, governedquery.CodeSourceSQLConcurrencyLimited)
	}
}

func TestSourceReadableLeavesOneGovernedQueryAuditRecord(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	resolver := &fakeSourceSQLResolver{dsn: "postgres://user:pass@127.0.0.1:1/customer?sslmode=verify-full"}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	if err := executor.SourceReadable(context.Background(), hardeningAccess(), "ws_alpha", target.SourceID); err == nil {
		t.Fatal("a check that could not reach the database reported the source readable")
	}
	if len(auditor.events) != 1 {
		t.Fatalf("readiness check audited %d events, want exactly 1", len(auditor.events))
	}
	event := auditor.events[0]
	if event.Action != audit.ActionGovernedQueryAttempted || event.ResourceType != audit.ResourceGovernedQueryAttempt {
		t.Fatalf("readiness audit = %s/%s, want the governed-query attempt pair", event.Action, event.ResourceType)
	}
	if event.Metadata.GovernedQueryConnectionID == nil || *event.Metadata.GovernedQueryConnectionID != target.SourceID {
		t.Fatalf("readiness audit connection = %v, want %s", event.Metadata.GovernedQueryConnectionID, target.SourceID)
	}
	if event.Metadata.GovernedQueryPurpose == nil || *event.Metadata.GovernedQueryPurpose != "readiness" {
		t.Fatalf("readiness audit purpose = %v, want the readiness check's own purpose", event.Metadata.GovernedQueryPurpose)
	}
	if event.ActorPrincipalID == nil || *event.ActorPrincipalID != "usr_alice" {
		t.Fatalf("readiness audit actor = %v, want the asking user usr_alice", event.ActorPrincipalID)
	}
	if event.WorkspaceID == nil || *event.WorkspaceID != "ws_alpha" {
		t.Fatalf("readiness audit workspace = %v, want ws_alpha", event.WorkspaceID)
	}
}

// d18FailingAuditor is a journal whose every append fails, so the test can
// prove a check whose record cannot be written counts as failed.
type d18FailingAuditor struct{ calls int }

func (auditor *d18FailingAuditor) Append(context.Context, database.AccessContext, audit.EventInput) (audit.Event, error) {
	auditor.calls++
	return audit.Event{}, errors.New("audit store unavailable")
}

func (auditor *d18FailingAuditor) GovernedQueryAttemptMatches(context.Context, database.AccessContext, string, string, string, string, string) (bool, error) {
	return false, nil
}

func TestSourceReadableAuditFailureIsAFailedCheck(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &d18FailingAuditor{}
	resolver := &fakeSourceSQLResolver{dsn: "postgres://user:pass@127.0.0.1:1/customer?sslmode=verify-full"}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	err := executor.SourceReadable(context.Background(), hardeningAccess(), "ws_alpha", target.SourceID)
	if err == nil {
		t.Fatal("a check whose audit record could not be written reported the source readable")
	}
	if errors.Is(err, workspacetools.ErrSourceBusy) {
		t.Fatalf("audit failure = %v, want a failed check, not a busy source", err)
	}
	if auditor.calls != 1 {
		t.Fatalf("audit appends = %d, want exactly 1", auditor.calls)
	}
}

func TestSourceReadableUnauthorizedSourceIsNotAudited(t *testing.T) {
	target := readySourceSQLTarget()
	target.TrustVerified = false
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	resolver := &fakeSourceSQLResolver{dsn: "postgres://user:pass@127.0.0.1:1/customer?sslmode=verify-full"}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	if err := executor.SourceReadable(context.Background(), hardeningAccess(), "ws_alpha", target.SourceID); err == nil {
		t.Fatal("an untrusted source reported readable")
	}
	if len(auditor.events) != 0 {
		t.Fatalf("a source that never passed authorization audited %d events, want 0", len(auditor.events))
	}
	if resolver.calls != 0 {
		t.Fatalf("an unauthorized check resolved the credential %d times, want no connection", resolver.calls)
	}
}
