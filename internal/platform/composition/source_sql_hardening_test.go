package composition

// S3 card 2c focused tests for the production SQL executor's audit, source
// state and load-limit contract. The executor talks to the workspace store
// through a narrow interface, so these proofs use a closed fake and need no
// database: exactly one audit event per authorized attempt (including the
// not-configured and credential-resolution refusals), the content-free
// not-found for a pending-activation or untrusted source, the returned attempt
// id equal to the audited event id, the audit surviving client cancellation,
// and the load limits refusing before any credential is resolved.

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

type fakeSourceSQLWorkspace struct {
	target     workspacerepository.SourceQuerySource
	targetErr  error
	recorded   int
	lastScope  string
	setCalls   int
	targetCall int
}

func (workspace *fakeSourceSQLWorkspace) SourceQuery(context.Context, database.AccessContext, string, string) (workspacerepository.SourceQuerySource, error) {
	workspace.targetCall++
	return workspace.target, workspace.targetErr
}

func (workspace *fakeSourceSQLWorkspace) RecordSourceQueryVerification(_ context.Context, _ database.AccessContext, _ string, _ string, _, _ int64, scopeHash, _ string) error {
	workspace.recorded++
	workspace.lastScope = scopeHash
	return nil
}

func (workspace *fakeSourceSQLWorkspace) SourceQueryCredentialTarget(context.Context, database.AccessContext, string, string) (workspacerepository.SourceQuerySource, error) {
	return workspace.target, workspace.targetErr
}

func (workspace *fakeSourceSQLWorkspace) SetSourceQueryCredential(context.Context, database.AccessContext, string, string, string) error {
	workspace.setCalls++
	return nil
}

type fakeSourceSQLAuditor struct {
	events   []audit.EventInput
	ctxError error
}

func (auditor *fakeSourceSQLAuditor) Append(ctx context.Context, _ database.AccessContext, input audit.EventInput) (audit.Event, error) {
	auditor.ctxError = ctx.Err()
	auditor.events = append(auditor.events, input)
	return audit.Event{EventID: input.EventID}, nil
}

type fakeSourceSQLResolver struct {
	dsn   string
	err   error
	calls int
}

func (resolver *fakeSourceSQLResolver) ResolveReference(context.Context, string) (string, error) {
	resolver.calls++
	return resolver.dsn, resolver.err
}

type fakeSourceSQLRoots struct{ calls int }

func (roots *fakeSourceSQLRoots) NewCertPool() (*x509.CertPool, error) {
	roots.calls++
	return x509.NewCertPool(), nil
}

func readySourceSQLTarget() workspacerepository.SourceQuerySource {
	return workspacerepository.SourceQuerySource{
		SourceID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", SourceScopeID: "scope_01H9ABCDEFGHJKMNPQRSTVWX",
		ScopeRevision: 3, ConnectionRevision: 1, DatabaseIdentity: "pgdb:" + "a",
		QueryCredentialReference: "cred_01H9ABCDEFGHJKMNPQRSTVWXYZ", QueryCredentialRevision: 1,
		ActivationStatus: "READY", TrustVerified: true,
		Relations: []workspacerepository.SourceQueryRelation{{Schema: "public", Table: "contracts", Columns: []string{"id", "status"}}},
	}
}

func newHardeningExecutor(workspace sourceSQLWorkspace, auditor sourceSQLAuditor, resolver sourceQueryCredentialResolver, roots sourceQueryTrustRoots) sourceSQLExecutor {
	return sourceSQLExecutor{
		workspaces: workspace, auditor: auditor, resolver: resolver, roots: roots,
		limits: sourceSQLServerLimits(), now: time.Now, limiter: newSourceSQLLimiter(),
	}
}

func hardeningAccess() database.AccessContext {
	return database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_hardening"}
}

func TestSourceSQLNotConfiguredIsAuditedExactlyOnce(t *testing.T) {
	target := readySourceSQLTarget()
	target.QueryCredentialReference = ""
	target.QueryCredentialRevision = 0
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	executor := newHardeningExecutor(workspace, auditor, &fakeSourceSQLResolver{}, &fakeSourceSQLRoots{})

	_, err := executor.SourceSQL(context.Background(), hardeningAccess(), "ws_alpha", workspaceapi.SourceSQLRequest{
		SourceID: target.SourceID, SQL: "SELECT 1", Purpose: "count contracts",
	})
	if workspaceapi.SourceSQLRefusalCode(err) != string(governedquery.CodeSourceSQLNotConfigured) {
		t.Fatalf("not configured = %v, want %s", err, governedquery.CodeSourceSQLNotConfigured)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("audit events = %d, want exactly 1", len(auditor.events))
	}
	event := auditor.events[0]
	if event.Action != audit.ActionGovernedQueryAttempted || event.ErrorCode == nil ||
		*event.ErrorCode != string(governedquery.CodeSourceSQLNotConfigured) ||
		event.Metadata.GovernedQueryPurpose == nil || *event.Metadata.GovernedQueryPurpose != "count contracts" {
		t.Fatalf("audit event = %+v", event)
	}
	if event.Outcome != audit.OutcomeFailed {
		t.Fatalf("refusal outcome = %s, want FAILED", event.Outcome)
	}
}

func TestSourceSQLCredentialResolutionRefusalIsAudited(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	resolver := &fakeSourceSQLResolver{err: errors.New("unresolved")}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	_, err := executor.SourceSQL(context.Background(), hardeningAccess(), "ws_alpha", workspaceapi.SourceSQLRequest{
		SourceID: target.SourceID, SQL: "SELECT 1",
	})
	if workspaceapi.SourceSQLRefusalCode(err) != string(governedquery.CodeDatabaseRejected) {
		t.Fatalf("resolution refusal = %v, want %s", err, governedquery.CodeDatabaseRejected)
	}
	if resolver.calls != 1 || len(auditor.events) != 1 || auditor.events[0].Outcome != audit.OutcomeFailed {
		t.Fatalf("resolution refusal audit = calls=%d events=%d", resolver.calls, len(auditor.events))
	}
}

func TestSourceSQLPendingActivationAndUntrustedAreContentFreeNotFound(t *testing.T) {
	for name, mutate := range map[string]func(*workspacerepository.SourceQuerySource){
		"pending activation": func(target *workspacerepository.SourceQuerySource) { target.ActivationStatus = "DRAFT" },
		"syncing activation": func(target *workspacerepository.SourceQuerySource) { target.ActivationStatus = "SYNCING" },
		"untrusted":          func(target *workspacerepository.SourceQuerySource) { target.TrustVerified = false },
	} {
		t.Run(name, func(t *testing.T) {
			target := readySourceSQLTarget()
			mutate(&target)
			workspace := &fakeSourceSQLWorkspace{target: target}
			auditor := &fakeSourceSQLAuditor{}
			executor := newHardeningExecutor(workspace, auditor, &fakeSourceSQLResolver{}, &fakeSourceSQLRoots{})
			_, err := executor.SourceSQL(context.Background(), hardeningAccess(), "ws_alpha", workspaceapi.SourceSQLRequest{
				SourceID: target.SourceID, SQL: "SELECT 1",
			})
			if workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
				t.Fatalf("%s = %v, want CodeNotFound", name, err)
			}
			if len(auditor.events) != 0 {
				t.Fatalf("%s audited %d events for a source that was never authorized", name, len(auditor.events))
			}
		})
	}
}

func TestSourceSQLConcurrencyLimitRefusesBeforeCredentialResolution(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	resolver := &fakeSourceSQLResolver{dsn: "postgres://user:pass@db.example/customer?sslmode=verify-full"}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	// Occupy both per-source slots without releasing them.
	first, code := executor.limiter.acquire(target.SourceID, "usr_alice")
	if code != "" {
		t.Fatalf("first acquire = %s", code)
	}
	second, code := executor.limiter.acquire(target.SourceID, "usr_alice")
	if code != "" {
		t.Fatalf("second acquire = %s", code)
	}
	defer first()
	defer second()

	_, err := executor.SourceSQL(context.Background(), hardeningAccess(), "ws_alpha", workspaceapi.SourceSQLRequest{
		SourceID: target.SourceID, SQL: "SELECT 1",
	})
	if workspaceapi.SourceSQLRefusalCode(err) != string(governedquery.CodeSourceSQLConcurrencyLimited) {
		t.Fatalf("third concurrent call = %v, want %s", err, governedquery.CodeSourceSQLConcurrencyLimited)
	}
	if resolver.calls != 0 {
		t.Fatalf("an over-limit call resolved the credential %d times", resolver.calls)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("over-limit call audited %d events, want 1", len(auditor.events))
	}
}

func TestSourceSQLRateLimitRefusesTheTwentyFirstCall(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	executor := newHardeningExecutor(workspace, auditor, &fakeSourceSQLResolver{}, &fakeSourceSQLRoots{})
	now := time.Unix(1_700_000_000, 0)
	executor.limiter.now = func() time.Time { return now }
	for call := 0; call < sourceSQLMaxExecutionsPerMinute; call++ {
		release, code := executor.limiter.acquire(target.SourceID, "usr_alice")
		if code != "" {
			t.Fatalf("call %d refused before the bound: %s", call+1, code)
		}
		release()
	}
	_, err := executor.SourceSQL(context.Background(), hardeningAccess(), "ws_alpha", workspaceapi.SourceSQLRequest{
		SourceID: target.SourceID, SQL: "SELECT 1",
	})
	if workspaceapi.SourceSQLRefusalCode(err) != string(governedquery.CodeSourceSQLRateLimited) {
		t.Fatalf("twenty-first call = %v, want %s", err, governedquery.CodeSourceSQLRateLimited)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("rate-limited call audited %d events, want 1", len(auditor.events))
	}
}

func TestSourceSQLLimiterReleaseAndWindowRestoreCapacity(t *testing.T) {
	limiter := newSourceSQLLimiter()
	now := time.Unix(1_700_000_000, 0)
	limiter.now = func() time.Time { return now }
	first, code := limiter.acquire("conn_1", "usr_1")
	second, code2 := limiter.acquire("conn_1", "usr_1")
	if code != "" || code2 != "" {
		t.Fatalf("first two acquires = %q, %q", code, code2)
	}
	if _, denied := limiter.acquire("conn_1", "usr_1"); denied != string(governedquery.CodeSourceSQLConcurrencyLimited) {
		t.Fatalf("third acquire = %q, want %s", denied, governedquery.CodeSourceSQLConcurrencyLimited)
	}
	first()
	reused, reusedCode := limiter.acquire("conn_1", "usr_1")
	if reusedCode != "" {
		t.Fatalf("after release = %q, want admission", reusedCode)
	}
	reused()
	second()
	// Advance the window: the earlier admissions no longer count.
	now = now.Add(2 * time.Minute)
	release, code := limiter.acquire("conn_1", "usr_1")
	if code != "" {
		t.Fatalf("after the window = %q, want admission", code)
	}
	release()
}

func TestSourceSQLAttemptIDIsTheAuditedEventID(t *testing.T) {
	auditor := &fakeSourceSQLAuditor{}
	executor := sourceSQLExecutor{auditor: auditor, now: time.Now}
	attempt := governedquery.Attempt{SQLHash: "sha256:" + strings.Repeat("a", 64), Outcome: governedquery.OutcomeSucceeded}
	eventID, err := executor.auditAttempt(context.Background(), hardeningAccess(), "ws_alpha", readySourceSQLTarget(), "count", attempt, "")
	if err != nil {
		t.Fatalf("audit success attempt: %v", err)
	}
	if len(auditor.events) != 1 || eventID == "" || auditor.events[0].EventID != eventID {
		t.Fatalf("attempt id %q != audited event id %q", eventID, auditor.events[0].EventID)
	}
}

func TestSourceSQLAuditSurvivesClientCancellation(t *testing.T) {
	auditor := &fakeSourceSQLAuditor{}
	executor := sourceSQLExecutor{auditor: auditor, now: time.Now}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executor.auditAttempt(ctx, hardeningAccess(), "ws_alpha", readySourceSQLTarget(), "", governedquery.Attempt{}, string(governedquery.CodeTimeout)); err != nil {
		t.Fatalf("cancelled client suppressed the audit: %v", err)
	}
	if len(auditor.events) != 1 || auditor.ctxError != nil {
		t.Fatalf("audit under cancellation = events=%d ctxErr=%v", len(auditor.events), auditor.ctxError)
	}
}
