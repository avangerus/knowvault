package composition

// source_sql_rereview_test.go is card S3.2d's focused proof for the two
// composition-boundary findings the re-review raised:
//
//   - R6: a stored SQL citation is disclosed only while its own audit event
//     still names the same workspace/connection/hash/digest and the source is
//     still active and trusted; and
//   - R7: every set/clear attempt that passed the OWNER gate writes exactly one
//     audit event (the composition audits a refusal, the repository audits a
//     success), the credential checks share the SQL limiter, and a limiter
//     refusal writes at most one event.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const rereviewCredentialReference = "cred_01ARZ3NDEKTSV4RRFFQ69G5FAV"

func rereviewDisclosure(target workspacerepository.SourceQuerySource) question.SourceSQLAttemptDisclosure {
	return question.SourceSQLAttemptDisclosure{
		AttemptID: "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ", ConnectionID: target.SourceID,
		SQLHash: "sha256:" + strings.Repeat("a", 64), ExposedSchemaRevision: target.ScopeRevision,
		ResultDigest: "sha256:" + strings.Repeat("b", 64),
	}
}

func TestReauthorizeSourceSQLAttemptRequiresLiveAuditAndActiveSource(t *testing.T) {
	base := readySourceSQLTarget()
	disclosure := rereviewDisclosure(base)
	access := hardeningAccess()

	cases := []struct {
		name           string
		mutate         func(*fakeSourceSQLWorkspace, *fakeSourceSQLAuditor)
		wantErr        bool
		wantMatchCalls int
	}{
		{
			name:           "audit event matches and source is READY",
			mutate:         func(*fakeSourceSQLWorkspace, *fakeSourceSQLAuditor) {},
			wantErr:        false,
			wantMatchCalls: 1,
		},
		{
			name: "audit event missing",
			mutate: func(_ *fakeSourceSQLWorkspace, auditor *fakeSourceSQLAuditor) {
				auditor.attemptMatched = false
			},
			wantErr:        true,
			wantMatchCalls: 1,
		},
		{
			name: "tampered result digest",
			mutate: func(_ *fakeSourceSQLWorkspace, auditor *fakeSourceSQLAuditor) {
				auditor.attemptMatched = false
			},
			wantErr:        true,
			wantMatchCalls: 1,
		},
		{
			name: "audit lookup failure",
			mutate: func(_ *fakeSourceSQLWorkspace, auditor *fakeSourceSQLAuditor) {
				auditor.matchErr = errors.New("journal unavailable")
			},
			wantErr:        true,
			wantMatchCalls: 1,
		},
		{
			name: "activation revoked",
			mutate: func(workspace *fakeSourceSQLWorkspace, _ *fakeSourceSQLAuditor) {
				workspace.target.ActivationStatus = "REVOKED"
			},
			wantErr:        true,
			wantMatchCalls: 0,
		},
		{
			name: "trust revoked",
			mutate: func(workspace *fakeSourceSQLWorkspace, _ *fakeSourceSQLAuditor) {
				workspace.target.TrustVerified = false
			},
			wantErr:        true,
			wantMatchCalls: 0,
		},
		{
			name: "scope revision moved",
			mutate: func(workspace *fakeSourceSQLWorkspace, _ *fakeSourceSQLAuditor) {
				workspace.target.ScopeRevision = base.ScopeRevision + 1
			},
			wantErr:        true,
			wantMatchCalls: 0,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			target := base
			workspace := &fakeSourceSQLWorkspace{target: target}
			auditor := &fakeSourceSQLAuditor{attemptMatched: true}
			testCase.mutate(workspace, auditor)
			executor := newHardeningExecutor(workspace, auditor, &fakeSourceSQLResolver{}, &fakeSourceSQLRoots{})
			err := executor.ReauthorizeSourceSQLAttempt(context.Background(), access, "ws_alpha", disclosure)
			if testCase.wantErr && err == nil {
				t.Fatal("a stale or unproven receipt was disclosed")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("a live receipt was refused: %v", err)
			}
			if auditor.matchCalls != testCase.wantMatchCalls {
				t.Fatalf("audit lookups = %d, want %d", auditor.matchCalls, testCase.wantMatchCalls)
			}
		})
	}
}

func TestSourceQueryCredentialLimiterRefusalIsAuditedOnce(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	resolver := &fakeSourceSQLResolver{dsn: "postgres://user:pass@db.example/customer?sslmode=verify-full"}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	first, code := executor.limiter.acquire(target.SourceID, hardeningAccess().PrincipalID)
	if code != "" {
		t.Fatalf("first acquire = %s", code)
	}
	second, code := executor.limiter.acquire(target.SourceID, hardeningAccess().PrincipalID)
	if code != "" {
		t.Fatalf("second acquire = %s", code)
	}
	defer first()
	defer second()

	err := executor.SetSourceQueryCredential(context.Background(), hardeningAccess(), "ws_alpha", target.SourceID, rereviewCredentialReference)
	if workspaceapi.SourceQueryCredentialRefusalCode(err) != string(governedquery.CodeSourceSQLConcurrencyLimited) {
		t.Fatalf("limiter refusal = %v, want %s", err, governedquery.CodeSourceSQLConcurrencyLimited)
	}
	if resolver.calls != 0 || workspace.setCalls != 0 {
		t.Fatalf("an over-limit credential control reached the outside world: resolver=%d writes=%d", resolver.calls, workspace.setCalls)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("over-limit control audited %d events, want exactly 1", len(auditor.events))
	}
	event := auditor.events[0]
	if event.Action != audit.ActionSourceQueryCredentialSet || event.Outcome != audit.OutcomeFailed ||
		event.ErrorCode == nil || *event.ErrorCode != string(governedquery.CodeSourceSQLConcurrencyLimited) {
		t.Fatalf("over-limit control event = %+v", event)
	}
}

func TestSourceQueryCredentialCandidateRefusalIsAuditedOnce(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	resolver := &fakeSourceSQLResolver{err: errors.New("unresolved")}
	executor := newHardeningExecutor(workspace, auditor, resolver, &fakeSourceSQLRoots{})

	err := executor.SetSourceQueryCredential(context.Background(), hardeningAccess(), "ws_alpha", target.SourceID, rereviewCredentialReference)
	if workspaceapi.SourceQueryCredentialRefusalCode(err) != workspaceapi.SourceQueryCredentialUnresolved {
		t.Fatalf("candidate refusal = %v, want %s", err, workspaceapi.SourceQueryCredentialUnresolved)
	}
	if resolver.calls != 1 || workspace.setCalls != 0 {
		t.Fatalf("refused candidate was written: resolver=%d writes=%d", resolver.calls, workspace.setCalls)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("refused candidate audited %d events, want exactly 1", len(auditor.events))
	}
	event := auditor.events[0]
	if event.Action != audit.ActionSourceQueryCredentialSet || event.Outcome != audit.OutcomeFailed ||
		event.ErrorCode == nil || *event.ErrorCode != workspaceapi.SourceQueryCredentialUnresolved {
		t.Fatalf("refused candidate event = %+v", event)
	}
}

// TestSourceQueryCredentialClearDelegatesTheSingleAuditEvent proves the success
// path stays exactly one event: the composition does not append its own, the
// repository's own audited write is the one.
func TestSourceQueryCredentialClearDelegatesTheSingleAuditEvent(t *testing.T) {
	target := readySourceSQLTarget()
	workspace := &fakeSourceSQLWorkspace{target: target}
	auditor := &fakeSourceSQLAuditor{}
	executor := newHardeningExecutor(workspace, auditor, &fakeSourceSQLResolver{}, &fakeSourceSQLRoots{})

	if err := executor.SetSourceQueryCredential(context.Background(), hardeningAccess(), "ws_alpha", target.SourceID, ""); err != nil {
		t.Fatalf("clear = %v", err)
	}
	if workspace.setCalls != 1 {
		t.Fatalf("clear writes = %d, want 1", workspace.setCalls)
	}
	if len(auditor.events) != 0 {
		t.Fatalf("the composition appended %d extra events for a delegated clear", len(auditor.events))
	}
}
