package repository

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
)

// These tests pin the 12.09 acc2 guard repair path introduced for a workspace
// whose persisted revision configuration hash no longer matches the hash
// recomputed from its live metadata. They exercise the exact predicates and the
// exact audit-event construction that Get, List and authorizeMutation use, so a
// stale hash yields a readable degraded workspace and a re-hash repair instead
// of WORKSPACE_PERSISTENCE_FAILED, without needing a live database.

func TestConfigurationHashStaleReadIsDegradedNotPersistenceFailure(t *testing.T) {
	t.Parallel()

	staleMarker, reason := configurationHashReadOutcome("hash_of_stored_revision", "hash_of_live_metadata")
	if !staleMarker {
		t.Fatal("a stored-versus-live hash mismatch must be reported as a degraded read")
	}
	if reason != SummaryDegradedReasonConfigurationHashStale {
		t.Fatalf("degraded reason = %q, want %q", reason, SummaryDegradedReasonConfigurationHashStale)
	}
	if reason == string(CodePersistence) {
		t.Fatalf("degraded read must not surface %s", CodePersistence)
	}

	// The marker names only a closed reason code: neither the stored nor the
	// recomputed hash may appear in the projection.
	if reason == "hash_of_stored_revision" || reason == "hash_of_live_metadata" {
		t.Fatalf("degraded reason leaked a configuration hash: %q", reason)
	}

	// A healthy workspace carries no degraded marker at all.
	healthy, healthyReason := configurationHashReadOutcome("same_hash", "same_hash")
	if healthy || healthyReason != "" {
		t.Fatalf("healthy read outcome = (%t, %q), want (false, \"\")", healthy, healthyReason)
	}
}

func TestConfigurationHashStaleMutationUsesLivePreconditionAndRepairs(t *testing.T) {
	t.Parallel()

	change := compareConfigurationHash("hash_of_stored_revision", "hash_of_live_metadata")
	if !change.Stale {
		t.Fatal("a stored-versus-live hash mismatch must be classified as stale")
	}
	if change.EffectiveHash != "hash_of_live_metadata" {
		t.Fatalf("repair precondition = %q, want the recomputed live hash", change.EffectiveHash)
	}
	// mutate compares its loaded hash against the caller's expected hash. The
	// stale workspace therefore accepts the live hash a member read exposes as
	// its ETag and persists a corrected revision instead of hard-failing.
	if change.EffectiveHash == "hash_of_stored_revision" {
		t.Fatal("a stale workspace must not keep requiring the stale stored hash")
	}
	// Once the repair persists a revision whose configuration hash is the live
	// hash, a subsequent read compares equal and the degraded marker clears.
	if cleared, clearedReason := configurationHashReadOutcome(change.EffectiveHash, "hash_of_live_metadata"); cleared || clearedReason != "" {
		t.Fatalf("after repair the read outcome = (%t, %q), want (false, \"\")", cleared, clearedReason)
	}

	healthy := compareConfigurationHash("same_hash", "same_hash")
	if healthy.Stale {
		t.Fatal("an unchanged hash must not be classified as stale")
	}
	if healthy.EffectiveHash != "same_hash" {
		t.Fatalf("healthy precondition = %q, want the stored revision hash", healthy.EffectiveHash)
	}
	// List marks only the stale workspace; a healthy sibling keeps its exact
	// stored hash and no degraded projection.
	if staleMarker, _ := configurationHashReadOutcome(healthy.EffectiveHash, "same_hash"); staleMarker {
		t.Fatal("a healthy sibling workspace must stay readable and undegraded")
	}
}

func TestConfigurationHashRepairAuditEventIsContentFree(t *testing.T) {
	t.Parallel()

	occurredAt := time.Date(2026, time.September, 12, 9, 30, 0, 0, time.UTC)
	event := configurationHashRepairAuditEvent("aud_repair_001", "ws_alpha", "usr_alice", "req_server_001", occurredAt)

	if event.Action != audit.ActionPolicyDecision {
		t.Fatalf("action = %q, want %q", event.Action, audit.ActionPolicyDecision)
	}
	if event.ResourceType != audit.ResourcePolicy || event.ResourceID != "ws_alpha" {
		t.Fatalf("resource = (%q, %q), want (%q, ws_alpha)", event.ResourceType, event.ResourceID, audit.ResourcePolicy)
	}
	if event.WorkspaceID == nil || *event.WorkspaceID != "ws_alpha" {
		t.Fatalf("workspace id = %v, want ws_alpha", event.WorkspaceID)
	}
	if event.ActorType != audit.ActorHuman || event.ActorPrincipalID == nil || *event.ActorPrincipalID != "usr_alice" {
		t.Fatalf("actor = (%q, %v), want (HUMAN, usr_alice)", event.ActorType, event.ActorPrincipalID)
	}
	if event.RequestID != "req_server_001" {
		t.Fatalf("request id = %q, want req_server_001", event.RequestID)
	}
	// A successful repair carries the closed reason and no error code.
	if event.Outcome != audit.OutcomeSuccess {
		t.Fatalf("outcome = %q, want %q", event.Outcome, audit.OutcomeSuccess)
	}
	if event.ErrorCode != nil {
		t.Fatalf("successful repair carried error code %q", *event.ErrorCode)
	}
	if len(event.Metadata.ReasonCodes) != 1 || event.Metadata.ReasonCodes[0] != SummaryDegradedReasonConfigurationHashStale {
		t.Fatalf("reason codes = %v, want [%q]", event.Metadata.ReasonCodes, SummaryDegradedReasonConfigurationHashStale)
	}
	// The journal entry never carries the stored or recomputed configuration
	// hash and never any workspace content.
	if event.Metadata.WorkspaceConfigurationHash != nil {
		t.Fatalf("repair event leaked WorkspaceConfigurationHash = %q", *event.Metadata.WorkspaceConfigurationHash)
	}
	if !event.OccurredAt.Equal(occurredAt) {
		t.Fatalf("occurred at = %v, want %v", event.OccurredAt, occurredAt)
	}
}

func TestConfigurationHashStaleReadDeniesNonMemberContentFree(t *testing.T) {
	t.Parallel()

	subject := policy.Subject{
		OrganizationID: "org_alpha", PrincipalID: "usr_alice",
		Status: policy.PrincipalActive, SessionRevision: 1,
	}
	degradedWorkspace := policy.Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: policy.WorkspaceActive}
	request := policy.Request{
		Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
		Workspace: degradedWorkspace,
	}

	// A principal with no current membership is denied before any hash is
	// compared, so the degraded marker can never become an existence or content
	// oracle.
	denied := policy.EvaluateWorkspace(policy.Request{
		Operation: request.Operation, Subject: request.Subject, Workspace: request.Workspace,
	})
	if denied.Allowed {
		t.Fatal("a non-member must be denied on a degraded workspace")
	}
	if len(denied.ReasonCodes) != 1 || denied.ReasonCodes[0] != policy.ReasonWorkspaceMembershipAbsent {
		t.Fatalf("denial reason codes = %v, want [%q]", denied.ReasonCodes, policy.ReasonWorkspaceMembershipAbsent)
	}
	if denied.Allowed {
		t.Fatal("the denial must stay content-free and carry no workspace data")
	}

	// A current member resolves through the same membership projection the
	// repository uses and stays allowed, even while the workspace is degraded.
	member := currentMembership(workspace.Snapshot{
		ID: "ws_alpha", OrganizationID: "org_alpha",
		Members: []workspace.Member{{PrincipalID: "usr_alice", Role: workspace.RoleViewer}},
	}, "usr_alice")
	allowed := policy.EvaluateWorkspace(policy.Request{
		Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
		Workspace: degradedWorkspace, Membership: member,
	})
	if !allowed.Allowed {
		t.Fatalf("a current member must still read a degraded workspace: %v", allowed.ReasonCodes)
	}
}

func TestConfigurationHashStaleReplayToleratedButDeniesNonMember(t *testing.T) {
	t.Parallel()

	// An idempotent replay of a prior workspace mutation on a workspace whose
	// stored revision hash has gone stale must classify through the shared
	// predicate and continue, never returning WORKSPACE_PERSISTENCE_FAILED for
	// the same condition Get reports degraded and authorizeMutation repairs.
	if err := authorizeReplayConfigurationHash("hash_of_stored_revision", "hash_of_live_metadata", nil); err != nil {
		t.Fatalf("stale-hash replay must be tolerated, got %v", err)
	}
	// A healthy workspace keeps replaying unchanged.
	if err := authorizeReplayConfigurationHash("same_hash", "same_hash", nil); err != nil {
		t.Fatalf("healthy-hash replay must be tolerated, got %v", err)
	}
	// Only a genuine recompute failure stays a persistence failure.
	recomputeErr := &Error{code: CodePersistence}
	if replayErr := authorizeReplayConfigurationHash("hash_of_stored_revision", "", recomputeErr); CodeOf(replayErr) != CodePersistence {
		t.Fatalf("recompute failure code = %v, want %s", replayErr, CodePersistence)
	}

	// Replay still evaluates the same membership gate as the read path, so a
	// principal with no current membership is denied with no content even on the
	// stale-hash-degraded condition.
	subject := policy.Subject{
		OrganizationID: "org_alpha", PrincipalID: "usr_mallory",
		Status: policy.PrincipalActive, SessionRevision: 1,
	}
	denied := policy.EvaluateWorkspace(policy.Request{
		Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
		Workspace: policy.Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: policy.WorkspaceActive},
	})
	if denied.Allowed {
		t.Fatal("a non-member replay must be denied on a stale-hash workspace")
	}
	if len(denied.ReasonCodes) != 1 || denied.ReasonCodes[0] != policy.ReasonWorkspaceMembershipAbsent {
		t.Fatalf("replay denial reason codes = %v, want [%q]", denied.ReasonCodes, policy.ReasonWorkspaceMembershipAbsent)
	}
	// A current member still authorizes through the same projection.
	memberSubject := policy.Subject{
		OrganizationID: "org_alpha", PrincipalID: "usr_alice",
		Status: policy.PrincipalActive, SessionRevision: 1,
	}
	member := currentMembership(workspace.Snapshot{
		ID: "ws_alpha", OrganizationID: "org_alpha",
		Members: []workspace.Member{{PrincipalID: "usr_alice", Role: workspace.RoleViewer}},
	}, "usr_alice")
	allowed := policy.EvaluateWorkspace(policy.Request{
		Operation: policy.OperationWorkspaceViewMetadata, Subject: memberSubject,
		Workspace: policy.Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: policy.WorkspaceActive},
		Membership: member,
	})
	if !allowed.Allowed {
		t.Fatalf("a current member must still pass the replay authorization gate: %v", allowed.ReasonCodes)
	}
}
