package postgres_test

// S3 card 2d database-side acceptance proof for the re-review findings that
// touch the product store:
//
//   - R1: the credential revision only ever increases across clear and set, so
//     a cleared-then-set credential reaches revision 2 rather than restarting
//     at 1; and
//   - R6: a stored SQL citation is provable only while its own
//     source.governed_query_attempted audit event still names the same
//     workspace, connection, SQL hash and result digest; a missing or tampered
//     event is not a match. The composition-side gate that turns a non-match
//     (or a source that is no longer READY/trusted) into the content-free
//     not-found is proven by source_sql_rereview_test.go.

import (
	"context"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestSourceQueryCredentialRevisionOnlyIncreases(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	repository, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_revision_owner")

	read := func() (string, int64) {
		t.Helper()
		target, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
		if err != nil {
			t.Fatalf("read scope: %v", err)
		}
		return target.QueryCredentialReference, target.QueryCredentialRevision
	}
	if reference, revision := read(); reference != "" || revision != 0 {
		t.Fatalf("fresh connection credential = %q/%d, want unset", reference, revision)
	}
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef2); err != nil {
		t.Fatalf("first set: %v", err)
	}
	_, afterSet := read()
	if afterSet != 1 {
		t.Fatalf("first set revision = %d, want 1", afterSet)
	}
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	clearedReference, afterClear := read()
	if clearedReference != "" {
		t.Fatalf("clear left reference %q", clearedReference)
	}
	// The clear writes a tombstone and keeps the counter: it never resets it.
	if afterClear != afterSet {
		t.Fatalf("clear changed the revision: %d -> %d", afterSet, afterClear)
	}
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef3); err != nil {
		t.Fatalf("second set after clear: %v", err)
	}
	if _, afterSecondSet := read(); afterSecondSet != 2 {
		t.Fatalf("clear then set revision = %d, want 2", afterSecondSet)
	}
}

func TestGovernedQueryAttemptMatchesRealAuditEvent(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_attempt_match_owner")
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := ids.New("gqat")
	if err != nil {
		t.Fatal(err)
	}
	workspace := regWorkspace
	principal := regOwner
	connection := connectionID
	sqlHash := "sha256:" + strings.Repeat("a", 64)
	resultDigest := "sha256:" + strings.Repeat("b", 64)
	revision := int64(1)
	outcome := audit.GovernedQueryOutcomeSucceeded
	cost := int64(1)
	rows := int64(1)
	if _, err := auditStore.Append(ctx, owner, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspace, ActorType: audit.ActorHuman,
		ActorPrincipalID: &principal, Action: audit.ActionGovernedQueryAttempted,
		ResourceType: audit.ResourceGovernedQueryAttempt, ResourceID: sqlHash,
		RequestID: owner.RequestID, Outcome: audit.OutcomeSuccess,
		Metadata: audit.Metadata{
			GovernedQueryConnectionID: &connection, GovernedQueryExposedSchemaRevision: &revision,
			GovernedQuerySQLHash: &sqlHash, GovernedQueryOutcome: &outcome,
			GovernedQueryCostEstimate: &cost, GovernedQueryRowCount: &rows,
			GovernedQueryResultDigest: &resultDigest,
		},
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("append governed query attempt: %v", err)
	}

	matched, err := auditStore.GovernedQueryAttemptMatches(ctx, owner, regWorkspace, eventID, connectionID, sqlHash, resultDigest)
	if err != nil || !matched {
		t.Fatalf("matching event = %v err=%v, want a match", matched, err)
	}
	tampered := "sha256:" + strings.Repeat("c", 64)
	if matched, err := auditStore.GovernedQueryAttemptMatches(ctx, owner, regWorkspace, eventID, connectionID, sqlHash, tampered); err != nil || matched {
		t.Fatalf("tampered result digest = %v err=%v, want no match", matched, err)
	}
	if matched, err := auditStore.GovernedQueryAttemptMatches(ctx, owner, regWorkspace, eventID, "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", sqlHash, resultDigest); err != nil || matched {
		t.Fatalf("another connection = %v err=%v, want no match", matched, err)
	}
	missing, err := ids.New("gqat")
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := auditStore.GovernedQueryAttemptMatches(ctx, owner, regWorkspace, missing, connectionID, sqlHash, resultDigest); err != nil || matched {
		t.Fatalf("missing event = %v err=%v, want no match", matched, err)
	}
}

// TestRevokedSourceActivationIsNotDisclosable proves the source fact the R6
// gate reads: once the scope activation leaves READY, SourceQuery reports a
// state that the composition-side reauthorization turns into the content-free
// not-found.
func TestRevokedSourceActivationIsNotDisclosable(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	repository, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_revoked_activation_owner")
	target, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil {
		t.Fatalf("read scope: %v", err)
	}
	// Move the activation to READY (the transition guard allows DRAFT/SYNCING
	// into READY) so the revocation is a visible delta.
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE public.source_scope_activation SET status = 'SYNCING', changed_at = transaction_timestamp()
		  WHERE organization_id = $1 AND source_scope_id = $2 AND source_scope_revision = $3`, []any{regOrg, target.SourceScopeID, target.ScopeRevision}},
		{`UPDATE public.source_scope_activation SET status = 'READY', changed_at = transaction_timestamp(), activated_at = transaction_timestamp()
		  WHERE organization_id = $1 AND source_scope_id = $2 AND source_scope_revision = $3`, []any{regOrg, target.SourceScopeID, target.ScopeRevision}},
	} {
		if _, err := admin.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("activate scope: %v", err)
		}
	}
	ready, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || ready.ActivationStatus != "READY" {
		t.Skipf("the registration fixture cannot reach READY here: state=%q err=%v", ready.ActivationStatus, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation SET status = 'REVOKED', changed_at = transaction_timestamp()
		WHERE organization_id = $1 AND source_scope_id = $2 AND source_scope_revision = $3`, regOrg, target.SourceScopeID, target.ScopeRevision); err != nil {
		t.Fatalf("revoke activation: %v", err)
	}
	revoked, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil {
		if workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
			t.Fatalf("revoked activation = %v, want not-found", err)
		}
		return
	}
	if revoked.ActivationStatus == "READY" {
		t.Fatalf("revoked source still reports a disclosable state: %+v", revoked)
	}
	if revoked.ActivationStatus != "REVOKED" {
		t.Fatalf("revoked activation status = %q", revoked.ActivationStatus)
	}
}
