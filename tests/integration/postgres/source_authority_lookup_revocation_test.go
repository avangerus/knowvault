package postgres_test

// B2.2b2a — a lookup candidate is never a durable authorization token.
//
// Store.ResolvePostgreSQLAuthorityRequest returns only a candidate: the exact
// workspace/scope/connection identity that Store.ResolvePostgreSQLAuthority
// must still re-authorize against the live workspace-managed confirmation.
// This card proves the security consequence against real PostgreSQL 18.4: once
// the candidate has been saved, revoking its confirmation through the
// production authority command makes the resolver reject that saved candidate
// with the same content-free NOT_FOUND surface as an unknown source.
//
// The revocation is a production repository command, never a direct authority
// table mutation. Direct-control SQL only reads the exact connection identity
// and proves the confirmation is revoked; it is never application authority.
// No connector is called and no source SQL query is executed.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestPostgreSQLSourceAuthorityLookupCandidateIsRejectedAfterConfirmationRevocation(t *testing.T) {
	ctx := context.Background()
	fixture := newAdmittedAuthorityFixture(t)

	// The exact connection identity is one direct-control fact, read from the
	// same source scope row used by source_authority_lookup_test.go.
	var directConnectionID string
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id
		FROM public.source_scope
		WHERE organization_id = $1 AND id = $2`,
		regOrg, fixture.request.SourceScopeID).Scan(&directConnectionID); err != nil {
		t.Fatalf("direct control read of the source scope connection: %v", err)
	}
	if directConnectionID == "" {
		t.Fatal("direct control read returned an empty connection id")
	}

	// 1. The lookup yields the exact admitted request as a candidate, and the
	// candidate is saved unchanged.
	candidate, err := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access,
		workspacerepository.PostgreSQLAuthorityLookup{
			WorkspaceID:   fixture.request.WorkspaceID,
			SourceScopeID: fixture.request.SourceScopeID,
			ConnectionID:  directConnectionID,
		})
	if err != nil {
		t.Fatalf("lookup the admitted source: %v", err)
	}
	if candidate != fixture.request {
		t.Fatalf("lookup candidate = %#v, want the exact admitted request %#v", candidate, fixture.request)
	}

	// 2. Revoke the exact live confirmation through the production command. The
	// live identity is a direct-control fact and must be the confirmation the
	// fixture issued, so the revocation cannot target a different row.
	confirmationID, confirmationHash := loadLiveManagedConfirmation(t, ctx, fixture.admin, fixture.binding)
	if confirmationID != fixture.confirmation.ResultID || confirmationHash != fixture.confirmation.ResultHash {
		t.Fatalf("live confirmation identity = %s/%s, want the fixture confirmation %s/%s",
			confirmationID, confirmationHash, fixture.confirmation.ResultID, fixture.confirmation.ResultHash)
	}
	revocation, err := fixture.store.RevokeManagedConfirmation(ctx,
		authorityAccess(fixture.binding, regOwner, "req_lookup_candidate_confirmation_revocation"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey:         authorityIdempotencyKey("lookup-candidate-confirmation-revocation"),
			OrganizationID:         regOrg,
			WorkspaceID:            fixture.binding.workspaceID,
			ConfirmationID:         confirmationID,
			ConfirmationHash:       confirmationHash,
			ExpectedPolicyRevision: fixture.binding.policyID,
		})
	if err != nil {
		t.Fatalf("revoke the workspace-managed confirmation: %v", err)
	}
	if revocation.Operation != operationConfirmRevoke || revocation.ResultID == "" || revocation.ResultHash == "" {
		t.Fatalf("confirmation revocation result = %#v, want a %s result", revocation, operationConfirmRevoke)
	}
	// Control read only: the exact confirmation is now revoked, so the later
	// rejection cannot come from any other mutation this test performed.
	var revoked bool
	if err := fixture.admin.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.workspace_managed_grant_revocation AS revocation
			WHERE revocation.organization_id = $1
			  AND revocation.confirmation_id = $2
		)`, regOrg, confirmationID).Scan(&revoked); err != nil {
		t.Fatalf("direct control read of the confirmation revocation: %v", err)
	}
	if !revoked {
		t.Fatal("the workspace-managed confirmation was not revoked")
	}

	// 3. The saved candidate carried no durable authority: with the confirmation
	// revoked it collapses to the zero result and the content-free NOT_FOUND
	// surface, exposing no identifier, hash, source fact, SQL or credential.
	result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, candidate)
	assertAuthorityNotFound(t, result, err)
	surface := fmt.Sprintf("result=%#v error_type=%T error_value=%#v error_text=%q",
		result, err, err, err.Error())
	for _, marker := range []string{
		directConnectionID, candidate.WorkspaceID, candidate.WorkspaceSourceID,
		candidate.SourceScopeID, candidate.ScopeConfigHash,
		fixture.binding.workspaceID, fixture.binding.workspaceSourceID,
		fixture.binding.sourceScopeID, fixture.binding.scopeConfigHash,
		fixture.binding.workspaceConfHash,
		authorityCredentialSentinel, authorityDSNSentinel, authoritySQLSentinel,
		"postgres://", "postgresql://", "password", "credential", "dsn",
		"select ", "insert ", "update ", "delete ", "permission",
	} {
		if marker != "" && strings.Contains(strings.ToLower(surface), strings.ToLower(marker)) {
			t.Fatalf("revoked-candidate denial surface leaked %q: %s", marker, surface)
		}
	}
}
