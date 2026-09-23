package postgres_test

// B2.4g2b — the callable analytics source resolver, its one positive
// real-PostgreSQL proof, and the one revocation proof that a successful
// resolution is not cached authority for the next one.
//
// The positive proof starts from newTypedAnalyticsAuthorityFixture's fully
// admitted typed analytics POSTGRESQL_QUERY source and seeds the exact typed
// governed exposure for that source through seedTypedGovernedExposureReadSurface.
// It then mounts the one active typed analytics catalog over the independently
// controlled facts of the same source: the connection identity read directly
// from the fixture's exact current scope revision row, the full-artifact hash of
// the seeded inventory, the registered database, lineage, revision and contract
// identity, and the registered schema, relation and VIEW kind. The catalog is
// sealed by newTypedAnalyticsCatalogFixture and loaded only through the
// production mount loader, and the request names the fixture workspace plus that
// loaded catalog's own identity and its one resolved active profile.
//
// The production path under proof is exactly one call:
// analyticsource.Resolver.Resolve performs all three separately authorized
// reads itself, so this test calls no authority or exposure method directly;
// existing fixture setup may perform its own precondition check. The production
// resolution itself passes only through Resolver.Resolve and must return no
// error and a valid opaque Resolution for an admitted, exposed, actively mounted
// source.
//
// The revocation proof starts from the same mounted fixture, resolves it once
// while the fixture's workspace-managed confirmation is live, and then revokes
// that exact confirmation through the production revocation command. The source
// is no longer authorized, so the second Resolve over the unchanged resolver,
// access context and request must return the exact zero Resolution and the one
// content-free refusal. The earlier baseline Resolution is deliberately not
// re-examined: Valid checks its own seal, not current authority.
//
// Deliberately not covered here: the authority and exposure facts themselves
// (the prior fixture proofs own them), SQL execution against the pinned
// connection, runtime freshness, an atomic-snapshot claim, mount provenance,
// the remaining negative matrix and Question/MCP/UI wiring.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// newMountedTypedAnalyticsResolverFixture performs the complete positive setup
// both resolver proofs start from and takes no scenario parameters. It admits
// the typed analytics authority fixture, seeds the typed governed exposure for
// the fixture's pinned connection, reads that connection identity and revision
// directly from the fixture's exact current scope revision row, builds the exact
// analytic.SourceProjectionInput from those independently controlled facts,
// seals the typed analytics catalog, mounts it through the production mount
// loader, resolves its one active profile, and returns the fixture, a resolver
// bound to the retained store and the loaded catalog, and the exact request
// naming that catalog and profile.
func newMountedTypedAnalyticsResolverFixture(t *testing.T) (
	admittedAuthorityFixture,
	*analyticsource.Resolver,
	analyticsource.ResolveRequest,
) {
	t.Helper()
	ctx := context.Background()
	fixture := newTypedAnalyticsAuthorityFixture(t)

	// The expected artifact hash covers the whole inventory the helper seeds, so
	// it is computed from that same slice before the canonical JSON and hash
	// pair is persisted.
	objects := []governedquery.ExposedObject{typedAnalyticsExposedObject()}
	canonicalBytes, err := canon.CanonicalJSON(objects)
	if err != nil {
		t.Fatalf("canonicalize typed analytics governed exposure artifact: %v", err)
	}
	artifactHash := canon.Hash(canonicalBytes)
	const exposureRevision = int64(1)

	seededExposure := seedTypedGovernedExposureReadSurface(t, ctx, fixture,
		typedAnalyticsDatabaseIdentity, objects)

	// The pinned connection is a direct-control fact of the fixture's exact
	// current scope revision row, so it is read here rather than derived from
	// the fixture, the mount document or the seeded exposure lookup.
	var pinnedConnectionID string
	var pinnedConnectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id, connection_revision
		  FROM public.source_scope_revision
		 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		fixture.binding.organizationID, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&pinnedConnectionID, &pinnedConnectionRevision); err != nil {
		t.Fatalf("direct control read of the typed analytics source connection: %v", err)
	}
	if pinnedConnectionID == "" || pinnedConnectionRevision < 1 {
		t.Fatalf("direct control read returned connection id %q at revision %d, want a non-empty id at a positive pinned revision",
			pinnedConnectionID, pinnedConnectionRevision)
	}
	if seededExposure.ConnectionID != pinnedConnectionID {
		t.Fatalf("seeded governed exposure lookup connection = %q, want the independently pinned %q",
			seededExposure.ConnectionID, pinnedConnectionID)
	}

	// Every member of the source input is one independently controlled fact:
	// the admitted scope, the directly read pinned connection, the registered
	// database/lineage/revision/contract identity, the exposure revision and
	// full-artifact hash of the seeded inventory, and the registered schema,
	// relation and VIEW kind.
	sourceInput := analytic.SourceProjectionInput{
		SourceScopeID:          fixture.request.SourceScopeID,
		ConnectionID:           pinnedConnectionID,
		DatabaseIdentity:       typedAnalyticsDatabaseIdentity,
		ProjectionLineageID:    typedAnalyticsLineage,
		ProjectionRevision:     typedAnalyticsProjectionRevision,
		ProjectionContractHash: typedAnalyticsContractHash(),
		ExposedSchemaRevision:  exposureRevision,
		ExposedSchemaHash:      artifactHash,
		SchemaName:             typedAnalyticsSchema,
		RelationName:           typedAnalyticsRelation,
		RelationKind:           analytic.RelationView,
	}
	catalogFixture := newTypedAnalyticsCatalogFixture(t, sourceInput)
	loadedCatalog := catalogFixture.mountedCatalog(t)
	if !loadedCatalog.Valid() {
		t.Fatal("loaded typed analytics catalog is not valid")
	}
	profile, resolved := loadedCatalog.ResolveActive(catalogFixture.profile.Key(), catalogFixture.profile.Hash())
	if !resolved || !profile.Valid() {
		t.Fatalf("loaded typed analytics catalog resolved = %v for key %v hash %q, want the one valid active profile",
			resolved, catalogFixture.profile.Key(), catalogFixture.profile.Hash())
	}

	resolver, err := analyticsource.NewResolver(fixture.store, loadedCatalog)
	if err != nil {
		t.Fatalf("construct typed analytics resolver over the retained store and loaded catalog: %v", err)
	}
	request := analyticsource.ResolveRequest{
		WorkspaceID:     fixture.binding.workspaceID,
		CatalogID:       loadedCatalog.ID(),
		CatalogRevision: loadedCatalog.Revision(),
		CatalogHash:     loadedCatalog.Hash(),
		ProfileKey:      profile.Key(),
		ProfileHash:     profile.Hash(),
	}
	return fixture, resolver, request
}

// TestTypedAnalyticsResolverResolvesAdmittedExposedMountedSource proves one
// accepted request resolves the fixture's admitted, exposed and mounted source
// through Resolver.Resolve alone: the mounted catalog declares exactly the fact
// set the three reads return, so the sealed binding is produced, and Resolve
// reports no error and one valid opaque Resolution.
func TestTypedAnalyticsResolverResolvesAdmittedExposedMountedSource(t *testing.T) {
	ctx := context.Background()
	fixture, resolver, request := newMountedTypedAnalyticsResolverFixture(t)

	resolution, err := resolver.Resolve(ctx, fixture.access, request)
	if err != nil {
		t.Fatalf("resolve typed analytics source: %v", err)
	}
	if !resolution.Valid() {
		t.Fatal("resolved typed analytics source is not valid")
	}
}

// TestTypedAnalyticsResolverRefusesAfterManagedConfirmationRevocation proves a
// successful Resolve is not cached authority for the next one. After the exact
// live workspace-managed confirmation is revoked through the production command,
// the unchanged second Resolve over the same resolver, access context and
// request returns the exact zero Resolution and the one content-free refusal
// equal to no match against the approved projection. Revocation is append-only,
// so nothing is restored or re-confirmed here and cleanup belongs to the
// fixture reset.
func TestTypedAnalyticsResolverRefusesAfterManagedConfirmationRevocation(t *testing.T) {
	ctx := context.Background()
	fixture, resolver, request := newMountedTypedAnalyticsResolverFixture(t)

	baseline, err := resolver.Resolve(ctx, fixture.access, request)
	if err != nil {
		t.Fatalf("resolve the mounted typed analytics source before revocation: %v", err)
	}
	if !baseline.Valid() {
		t.Fatal("baseline typed analytics resolution is not valid")
	}

	// The live identity is a direct-control fact and must be the confirmation
	// the fixture issued, so the revocation cannot target a different row.
	confirmationID, confirmationHash := loadLiveManagedConfirmation(t, ctx, fixture.admin, fixture.binding)
	if confirmationID != fixture.confirmation.ResultID || confirmationHash != fixture.confirmation.ResultHash {
		t.Fatalf("live confirmation identity = %s/%s, want the fixture confirmation %s/%s",
			confirmationID, confirmationHash, fixture.confirmation.ResultID, fixture.confirmation.ResultHash)
	}

	revocation, err := fixture.store.RevokeManagedConfirmation(ctx,
		authorityAccess(fixture.binding, regOwner, "req_analyticsource_confirmation_revocation"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey:         authorityIdempotencyKey("analyticsource-confirmation-revocation"),
			OrganizationID:         fixture.binding.organizationID,
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

	// Control read only: the exact confirmation row is revoked, so the later
	// refusal cannot come from any other mutation this test performed.
	var revoked bool
	if err := fixture.admin.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.workspace_managed_grant_revocation AS revocation
			WHERE revocation.organization_id = $1
			  AND revocation.confirmation_id = $2
			  AND revocation.confirmation_hash = $3
		)`, fixture.binding.organizationID, confirmationID, confirmationHash).Scan(&revoked); err != nil {
		t.Fatalf("direct control read of the confirmation revocation: %v", err)
	}
	if !revoked {
		t.Fatal("the workspace-managed confirmation revocation row is missing")
	}

	// The revoked confirmation is no authority for the unchanged second call:
	// the same resolver, access context and request return the exact zero
	// Resolution and the one content-free refusal.
	refused, err := resolver.Resolve(ctx, fixture.access, request)
	if err == nil {
		t.Fatalf("resolve after confirmation revocation returned %#v, want the content-free refusal", refused)
	}
	if err.Error() != "analyticsource: facts do not match approved projection" {
		t.Fatalf("resolve after confirmation revocation error = %q, want the exact content-free refusal", err.Error())
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("refusal wraps %v, want the exact unwrapped refusal", unwrapped)
	}
	if !reflect.DeepEqual(refused, analyticsource.Resolution{}) {
		t.Fatalf("refused resolution = %#v, want the exact zero analyticsource.Resolution{}", refused)
	}
	if refused.Valid() {
		t.Fatal("the refused resolution reports Valid")
	}
	encoded, marshalErr := json.Marshal(refused)
	if marshalErr != nil {
		t.Fatalf("marshal the refused resolution: %v", marshalErr)
	}
	if string(encoded) != "{}" {
		t.Fatalf("refused resolution marshaled to %s, want {}", encoded)
	}
}
