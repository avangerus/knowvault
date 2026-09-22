package postgres_test

// B2.4g2c3a — the callable analytics source resolver refuses a valid newer
// governed-exposure artifact, plus the one shared refusal assertion the later
// resolver cards reuse.
//
// The proof starts from newMountedTypedAnalyticsResolverFixture's fully admitted
// and mounted typed analytics source, resolves it once as the baseline, and then
// appends revision 2 of that same connection's immutable exposure artifact
// through the existing seedGovernedExposureRevision. The drifted revision
// replaces only the exposed object's description, so its schema, relation and
// four ordered columns stay exact while its canonical full-artifact hash differs
// from revision 1's. The loader reads the latest revision, so the unchanged
// second Resolve over the same resolver, access context and request reads
// revision 2 and must return the exact zero Resolution and the one content-free
// refusal.
//
// This proves a valid newer immutable exposure artifact no longer matches the
// exposure selection of the mounted profile. It does not claim to isolate the
// exposure-revision mismatch from the full-artifact hash mismatch: revision 2
// moves both values at once.
//
// Deliberately not covered here: malformed persisted JSON or hashes, a missing
// relation or column, authority revocation, workspace revision mutation, the
// live-queries flag, remounting or reconstructing the resolver, direct
// repository reads, concurrent interleaving, revalidating the baseline
// Resolution, SQL execution, and the Question/MCP/UI wiring.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

// callableResolverRefusalText is the exact content-free refusal
// analyticsource.Resolver.Resolve returns for every refused resolution.
const callableResolverRefusalText = "analyticsource: facts do not match approved projection"

// assertCallableResolverRefusal requires one analyticsource.Resolver.Resolve
// attempt to be exactly the one content-free refusal: a non-nil error whose
// whole text is the exact refusal with no unwrap chain, plus the exact zero
// Resolution, which reports invalid and marshals to the opaque empty JSON
// object. label names the attempt in every diagnostic.
func assertCallableResolverRefusal(t *testing.T, label string, result analyticsource.Resolution, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: resolve returned %#v, want the content-free refusal", label, result)
	}
	if err.Error() != callableResolverRefusalText {
		t.Fatalf("%s: refusal error = %q, want %q", label, err.Error(), callableResolverRefusalText)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("%s: refusal wraps %v, want the exact unwrapped refusal", label, unwrapped)
	}
	if !reflect.DeepEqual(result, analyticsource.Resolution{}) {
		t.Fatalf("%s: refused resolution = %#v, want the exact zero analyticsource.Resolution{}", label, result)
	}
	if result.Valid() {
		t.Fatalf("%s: the refused resolution reports Valid", label)
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatalf("%s: marshal the refused resolution: %v", label, marshalErr)
	}
	if string(encoded) != "{}" {
		t.Fatalf("%s: refused resolution marshaled to %s, want {}", label, encoded)
	}
}

// TestTypedAnalyticsResolverRefusesAfterExposureRevisionDrift proves a valid
// newer immutable exposure artifact no longer matches the exposure selection of
// the mounted profile. The baseline Resolve accepts the fixture's live exposure
// revision 1; appending revision 2 with one different object description — and
// therefore a different canonical full-artifact hash, while its schema, relation
// and four ordered columns stay exact — leaves the resolver, the access context,
// the request, the pinned connection identity and the enabled workspace binding
// untouched, so the unchanged second Resolve of the same source must return the
// exact zero Resolution and the one content-free refusal.
func TestTypedAnalyticsResolverRefusesAfterExposureRevisionDrift(t *testing.T) {
	ctx := context.Background()
	fixture, resolver, request := newMountedTypedAnalyticsResolverFixture(t)

	baseline, err := resolver.Resolve(ctx, fixture.access, request)
	if err != nil {
		t.Fatalf("resolve the mounted typed analytics source before the exposure revision drift: %v", err)
	}
	if !baseline.Valid() {
		t.Fatal("baseline typed analytics resolution is not valid")
	}

	// The connection the drifted revision belongs to is a direct-control fact of
	// the fixture's exact current scope revision row, so it is read here rather
	// than derived from the fixture, the mount document or the seeded exposure.
	var connectionID string
	var connectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id, connection_revision
		  FROM public.source_scope_revision
		 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		fixture.binding.organizationID, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&connectionID, &connectionRevision); err != nil {
		t.Fatalf("direct control read of the typed analytics source connection: %v", err)
	}
	if connectionID == "" || connectionRevision < 1 {
		t.Fatalf("direct control read returned connection id %q at revision %d, want a non-empty id at a positive pinned revision",
			connectionID, connectionRevision)
	}

	// Revision 2 carries the same exposed object with one other valid
	// description, so the drift is exactly the artifact identity: the schema,
	// the relation and all four ordered columns stay the revision-1 values.
	originalObjects := []governedquery.ExposedObject{typedAnalyticsExposedObject()}
	driftedObjects := []governedquery.ExposedObject{typedAnalyticsExposedObject()}
	driftedObjects[0].Description = "Typed analytics operations exposed for governed queries at revision two."
	if driftedObjects[0].SchemaName != originalObjects[0].SchemaName ||
		driftedObjects[0].TableName != originalObjects[0].TableName ||
		!reflect.DeepEqual(driftedObjects[0].Columns, originalObjects[0].Columns) {
		t.Fatalf("revision-2 exposure object = %#v, want only the description changed from %#v",
			driftedObjects[0], originalObjects[0])
	}
	if driftedObjects[0].Description == originalObjects[0].Description {
		t.Fatalf("revision-2 exposure description = %q, want a different valid text",
			driftedObjects[0].Description)
	}

	// Both revisions are canonicalized and hashed here, before either one is
	// persisted, so the persisted hashes are never the source of the expected
	// values.
	originalCanonical, err := canon.CanonicalJSON(originalObjects)
	if err != nil {
		t.Fatalf("canonicalize the revision-1 typed analytics exposure inventory: %v", err)
	}
	driftedCanonical, err := canon.CanonicalJSON(driftedObjects)
	if err != nil {
		t.Fatalf("canonicalize the revision-2 typed analytics exposure inventory: %v", err)
	}
	originalHash := canon.Hash(originalCanonical)
	driftedHash := canon.Hash(driftedCanonical)
	if originalHash == driftedHash {
		t.Fatalf("revision-2 exposure artifact hash = %s, want a hash distinct from the revision-1 hash %s",
			driftedHash, originalHash)
	}

	seededHash := seedGovernedExposureRevision(t, ctx, fixture, connectionID, 2, driftedObjects)
	if seededHash != driftedHash {
		t.Fatalf("seeded revision-2 exposure artifact hash = %s, want the independently computed %s",
			seededHash, driftedHash)
	}

	// Control read only: the latest stored artifact is revision 2, carries the
	// drifted hash and holds exactly the drifted inventory.
	var latestRevision int64
	var latestHash string
	var latestContentEqual bool
	if err := fixture.admin.QueryRow(ctx, `
		SELECT revision, revision_hash, objects_json = $3::jsonb
		FROM public.governed_query_exposed_schema
		WHERE organization_id = $1 AND connection_id = $2
		ORDER BY revision DESC
		LIMIT 1`,
		fixture.binding.organizationID, connectionID, string(driftedCanonical)).
		Scan(&latestRevision, &latestHash, &latestContentEqual); err != nil {
		t.Fatalf("direct control read of the latest typed analytics exposure revision: %v", err)
	}
	if latestRevision != 2 || latestHash != driftedHash || !latestContentEqual {
		t.Fatalf("latest stored exposure revision = %d hash = %s content-equal = %v, want revision 2, the drifted hash %s and equal content",
			latestRevision, latestHash, latestContentEqual, driftedHash)
	}

	// The drift leaves the workspace's own opt-in untouched, so the refusal
	// below cannot come from a disabled live-queries binding.
	var liveQueriesEnabled bool
	if err := fixture.admin.QueryRow(ctx, `
		SELECT live_queries_enabled
		  FROM public.governed_query_workspace_binding
		 WHERE organization_id = $1 AND connection_id = $2 AND workspace_id = $3`,
		fixture.binding.organizationID, connectionID, fixture.binding.workspaceID).
		Scan(&liveQueriesEnabled); err != nil {
		t.Fatalf("direct control read of the typed analytics governed query workspace binding: %v", err)
	}
	if !liveQueriesEnabled {
		t.Fatal("the governed query workspace binding disabled live queries, want the fixture's enabled binding")
	}

	// The drifted artifact is no match for the exposure selection of the mounted
	// profile: the same resolver, access context and request return the exact
	// zero Resolution and the one content-free refusal.
	refused, err := resolver.Resolve(ctx, fixture.access, request)
	assertCallableResolverRefusal(t, "resolve after the exposure revision drift", refused, err)
}
