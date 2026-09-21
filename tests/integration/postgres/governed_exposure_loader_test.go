package postgres_test

// B2.3c1: real-PostgreSQL positive/latest proof for the scope-bound
// governed-exposure loader, Store.ResolveGovernedExposure.
//
// The fixture is newAdmittedAuthorityFixture: the smallest fully admitted
// workspace-managed POSTGRESQL_QUERY source, created after its own database
// reset. This test reads the connection id the fixture's current scope revision
// pinned, seeds exactly the governed rows the loader rebinds -- the
// governed_query_connection, this exact workspace's
// governed_query_workspace_binding with live queries enabled, and exposed-schema
// revisions 1 and 2 -- and then resolves revision 2's requested relation through
// the production repository.
//
// Both artifacts are built through canon.CanonicalJSON and canon.Hash, the
// canonical JSON and hash pair internal/governedask.RegisterExposedSchema
// persists, so the loader's re-derived full-artifact hash is the persisted
// revision_hash byte for byte. Revision 2 carries a second, unrelated object and
// an operator-written unit: the returned result is only the requested relation's
// neutral projection while the hash covers the whole artifact.
//
// The absence case below is the same latest-selection behavior, not a second
// feature family: a relation only revision 1 holds is not in the latest
// revision-2 artifact, so requesting it answers the exact zero result with a
// cause-free CodeNotFound. The loader grants no execution right, so this proof
// dials no external database and executes no SQL against the pinned connection.
//
// B2.3c2 adds the opaque denial pair: the same fully seeded read surface with
// this workspace's live binding disabled, and an active organization MEMBER
// that holds no workspace membership. The two independent gates must collapse
// to the identical true-zero, cause-free CodeNotFound, so a caller can
// distinguish neither the disabled live flag nor the missing membership from
// any other unavailable lookup.
//
// B2.3c3 adds the malformed persisted-fact precedence pair: a latest artifact
// whose stored revision_hash is not the hash of the JSON stored beside it, and
// a stored database identity the application boundary deliberately refuses
// while the connection's only exposure artifact holds no requested relation.
// Both are malformed server facts, so both answer the identical true-zero,
// cause-free CodePersistence rather than the decoder's CodeNotFound.

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	// governedExposureDatabaseIdentity is the non-secret identity of the
	// governed-execution database this connection names.
	governedExposureDatabaseIdentity = "cluster-governed-exposure-positive"

	governedExposureSchema        = "reporting"
	governedExposureRelation      = "contracts"
	governedExposureStaleRelation = "retired_ledger"
	governedExposureOtherRelation = "counterparties"

	// governedExposureMalformedDatabaseIdentity is stored as the governed
	// connection's database identity by the B2.3c3 malformed-fact case: the
	// migration 000068 CHECK accepts it — 1..128 bytes, trimmed, no control
	// character — while the application boundary refuses the '/' character, so
	// the row itself is a legal persisted fact only that boundary rejects.
	governedExposureMalformedDatabaseIdentity = "cluster/governed-exposure-malformed"
)

// seedGovernedExposureRevision inserts one immutable exposed-schema revision of
// connectionID through the canonical JSON and hash pair production registration
// persists, and returns the exact revision_hash the loader must re-derive.
func seedGovernedExposureRevision(t *testing.T, ctx context.Context, fixture admittedAuthorityFixture, connectionID string, revision int64, objects []governedquery.ExposedObject) string {
	t.Helper()
	objectsJSON, err := canon.CanonicalJSON(objects)
	if err != nil {
		t.Fatalf("canonicalize governed exposure revision %d: %v", revision, err)
	}
	revisionHash := canon.Hash(objectsJSON)
	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.governed_query_exposed_schema
		    (organization_id, connection_id, revision, objects_json, revision_hash, created_by)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6)`,
		fixture.binding.organizationID, connectionID, revision, string(objectsJSON), revisionHash,
		fixture.binding.ownerID); err != nil {
		t.Fatalf("seed governed exposure revision %d: %v", revision, err)
	}
	return revisionHash
}

// assertGovernedExposureFailure requires one failed lookup to be exactly the
// content-free refusal — the true zero result, the opaque empty JSON object,
// the exact wanted code as the whole error text and no unwrap/cause chain — so
// every documented refusal, the ordinary absence and the malformed persisted
// fact alike, shares one observable surface and cannot drift into
// distinguishable failures.
func assertGovernedExposureFailure(t *testing.T, label string, result workspacerepository.GovernedExposureResult, err error, want workspacerepository.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: lookup unexpectedly resolved a governed exposure", label)
	}
	if result.Valid() ||
		result.WorkspaceID() != "" || result.WorkspaceRevision() != 0 ||
		result.WorkspaceConfigurationHash() != "" || result.WorkspaceSourceID() != "" ||
		result.SourceScopeID() != "" || result.SourceScopeRevision() != 0 ||
		result.SourceScopeConfigurationHash() != "" || result.ConnectionID() != "" ||
		result.ConnectionRevision() != 0 || result.DatabaseIdentity() != "" ||
		result.LiveQueryEnabled() || result.ExposureRevision() != 0 ||
		result.ExposureArtifactHash() != "" || result.SchemaName() != "" ||
		result.RelationName() != "" || result.Columns() != nil {
		t.Fatalf("%s: failure returned a non-zero result", label)
	}
	encoded, marshalErr := jsonv2.Marshal(result)
	if marshalErr != nil || string(encoded) != "{}" {
		t.Fatalf("%s: failure result JSON = %q err=%v, want the opaque empty object", label, encoded, marshalErr)
	}
	if code := workspacerepository.CodeOf(err); code != want {
		t.Fatalf("%s: failure code = %q, want %q", label, code, want)
	}
	if err.Error() != string(want) {
		t.Fatalf("%s: failure text = %q, want %q", label, err.Error(), want)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("%s: failure retained a cause: %v", label, unwrapped)
	}
}

// assertGovernedExposureNotFound requires one failed lookup to be the ordinary
// absence: that same content-free surface carrying the exact NOT_FOUND code, so
// the positive test's absence case and the two independent gates below stay one
// indistinguishable denial.
func assertGovernedExposureNotFound(t *testing.T, label string, result workspacerepository.GovernedExposureResult, err error) {
	t.Helper()
	assertGovernedExposureFailure(t, label, result, err, workspacerepository.CodeNotFound)
}

// assertGovernedExposurePersistence requires one failed lookup to be the
// malformed-persisted-fact refusal: that same content-free surface carrying the
// exact PERSISTENCE code, so a server fact this boundary rejects is never
// reclassified as the decoder's ordinary absence.
func assertGovernedExposurePersistence(t *testing.T, label string, result workspacerepository.GovernedExposureResult, err error) {
	t.Helper()
	assertGovernedExposureFailure(t, label, result, err, workspacerepository.CodePersistence)
}

// seedGovernedExposureReadSurface seeds the otherwise-valid governed read
// surface for the fixture's exact pinned connection — the governed connection,
// this workspace's binding with liveQueriesEnabled, and one canonical exposure
// revision holding the requested relation — and returns the lookup naming it,
// so a caller changes exactly one gate and nothing else.
func seedGovernedExposureReadSurface(
	t *testing.T, ctx context.Context, fixture admittedAuthorityFixture, liveQueriesEnabled bool,
) workspacerepository.GovernedExposureLookup {
	t.Helper()
	// The pinned connection is a fact of the fixture's exact current scope
	// chain, not of the lookup: read the same source_scope_revision row the
	// loader rebinds.
	var connectionID string
	var connectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id, connection_revision
		  FROM public.source_scope_revision
		 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		fixture.binding.organizationID, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&connectionID, &connectionRevision); err != nil {
		t.Fatalf("load pinned source connection: %v", err)
	}
	if connectionID == "" || connectionRevision < 1 {
		t.Fatalf("pinned source connection = %q revision %d, want a non-empty id at a positive revision",
			connectionID, connectionRevision)
	}

	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.governed_query_connection
		    (organization_id, id, workspace_id, database_identity, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
		governedExposureDatabaseIdentity, fixture.binding.ownerID); err != nil {
		t.Fatalf("seed governed query connection: %v", err)
	}
	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.governed_query_workspace_binding
		    (organization_id, connection_id, workspace_id, live_queries_enabled, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
		liveQueriesEnabled, fixture.binding.ownerID); err != nil {
		t.Fatalf("seed governed query workspace binding: %v", err)
	}
	seedGovernedExposureRevision(t, ctx, fixture, connectionID, 1, []governedquery.ExposedObject{{
		SchemaName:  governedExposureSchema,
		TableName:   governedExposureRelation,
		Description: "Executed contracts.",
		Columns: []governedquery.ExposedColumn{
			{Name: "contract_id", DataType: "text", Description: "Contract identifier."},
		},
	}})

	return workspacerepository.GovernedExposureLookup{
		WorkspaceID:   fixture.binding.workspaceID,
		SourceScopeID: fixture.request.SourceScopeID,
		ConnectionID:  connectionID,
		SchemaName:    governedExposureSchema,
		RelationName:  governedExposureRelation,
	}
}

func TestResolveGovernedExposureRealPostgreSQLPositiveLatest(t *testing.T) {
	ctx := context.Background()
	fixture := newAdmittedAuthorityFixture(t)

	// The pinned connection is a fact of the fixture's exact current scope
	// chain, not of the lookup: read the same source_scope_revision row the
	// loader rebinds.
	var connectionID string
	var connectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id, connection_revision
		  FROM public.source_scope_revision
		 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		fixture.binding.organizationID, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&connectionID, &connectionRevision); err != nil {
		t.Fatalf("load pinned source connection: %v", err)
	}

	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.governed_query_connection
		    (organization_id, id, workspace_id, database_identity, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
		governedExposureDatabaseIdentity, fixture.binding.ownerID); err != nil {
		t.Fatalf("seed governed query connection: %v", err)
	}
	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.governed_query_workspace_binding
		    (organization_id, connection_id, workspace_id, live_queries_enabled, created_by, updated_by)
		VALUES ($1, $2, $3, true, $4, $4)`,
		fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
		fixture.binding.ownerID); err != nil {
		t.Fatalf("seed governed query workspace binding: %v", err)
	}

	// Revision 1 is the inventory a later registration superseded: it holds the
	// relation revision 2 no longer carries.
	seedGovernedExposureRevision(t, ctx, fixture, connectionID, 1, []governedquery.ExposedObject{{
		SchemaName:  governedExposureSchema,
		TableName:   governedExposureStaleRelation,
		Description: "Ledger withdrawn from the latest exposure inventory.",
		Columns: []governedquery.ExposedColumn{
			{Name: "ledger_id", DataType: "text", Description: "Ledger identifier."},
		},
	}})
	revisionTwoHash := seedGovernedExposureRevision(t, ctx, fixture, connectionID, 2, []governedquery.ExposedObject{
		{
			SchemaName:  governedExposureSchema,
			TableName:   governedExposureRelation,
			Description: "Executed contracts.",
			Columns: []governedquery.ExposedColumn{
				{Name: "contract_id", DataType: "text", Description: "Contract identifier."},
				{Name: "amount", DataType: "numeric", Description: "Signed contract amount.", Unit: "EUR"},
				{Name: "signed_on", DataType: "date", Description: "Signature date."},
			},
		},
		{
			SchemaName:  governedExposureSchema,
			TableName:   governedExposureOtherRelation,
			Description: "Counterparties of the executed contracts.",
			Columns: []governedquery.ExposedColumn{
				{Name: "counterparty_id", DataType: "text", Description: "Counterparty identifier."},
			},
		},
	})

	lookup := workspacerepository.GovernedExposureLookup{
		WorkspaceID:   fixture.binding.workspaceID,
		SourceScopeID: fixture.request.SourceScopeID,
		ConnectionID:  connectionID,
		SchemaName:    governedExposureSchema,
		RelationName:  governedExposureRelation,
	}
	result, err := fixture.store.ResolveGovernedExposure(ctx, fixture.access, lookup)
	if err != nil {
		t.Fatalf("resolve governed exposure: %v (code=%s)", err, workspacerepository.CodeOf(err))
	}

	for _, scalar := range []struct {
		name string
		got  string
		want string
	}{
		{"workspace id", result.WorkspaceID(), fixture.binding.workspaceID},
		{"workspace configuration hash", result.WorkspaceConfigurationHash(), fixture.binding.workspaceConfHash},
		{"workspace source id", result.WorkspaceSourceID(), fixture.binding.workspaceSourceID},
		{"source scope id", result.SourceScopeID(), fixture.request.SourceScopeID},
		{"source scope configuration hash", result.SourceScopeConfigurationHash(), fixture.request.ScopeConfigHash},
		{"connection id", result.ConnectionID(), connectionID},
		{"database identity", result.DatabaseIdentity(), governedExposureDatabaseIdentity},
		{"exposure artifact hash", result.ExposureArtifactHash(), revisionTwoHash},
		{"schema", result.SchemaName(), governedExposureSchema},
		{"relation", result.RelationName(), governedExposureRelation},
	} {
		if scalar.got != scalar.want {
			t.Fatalf("%s = %q, want %q", scalar.name, scalar.got, scalar.want)
		}
	}
	for _, revision := range []struct {
		name string
		got  int64
		want int64
	}{
		{"workspace revision", result.WorkspaceRevision(), fixture.binding.workspaceRevision},
		{"source scope revision", result.SourceScopeRevision(), fixture.request.SourceScopeRevision},
		{"connection revision", result.ConnectionRevision(), connectionRevision},
		{"exposure revision", result.ExposureRevision(), 2},
	} {
		if revision.got != revision.want {
			t.Fatalf("%s = %d, want %d", revision.name, revision.got, revision.want)
		}
	}
	if !result.LiveQueryEnabled() {
		t.Fatal("live query flag = false, want this workspace's enabled binding")
	}
	if !result.Valid() {
		t.Fatal("resolved governed exposure result is not valid")
	}
	wantColumns := []string{"contract_id", "amount", "signed_on"}
	if columns := result.Columns(); !reflect.DeepEqual(columns, wantColumns) {
		t.Fatalf("columns = %v, want %v", columns, wantColumns)
	}
	encoded, marshalErr := jsonv2.Marshal(result)
	if marshalErr != nil || string(encoded) != "{}" {
		t.Fatalf("resolved result JSON = %q err=%v, want the opaque empty object", encoded, marshalErr)
	}

	// Every Columns call detaches, so a caller that mutates one returned slice
	// cannot reach the resolved result through it.
	mutated := result.Columns()
	for index := range mutated {
		mutated[index] = "mutated"
	}
	mutated = append(mutated, "appended")
	if columns := result.Columns(); !reflect.DeepEqual(columns, wantColumns) {
		t.Fatalf("columns after caller mutation = %v, want %v", columns, wantColumns)
	}

	// Revision 2 is latest for this connection, so the relation only revision 1
	// holds is an ordinary absence: the exact zero result and a cause-free
	// CodeNotFound.
	staleLookup := lookup
	staleLookup.RelationName = governedExposureStaleRelation
	staleResult, staleErr := fixture.store.ResolveGovernedExposure(ctx, fixture.access, staleLookup)
	assertGovernedExposureNotFound(t, "revision-1-only relation", staleResult, staleErr)
}

// TestResolveGovernedExposureRealPostgreSQLOpaqueDenials is B2.3c2: the same
// otherwise-valid read surface denied by two independent gates. Each case
// builds its own fixture, so the existing database reset keeps them
// independent, and each case changes exactly one fact — the workspace binding's
// live flag, or the caller's workspace membership. Both must answer the
// identical true-zero, cause-free CodeNotFound, so neither the disabled live
// flag nor the missing membership is an existence oracle.
func TestResolveGovernedExposureRealPostgreSQLOpaqueDenials(t *testing.T) {
	ctx := context.Background()

	t.Run("live binding disabled", func(t *testing.T) {
		fixture := newAdmittedAuthorityFixture(t)
		lookup := seedGovernedExposureReadSurface(t, ctx, fixture, false)
		result, err := fixture.store.ResolveGovernedExposure(ctx, fixture.access, lookup)
		assertGovernedExposureNotFound(t, "live binding disabled", result, err)
	})

	t.Run("active organization member without workspace membership", func(t *testing.T) {
		fixture := newAdmittedAuthorityFixture(t)
		lookup := seedGovernedExposureReadSurface(t, ctx, fixture, true)

		// The caller is an ACTIVE organization MEMBER of the fixture tenant —
		// the same actor seed source_authority_lookup_test.go uses for this
		// precondition — that deliberately receives no workspace_member row,
		// so the workspace snapshot it is admitted against holds no membership
		// for it.
		if _, err := fixture.admin.Exec(ctx, `
			INSERT INTO public.principal (id, organization_id, type, display_name, status)
			VALUES ($1, $2, 'USER', $1, 'ACTIVE')`,
			authorityLookupOrgMemberPrincipal, fixture.binding.organizationID); err != nil {
			t.Fatalf("seed active organization member principal: %v", err)
		}
		if _, err := fixture.admin.Exec(ctx, `
			INSERT INTO public.organization_role_assignment
				(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
			VALUES ($1, $2, $3, 'MEMBER', 1, $4)`,
			authorityLookupOrgMemberRoleID, fixture.binding.organizationID,
			authorityLookupOrgMemberPrincipal, fixture.binding.ownerID); err != nil {
			t.Fatalf("seed organization MEMBER role: %v", err)
		}
		// Control read of the exact seeded facts: the actor is ACTIVE and holds
		// the organization MEMBER role, yet holds no membership row in the
		// fixture workspace, so the denial cannot come from a missing role.
		var memberStatus string
		var organizationMember, workspaceMember bool
		if err := fixture.admin.QueryRow(ctx, `
			SELECT principal.status,
			       EXISTS (
			           SELECT 1
			           FROM public.organization_role_assignment AS assignment
			           WHERE assignment.organization_id = $2
			             AND assignment.principal_id = $1
			             AND assignment.role = 'MEMBER'
			             AND assignment.revoked_at IS NULL
			       ),
			       EXISTS (
			           SELECT 1
			           FROM public.workspace_member AS member
			           WHERE member.organization_id = $2
			             AND member.workspace_id = $3
			             AND member.principal_id = $1
			             AND member.removed_at IS NULL
			       )
			FROM public.principal AS principal
			WHERE principal.organization_id = $2 AND principal.id = $1`,
			authorityLookupOrgMemberPrincipal, fixture.binding.organizationID,
			fixture.binding.workspaceID).Scan(&memberStatus, &organizationMember, &workspaceMember); err != nil {
			t.Fatalf("control read of the seeded organization member: %v", err)
		}
		if memberStatus != "ACTIVE" || !organizationMember || workspaceMember {
			t.Fatalf("seeded actor is status=%q organization_member=%t workspace_member=%t, want ACTIVE/true/false",
				memberStatus, organizationMember, workspaceMember)
		}

		access := authorityAccess(fixture.binding, authorityLookupOrgMemberPrincipal, "req_governed_exposure_org_member")
		result, err := fixture.store.ResolveGovernedExposure(ctx, access, lookup)
		assertGovernedExposureNotFound(t, "organization member without workspace membership", result, err)
	})
}

// TestResolveGovernedExposureRealPostgreSQLMalformedFacts is B2.3c3: which
// refusal wins when a persisted fact is malformed and the requested relation is
// also absent, and what a wrong stored artifact hash answers on its own. Each
// case builds its own fixture, so the existing database reset keeps them
// independent, and each case leaves every other fact valid and hash-verified.
// Both must answer the identical true-zero, cause-free CodePersistence, so a
// malformed server fact is never reclassified as the decoder's ordinary
// absence.
func TestResolveGovernedExposureRealPostgreSQLMalformedFacts(t *testing.T) {
	ctx := context.Background()

	t.Run("latest artifact hash mismatch", func(t *testing.T) {
		fixture := newAdmittedAuthorityFixture(t)
		lookup := seedGovernedExposureReadSurface(t, ctx, fixture, true)

		// Revision 2 becomes latest for the pinned connection and holds the
		// requested relation, so exactly one persisted fact is wrong: the
		// stored revision_hash is the digest of different bytes. The artifact
		// and that digest are each well formed, so only the loader's own
		// re-derivation can refuse the pair.
		objects := []governedquery.ExposedObject{{
			SchemaName:  governedExposureSchema,
			TableName:   governedExposureRelation,
			Description: "Executed contracts.",
			Columns: []governedquery.ExposedColumn{
				{Name: "contract_id", DataType: "text", Description: "Contract identifier."},
			},
		}}
		canonicalBytes, err := canon.CanonicalJSON(objects)
		if err != nil {
			t.Fatalf("canonicalize mismatched governed exposure revision 2: %v", err)
		}
		artifactHash := canon.Hash(canonicalBytes)
		wrongHash := canon.Hash([]byte("a different governed exposure artifact"))
		if wrongHash == artifactHash {
			t.Fatalf("mismatched persisted hash %q equals the artifact hash", wrongHash)
		}
		if _, err := fixture.admin.Exec(ctx, `
			INSERT INTO public.governed_query_exposed_schema
			    (organization_id, connection_id, revision, objects_json, revision_hash, created_by)
			VALUES ($1, $2, 2, $3::jsonb, $4, $5)`,
			fixture.binding.organizationID, lookup.ConnectionID, string(canonicalBytes), wrongHash,
			fixture.binding.ownerID); err != nil {
			t.Fatalf("seed mismatched governed exposure revision 2: %v", err)
		}

		result, err := fixture.store.ResolveGovernedExposure(ctx, fixture.access, lookup)
		assertGovernedExposurePersistence(t, "latest artifact hash mismatch", result, err)
	})

	t.Run("malformed base fact outranks missing relation", func(t *testing.T) {
		fixture := newAdmittedAuthorityFixture(t)

		// The pinned connection is a fact of the fixture's exact current scope
		// chain, not of the lookup: read the same source_scope_revision row the
		// loader rebinds.
		var connectionID string
		var connectionRevision int64
		if err := fixture.admin.QueryRow(ctx, `
			SELECT connection_id, connection_revision
			  FROM public.source_scope_revision
			 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
			fixture.binding.organizationID, fixture.request.SourceScopeID,
			fixture.request.SourceScopeRevision).Scan(&connectionID, &connectionRevision); err != nil {
			t.Fatalf("load pinned source connection: %v", err)
		}
		if connectionID == "" || connectionRevision < 1 {
			t.Fatalf("pinned source connection = %q revision %d, want a non-empty id at a positive revision",
				connectionID, connectionRevision)
		}

		// The governed connection is inserted once with the one identity this
		// boundary refuses: migration 000068 stores it, so no constraint is
		// disabled and no immutable field is rewritten afterwards.
		if _, err := fixture.admin.Exec(ctx, `
			INSERT INTO public.governed_query_connection
			    (organization_id, id, workspace_id, database_identity, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $5)`,
			fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
			governedExposureMalformedDatabaseIdentity, fixture.binding.ownerID); err != nil {
			t.Fatalf("seed malformed governed query connection: %v", err)
		}
		if _, err := fixture.admin.Exec(ctx, `
			INSERT INTO public.governed_query_workspace_binding
			    (organization_id, connection_id, workspace_id, live_queries_enabled, created_by, updated_by)
			VALUES ($1, $2, $3, true, $4, $4)`,
			fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
			fixture.binding.ownerID); err != nil {
			t.Fatalf("seed governed query workspace binding: %v", err)
		}
		// The single artifact is valid, hash-verified and holds a relation, so
		// the decoder's own answer for the requested relation is CodeNotFound.
		seedGovernedExposureRevision(t, ctx, fixture, connectionID, 1, []governedquery.ExposedObject{{
			SchemaName:  governedExposureSchema,
			TableName:   governedExposureOtherRelation,
			Description: "Counterparties of the executed contracts.",
			Columns: []governedquery.ExposedColumn{
				{Name: "counterparty_id", DataType: "text", Description: "Counterparty identifier."},
			},
		}})

		lookup := workspacerepository.GovernedExposureLookup{
			WorkspaceID:   fixture.binding.workspaceID,
			SourceScopeID: fixture.request.SourceScopeID,
			ConnectionID:  connectionID,
			SchemaName:    governedExposureSchema,
			RelationName:  governedExposureRelation,
		}
		result, err := fixture.store.ResolveGovernedExposure(ctx, fixture.access, lookup)
		assertGovernedExposurePersistence(t, "malformed base fact outranks missing relation", result, err)
	})
}
