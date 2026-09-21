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
	if staleErr == nil {
		t.Fatal("the revision-1-only relation unexpectedly resolved from the latest revision")
	}
	if code := workspacerepository.CodeOf(staleErr); code != workspacerepository.CodeNotFound {
		t.Fatalf("revision-1-only relation code = %q, want %q", code, workspacerepository.CodeNotFound)
	}
	if staleErr.Error() != string(workspacerepository.CodeNotFound) {
		t.Fatalf("revision-1-only relation error = %q, want %q", staleErr.Error(), workspacerepository.CodeNotFound)
	}
	if unwrapped := errors.Unwrap(staleErr); unwrapped != nil {
		t.Fatalf("revision-1-only relation error retains a cause: %v", unwrapped)
	}
	if staleResult.Valid() ||
		staleResult.WorkspaceID() != "" || staleResult.WorkspaceRevision() != 0 ||
		staleResult.WorkspaceConfigurationHash() != "" || staleResult.WorkspaceSourceID() != "" ||
		staleResult.SourceScopeID() != "" || staleResult.SourceScopeRevision() != 0 ||
		staleResult.SourceScopeConfigurationHash() != "" || staleResult.ConnectionID() != "" ||
		staleResult.ConnectionRevision() != 0 || staleResult.DatabaseIdentity() != "" ||
		staleResult.LiveQueryEnabled() || staleResult.ExposureRevision() != 0 ||
		staleResult.ExposureArtifactHash() != "" || staleResult.SchemaName() != "" ||
		staleResult.RelationName() != "" || staleResult.Columns() != nil {
		t.Fatal("governed exposure failure returned a non-zero result")
	}
	encoded, marshalErr = jsonv2.Marshal(staleResult)
	if marshalErr != nil || string(encoded) != "{}" {
		t.Fatalf("failure result JSON = %q err=%v, want the opaque empty object", encoded, marshalErr)
	}
}
