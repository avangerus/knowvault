package observation

import (
	"context"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

type testPostgreSQLReader struct{ snapshot postgresqlquery.Snapshot }

func (reader testPostgreSQLReader) ReadProjection(context.Context, string, string, postgresqlquery.Projection, postgresqlquery.Limits) (postgresqlquery.Snapshot, error) {
	return reader.snapshot, nil
}

func TestPostgreSQLAdapterNormalizesTypedRowsWithoutSQLText(t *testing.T) {
	columns := []postgresqlquery.Column{
		{Ordinal: 1, Name: "id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
		{Ordinal: 2, Name: "team", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 128},
		{Ordinal: 3, Name: "amount", TypeFingerprint: "oid:1700:p:12:s:2", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 2, MaxBytes: 64},
	}
	projection := postgresqlquery.Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "lineage_demo", Revision: 1,
		ContractHash: observationHash([]byte("projection")), SchemaName: "public", RelationName: "business_objects",
		RelationKind: "VIEW", Columns: columns, EmptySnapshotPolicy: "AUTHORITATIVE",
	}
	if err := projection.Validate(); err != nil {
		t.Fatalf("projection: %v", err)
	}
	row, err := postgresqlquery.CanonicalizeRow(columns, []any{"550e8400-e29b-41d4-a716-446655440000", "alpha", "12.50"})
	if err != nil {
		t.Fatalf("row: %v", err)
	}
	snapshotHash, err := postgresqlquery.SnapshotSetHash([]postgresqlquery.Row{row})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewPostgreSQLAdapter(testPostgreSQLReader{snapshot: postgresqlquery.Snapshot{
		Rows: []postgresqlquery.Row{row}, RowCount: 1, CoverageComplete: true, SnapshotHash: snapshotHash,
	}}, "org_demo", "scope_demo", 1, "conn_demo", "cred_demo", projection, postgresqlquery.DefaultLimits(), []byte("identity-key"), 1)
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	page, err := adapter.Observe(context.Background(), Request{OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1, MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(page.Objects) != 1 || page.Objects[0].PayloadKind != PayloadTypedRow || page.Objects[0].BusinessRow == nil || page.Objects[0].Document != nil {
		t.Fatalf("unexpected SQL observation page: %+v", page)
	}
	if page.Objects[0].VersionKey == "" || page.Objects[0].ExternalID == "" {
		t.Fatalf("SQL observation lost stable identity/version: %+v", page.Objects[0])
	}
	contract := page.Objects[0].BusinessRow.Contract
	if contract.EntityID != page.Objects[0].ExternalID || contract.EntityVersion != page.Objects[0].VersionKey ||
		contract.LastUpdatedAt.IsZero() || contract.PayloadFormat != PayloadFormatJSON || string(contract.Payload) != string(row.Canonical) ||
		contract.Provenance.OrganizationID != "org_demo" || contract.Provenance.RowVersionHash != row.Hash {
		t.Fatalf("SQL observation lost minimum business-object contract: %+v", contract)
	}
	mutated := page
	mutated.Objects = append([]Object(nil), page.Objects...)
	mutated.Objects[0].BusinessRow = &BusinessRowPayload{
		Projection: page.Objects[0].BusinessRow.Projection, Row: page.Objects[0].BusinessRow.Row,
		Contract: contract,
	}
	mutated.Objects[0].BusinessRow.Contract.Provenance.OrganizationID = "org_other"
	if CodeOf(mutated.Validate(Request{OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1, MaxObjects: 10, MaxBytes: 1 << 20})) != CodeInvalidRequest {
		t.Fatal("cross-organization business-object provenance passed observation validation")
	}
}

func TestPostgreSQLAdapterRejectsIncompleteCoverage(t *testing.T) {
	projection := postgresqlquery.Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "lineage_demo", Revision: 1,
		ContractHash: observationHash([]byte("projection")), SchemaName: "public", RelationName: "business_objects",
		RelationKind: "VIEW", Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "id", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "value", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 64},
		}, EmptySnapshotPolicy: "AUTHORITATIVE",
	}
	adapter, err := NewPostgreSQLAdapter(testPostgreSQLReader{snapshot: postgresqlquery.Snapshot{CoverageComplete: false}}, "org_demo", "scope_demo", 1, "conn_demo", "cred_demo", projection, postgresqlquery.DefaultLimits(), []byte("key"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Observe(context.Background(), Request{OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1, MaxObjects: 10, MaxBytes: 1 << 20}); CodeOf(err) != CodeAdapterRejected {
		t.Fatalf("incomplete SQL snapshot code=%q, want %q", CodeOf(err), CodeAdapterRejected)
	}
}

func TestPostgreSQLLastUpdatedAtUsesDeclaredVersionHint(t *testing.T) {
	projection := postgresqlquery.Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "lineage_demo", Revision: 1,
		ContractHash: observationHash([]byte("projection-hint")), SchemaName: "public", RelationName: "business_objects",
		RelationKind: "VIEW", Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "updated_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint}, Precision: 3, MaxBytes: 64},
			{Ordinal: 3, Name: "amount", TypeFingerprint: "oid:1700:p:12:s:2", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 2, MaxBytes: 64},
		}, EmptySnapshotPolicy: "AUTHORITATIVE",
	}
	row, err := postgresqlquery.CanonicalizeRow(projection.Columns, []any{"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:34:56.789Z", "1.00"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := postgresqlLastUpdatedAt(projection, row)
	want := time.Date(2026, time.August, 29, 12, 34, 56, 789000000, time.UTC)
	if !ok || !got.Equal(want) {
		t.Fatalf("last updated=%v ok=%v, want %v", got, ok, want)
	}
}
