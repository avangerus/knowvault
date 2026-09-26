package discovery

import (
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

func TestBuildMetadataKeepsUnpreparedViewsTypedAndBounded(t *testing.T) {
	const connectionID = "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	target := target{connectionID: connectionID, connectionRevision: 1, maxViews: 64, maxColumns: 2, maxCommentBytes: 4096}
	snapshot := postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
			RelationOID: 24576, SchemaName: "prepared", RelationName: "unknown", RelationKind: "VIEW",
			Columns: []postgresqlquery.DiscoveredColumn{{
				Ordinal: 1, Name: "amount", TypeOID: 1700, TypeName: "numeric", TypeFingerprint: "oid:1700",
				LogicalType: postgresqlquery.TypeNumeric,
			}},
			Status:         postgresqlquery.DiscoveryNeedsInterpretation,
			Interpretation: postgresqlquery.InterpretationUnrecognizedFormat,
		}},
	}
	metadata, counts, err := buildMetadata(target, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) == 0 || counts.status != resultNeedsReview || counts.viewCount != 1 || counts.preparedCount != 0 || counts.needsCount != 1 {
		t.Fatalf("metadata/counts = %d/%#v", len(metadata), counts)
	}
}

func TestBuildMetadataRejectsInvalidConnectorOutput(t *testing.T) {
	const connectionID = "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	target := target{connectionID: connectionID, connectionRevision: 1, maxViews: 64, maxColumns: 1, maxCommentBytes: 4096}
	base := postgresqlquery.ViewDiscovery{
		ConnectionID: connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
		RelationOID: 24576, SchemaName: "prepared", RelationName: "unknown", RelationKind: "VIEW",
		Columns: []postgresqlquery.DiscoveredColumn{{
			Ordinal: 1, Name: "amount", TypeOID: 1700, TypeName: "numeric", TypeFingerprint: "oid:1700",
			LogicalType: postgresqlquery.TypeNumeric,
		}},
		Status:         postgresqlquery.DiscoveryNeedsInterpretation,
		Interpretation: postgresqlquery.InterpretationUnrecognizedFormat,
	}
	tooManyColumns := base
	tooManyColumns.Columns = append(tooManyColumns.Columns, postgresqlquery.DiscoveredColumn{
		Ordinal: 2, Name: "second", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25",
		LogicalType: postgresqlquery.TypeText,
	})
	if _, _, err := buildMetadata(target, postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: []postgresqlquery.ViewDiscovery{tooManyColumns},
	}); CodeOf(err) != CodeMetadataInvalid {
		t.Fatalf("over-column connector output code=%s err=%v", CodeOf(err), err)
	}
	invalidReason := base
	invalidReason.Interpretation = "UNTRUSTED_REASON"
	if _, _, err := buildMetadata(target, postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: []postgresqlquery.ViewDiscovery{invalidReason},
	}); CodeOf(err) != CodeMetadataInvalid {
		t.Fatalf("unknown interpretation code=%s err=%v", CodeOf(err), err)
	}
}

// TestBuildMetadataAcceptsPreparedBaseTable proves the worker's untrusted-
// connector-output gate accepts the ADR-0097 widened relation-kind set (a
// PREPARED base table with an IDENTITY-bearing primary key), not only the
// original VIEW/MATERIALIZED_VIEW five-column envelope.
func TestBuildMetadataAcceptsPreparedBaseTable(t *testing.T) {
	const connectionID = "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	target := target{connectionID: connectionID, connectionRevision: 1, maxViews: 64, maxColumns: 2, maxCommentBytes: 4096}
	projection := postgresqlquery.Projection{
		ConnectionID: connectionID, DatabaseIdentity: "db_demo", LineageID: "lineage_demo", Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("a", 64), SchemaName: "public", RelationName: "accounts",
		RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024},
		},
	}
	snapshot := postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
			RelationOID: 30001, SchemaName: "public", RelationName: "accounts", RelationKind: "TABLE",
			ApproxRowCount: 4200,
			Columns: []postgresqlquery.DiscoveredColumn{
				{Ordinal: 1, Name: "account_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, PrimaryKey: true, MaxBytes: 64},
				{Ordinal: 2, Name: "display_name", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 1024},
			},
			Status:     postgresqlquery.DiscoveryPrepared,
			Projection: &projection,
		}},
	}
	metadata, counts, err := buildMetadata(target, snapshot)
	if err != nil {
		t.Fatalf("prepared base table connector output rejected: %v (code=%s)", err, CodeOf(err))
	}
	if len(metadata) == 0 || counts.status != resultSucceeded || counts.viewCount != 1 || counts.preparedCount != 1 || counts.needsCount != 0 {
		t.Fatalf("metadata/counts = %d/%#v", len(metadata), counts)
	}
}

// TestBuildMetadataRejectsUnrecognizedRelationKind proves the closed
// relation-kind set stays closed: a foreign table (or any other spelling
// outside VIEW/MATERIALIZED_VIEW/TABLE/PARTITIONED_TABLE) is untrusted
// connector output, not a silently accepted fifth kind.
func TestBuildMetadataRejectsUnrecognizedRelationKind(t *testing.T) {
	const connectionID = "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	target := target{connectionID: connectionID, connectionRevision: 1, maxViews: 64, maxColumns: 1, maxCommentBytes: 4096}
	if _, _, err := buildMetadata(target, postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
			RelationOID: 24576, SchemaName: "prepared", RelationName: "unknown", RelationKind: "FOREIGN_TABLE",
			Columns: []postgresqlquery.DiscoveredColumn{{
				Ordinal: 1, Name: "amount", TypeOID: 1700, TypeName: "numeric", TypeFingerprint: "oid:1700",
				LogicalType: postgresqlquery.TypeNumeric,
			}},
			Status:         postgresqlquery.DiscoveryNeedsInterpretation,
			Interpretation: postgresqlquery.InterpretationUnrecognizedFormat,
		}},
	}); CodeOf(err) != CodeMetadataInvalid {
		t.Fatalf("unrecognized relation kind code=%s err=%v", CodeOf(err), err)
	}
}

// TestBuildMetadataAcceptsRealisticGMScaleCatalog is the S1 fix proof for
// DISCOVERY_LIMIT_EXCEEDED against the GM customer catalog (645 tables/views
// in schema public, ~3,400 columns total). It generates 1024 PREPARED base
// tables -- the new durable ceiling -- with 4 columns each (4096 columns
// total, comfortably above GM's real ~3,400) and proves buildMetadata still
// succeeds within every remaining bound, in particular the unchanged 8MiB
// encrypted-artifact plaintext cap (internal/platform/artifactcrypto and the
// len(encoded) > 8<<20 check below it): 1024 realistic-width relations do not
// come close to that cap, so it did not need to move. A 1025th view is
// rejected the same way a 65th view always was.
func TestBuildMetadataAcceptsRealisticGMScaleCatalog(t *testing.T) {
	const connectionID = "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	const relationCount = 1024
	views := make([]postgresqlquery.ViewDiscovery, relationCount)
	for index := 0; index < relationCount; index++ {
		views[index] = realisticTableView(connectionID, index)
	}
	target := target{connectionID: connectionID, connectionRevision: 1, maxViews: relationCount, maxColumns: 256, maxCommentBytes: 4096}
	snapshot := postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "gm_customer_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: views,
	}
	metadata, counts, err := buildMetadata(target, snapshot)
	if err != nil {
		t.Fatalf("realistic GM-scale catalog rejected: %v (code=%s)", err, CodeOf(err))
	}
	if counts.viewCount != relationCount || counts.preparedCount != relationCount || counts.needsCount != 0 || counts.status != resultSucceeded {
		t.Fatalf("counts = %#v, want %d prepared views", counts, relationCount)
	}
	if len(metadata) == 0 || len(metadata) > 8<<20 {
		t.Fatalf("encoded metadata size = %d bytes, want a non-empty payload under the 8MiB artifact cap", len(metadata))
	}
	t.Logf("1024-relation/4096-column encoded metadata size = %d bytes", len(metadata))

	// One relation past the durable ceiling is still rejected fail-closed,
	// the same way a 65th relation always was under the old 64 bound.
	overLimit := append(append([]postgresqlquery.ViewDiscovery(nil), views...), realisticTableView(connectionID, relationCount))
	if _, _, err := buildMetadata(target, postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "gm_customer_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: overLimit,
	}); CodeOf(err) != CodeMetadataInvalid {
		t.Fatalf("1025th relation code=%s err=%v, want %s", CodeOf(err), err, CodeMetadataInvalid)
	}
}

// realisticTableView builds one PREPARED base-table view with a UUID primary
// key and three ordinary evidence columns -- the ADR-0097 base-table shape a
// customer catalog like GM's actually has, not the wider theoretical
// 256-column-per-relation cap.
func realisticTableView(connectionID string, index int) postgresqlquery.ViewDiscovery {
	suffix := strconv.Itoa(index)
	relationName := "gm_table_" + suffix
	projection := postgresqlquery.Projection{
		ConnectionID: connectionID, DatabaseIdentity: "db_gm_demo", LineageID: "lineage_gm_" + suffix, Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("a", 64), SchemaName: "public", RelationName: relationName,
		RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024},
			{Ordinal: 3, Name: "amount", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 44},
			{Ordinal: 4, Name: "updated_at", TypeFingerprint: "oid:1184:p:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 6, MaxBytes: 64},
		},
	}
	return postgresqlquery.ViewDiscovery{
		ConnectionID: connectionID, DatabaseOID: 16384, DatabaseName: "gm_customer_db",
		RelationOID: uint32(30000 + index), SchemaName: "public", RelationName: relationName, RelationKind: "TABLE",
		ApproxRowCount: int64(index * 7), Comment: "gm base table " + suffix,
		Columns: []postgresqlquery.DiscoveredColumn{
			{Ordinal: 1, Name: "id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, PrimaryKey: true, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 1024, Nullable: true},
			{Ordinal: 3, Name: "amount", TypeOID: 1700, TypeName: "numeric", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Precision: 12, Scale: 3, MaxBytes: 44},
			{Ordinal: 4, Name: "updated_at", TypeOID: 1184, TypeName: "timestamptz", TypeFingerprint: "oid:1184:p:6", LogicalType: postgresqlquery.TypeTimestamptz, Precision: 6, MaxBytes: 64},
		},
		Status:     postgresqlquery.DiscoveryPrepared,
		Projection: &projection,
	}
}

func TestDiscoveryPayloadIsExactlyRequestReference(t *testing.T) {
	requestID := "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if !validDiscoveryPayload(jobs.Payload{"source_discovery_request_id": requestID}, requestID) {
		t.Fatal("exact discovery payload was rejected")
	}
	for _, payload := range []jobs.Payload{
		{"source_discovery_request_id": requestID, "content_hash": "sha256:" + strings.Repeat("a", 64)},
		{"source_discovery_request_id": "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAX"},
		{"source_discovery_request_id": 1},
	} {
		if validDiscoveryPayload(payload, requestID) {
			t.Fatalf("invalid discovery payload accepted: %#v", payload)
		}
	}
}
