package discovery

import (
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
