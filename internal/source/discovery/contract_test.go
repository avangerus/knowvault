package discovery

import (
	"bytes"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

func TestMetadataCanonicalizationAndResultHashAreBounded(t *testing.T) {
	metadata := Metadata{
		SchemaVersion: MetadataSchemaVersion, ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ConnectionRevision: 1, DatabaseOID: 16384, DatabaseName: "source_db",
		PrivilegeDigest: "sha256:" + repeated('a', 64), Views: []postgresqlquery.ViewDiscovery{},
	}
	left, err := marshalMetadata(metadata, 64)
	if err != nil {
		t.Fatal(err)
	}
	right, err := marshalMetadata(metadata, 64)
	if err != nil || !bytes.Equal(left, right) || !metadata.Validate(64) {
		t.Fatalf("metadata canonicalization = %q/%q, err=%v", left, right, err)
	}
	hash, err := resultHash(resultHashInput{
		SchemaVersion: ResultSchemaVersion, OrganizationID: "org_alpha", ActorPrincipalID: "usr_owner",
		RequestID: "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAV", ResultID: "sdr_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", ConnectionRevision: 1,
		TrustProfileHash: "sha256:" + repeated('b', 64), SecurityEpoch: 1,
		DatabaseIdentityHash: "sha256:" + repeated('c', 64), PrivilegeDigest: metadata.PrivilegeDigest,
		Status: resultSucceeded, ViewCount: 0, PreparedViewCount: 0, NeedsViewCount: 0,
		MetadataPlaintextHash: canonHash(left),
	})
	if err != nil || len(hash) != len("sha256:")+64 {
		t.Fatalf("result hash = %q, err=%v", hash, err)
	}
}

func TestMetadataRejectsInvalidPreparedInterpretationPair(t *testing.T) {
	metadata := Metadata{
		SchemaVersion: MetadataSchemaVersion, ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ConnectionRevision: 1, DatabaseOID: 16384, DatabaseName: "source_db",
		PrivilegeDigest: "sha256:" + repeated('a', 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", DatabaseOID: 16384, DatabaseName: "source_db",
			Status: postgresqlquery.DiscoveryPrepared,
		}},
	}
	if _, _, err := buildMetadata(target{connectionID: metadata.ConnectionID, connectionRevision: 1, maxViews: 64, maxColumns: 256, maxCommentBytes: 4096}, postgresqlquery.CatalogSnapshot{
		DatabaseOID: metadata.DatabaseOID, DatabaseName: metadata.DatabaseName, PrivilegeDigest: metadata.PrivilegeDigest, Views: metadata.Views,
	}); CodeOf(err) != CodeMetadataInvalid {
		t.Fatalf("invalid prepared view code=%s err=%v", CodeOf(err), err)
	}
}

func TestMetadataRejectsUnboundedOrNullViewCollections(t *testing.T) {
	base := Metadata{
		SchemaVersion: MetadataSchemaVersion, ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ConnectionRevision: 1, DatabaseOID: 16384, DatabaseName: "source_db",
		PrivilegeDigest: "sha256:" + repeated('a', 64), Views: []postgresqlquery.ViewDiscovery{},
	}
	if !base.Validate(64) {
		t.Fatal("bounded empty view collection was rejected")
	}
	base.Views = nil
	if base.Validate(64) {
		t.Fatal("null view collection was accepted")
	}
	base.Views = []postgresqlquery.ViewDiscovery{}
	if !base.Validate(1024) {
		t.Fatal("validator rejected the durable storage max view bound")
	}
	if base.Validate(1025) {
		t.Fatal("validator accepted a max view bound wider than durable storage")
	}
}

func repeated(character byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = character
	}
	return string(result)
}

func canonHash(value []byte) string {
	return canon.Hash(value)
}
