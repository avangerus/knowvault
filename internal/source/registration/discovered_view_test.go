package registration

// S3 card 1's registration-time half: the catalog JSON persisted next to a
// discovered projection is built from the projection's own (already narrowed)
// columns, so an excluded column is never named, and its comments are bounded
// to migration 000115's per-comment limit rather than allowed to fail an
// otherwise valid registration.

import (
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

func catalogTestProjection() postgresqlquery.Projection {
	return postgresqlquery.Projection{
		ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", DatabaseIdentity: "pgdb:" + strings.Repeat("a", 64),
		LineageID: "projection-lineage:" + strings.Repeat("b", 64), Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("c", 64), SchemaName: "public", RelationName: "accounts",
		RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024},
		},
	}
}

func decodeCatalog(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("catalog JSON did not decode: %v: %s", err, raw)
	}
	return items
}

func TestPostgresqlCatalogJSONNeverNamesAnExcludedColumn(t *testing.T) {
	discovered := []discovery.Column{
		{Name: "account_id", TypeName: "uuid", Comment: "surrogate key", PrimaryKey: true},
		{Name: "display_name", TypeName: "text", Comment: "customer name"},
		{Name: "phone", TypeName: "text", Comment: "never published"},
	}
	raw, err := postgresqlCatalogJSON(catalogTestProjection(), discovered)
	if err != nil {
		t.Fatalf("postgresqlCatalogJSON: %v", err)
	}
	items := decodeCatalog(t, raw)
	if len(items) != 2 {
		t.Fatalf("catalog = %s, want exactly the two projected columns", raw)
	}
	for _, item := range items {
		if item["name"] == "phone" {
			t.Fatalf("an excluded column was written into the catalog: %s", raw)
		}
	}
	if items[0]["name"] != "account_id" || items[0]["type_name"] != "uuid" ||
		items[0]["primary_key"] != true || items[0]["comment"] != "surrogate key" {
		t.Fatalf("account_id entry = %#v", items[0])
	}
	if items[1]["name"] != "display_name" || items[1]["type_name"] != "text" ||
		items[1]["primary_key"] != false || items[1]["comment"] != "customer name" {
		t.Fatalf("display_name entry = %#v", items[1])
	}
}

func TestPostgresqlCatalogJSONFallsBackToTheProjection(t *testing.T) {
	raw, err := postgresqlCatalogJSON(catalogTestProjection(), nil)
	if err != nil {
		t.Fatalf("postgresqlCatalogJSON: %v", err)
	}
	items := decodeCatalog(t, raw)
	if len(items) != 2 {
		t.Fatalf("catalog = %s, want 2", raw)
	}
	if items[0]["type_name"] != "UUID" || items[0]["comment"] != "" || items[0]["primary_key"] != true {
		t.Fatalf("fallback account_id entry = %#v", items[0])
	}
	if items[1]["type_name"] != "TEXT" {
		t.Fatalf("fallback display_name entry = %#v", items[1])
	}
}

func TestPostgresqlCatalogJSONBoundsComments(t *testing.T) {
	raw, err := postgresqlCatalogJSON(catalogTestProjection(), []discovery.Column{
		{Name: "account_id", TypeName: "uuid", Comment: strings.Repeat("я", maxCatalogCommentBytes)},
	})
	if err != nil {
		t.Fatalf("postgresqlCatalogJSON: %v", err)
	}
	items := decodeCatalog(t, raw)
	comment, _ := items[0]["comment"].(string)
	if len(comment) > maxCatalogCommentBytes || !strings.HasPrefix(comment, "я") {
		t.Fatalf("comment was not truncated to a valid %d-byte prefix: %d bytes", maxCatalogCommentBytes, len(comment))
	}
}
