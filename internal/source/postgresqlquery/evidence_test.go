package postgresqlquery

import (
	"encoding/json"
	"encoding/json/jsontext"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func testEvidenceProjection() Projection {
	return Projection{
		ConnectionID: "conn_01J00000000000000000000000", DatabaseIdentity: "cluster-db",
		LineageID: "waste-total", Revision: 1, ContractHash: "sha256:" + repeatedEvidence('a', 64),
		SchemaName: "public", RelationName: "waste_daily", RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD", Columns: []Column{
			{Ordinal: 1, Name: "id", TypeFingerprint: "oid:2950", LogicalType: TypeUUID, Roles: []Role{RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "disposed_kg", TypeFingerprint: "oid:1700:p:12:s:2", LogicalType: TypeNumeric, Roles: []Role{RoleEvidence}, Precision: 12, Scale: 2, MaxBytes: 64},
		},
	}
}

func repeatedEvidence(value byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return string(result)
}

func TestRenderedCellAnchorIsCanonicalAndExact(t *testing.T) {
	p := testEvidenceProjection()
	row, err := CanonicalizeRow(p.Columns, []any{"550e8400-e29b-41d4-a716-446655440000", "12.50"})
	if err != nil {
		t.Fatal(err)
	}
	entity, err := IdentityDigest([]byte("01234567890123456789012345678901"), 1, p, row)
	if err != nil {
		t.Fatal(err)
	}
	text, anchor, valueHash, err := RenderedCellAnchor(p, entity, row, p.Columns[1], row.Values[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != "disposed_kg = 12.50" || valueHash == "" || len(anchor) == 0 {
		t.Fatalf("unexpected rendered cell: %q %q %d", text, valueHash, len(anchor))
	}
	var decoded map[string]any
	if err := json.Unmarshal(anchor, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["kind"] != "POSTGRESQL_QUERY_CELL" || decoded["text_end"] != float64(len(text)) || decoded["row_version_hash"] != row.Hash {
		t.Fatalf("anchor lost exact tuple: %#v", decoded)
	}
	if canon.Hash(text) == "" {
		t.Fatal("cell text hash is empty")
	}
}

func TestRenderCellRejectsRoleAndTagMismatch(t *testing.T) {
	p := testEvidenceProjection()
	if _, err := RenderCell(p.Columns[0], ValueEntry{Ordinal: 1, TypeFingerprint: "oid:2950", LogicalType: TypeUUID, ValueTag: "UUID", Value: "550e8400-e29b-41d4-a716-446655440000"}); err == nil {
		t.Fatal("identity-only column became evidence")
	}
	if _, err := RenderCell(p.Columns[1], ValueEntry{Ordinal: 2, TypeFingerprint: "oid:1700:p:12:s:2", LogicalType: TypeNumeric, ValueTag: "TEXT", Value: "12.50"}); err == nil {
		t.Fatal("tag mismatch accepted")
	}
}

func TestRenderedEvidenceCellsExpandJSONPathsAndBindAnchors(t *testing.T) {
	p := testEvidenceProjection()
	p.Columns = []Column{
		p.Columns[0],
		{Ordinal: 2, Name: "payload", TypeFingerprint: "oid:3802", LogicalType: TypeJSONB, Roles: []Role{RoleEvidence}, MaxBytes: 4096},
	}
	row, err := CanonicalizeRow(p.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440000",
		`{"empty":{},"metrics":{"kg":12.50,"unit":"kg"},"name":"route/a"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	entity, err := IdentityDigest([]byte("01234567890123456789012345678901"), 1, p, row)
	if err != nil {
		t.Fatal(err)
	}
	cells, err := RenderedEvidenceCells(p, entity, row, p.Columns[1], row.Values[1])
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := map[string]string{"/empty": "payload[/empty] = {}", "/metrics/kg": "payload[/metrics/kg] = 12.5", "/metrics/unit": `payload[/metrics/unit] = "kg"`, "/name": `payload[/name] = "route/a"`}
	if len(cells) != len(wantPaths) {
		t.Fatalf("got %d JSON Evidence cells, want %d: %+v", len(cells), len(wantPaths), cells)
	}
	seenHashes := make(map[string]struct{}, len(cells))
	for _, cell := range cells {
		wantText, ok := wantPaths[cell.Path]
		if !ok || string(cell.Text) != wantText {
			t.Fatalf("unexpected JSON cell path/text: %q %q", cell.Path, cell.Text)
		}
		if _, exists := seenHashes[cell.ValueHash]; exists || cell.ValueHash == "" {
			t.Fatalf("JSON value hash is empty or duplicated: %q", cell.ValueHash)
		}
		seenHashes[cell.ValueHash] = struct{}{}
		var anchor map[string]any
		if err := json.Unmarshal(cell.Anchor, &anchor); err != nil {
			t.Fatal(err)
		}
		if anchor["json_path"] != cell.Path || anchor["column_name"] != "payload" || anchor["text_end"] != float64(len(cell.Text)) {
			t.Fatalf("anchor lost JSON path binding: %#v", anchor)
		}
	}
}

func TestJSONLeavesEscapePointersAndRejectInvalidEscapes(t *testing.T) {
	leaves, err := JSONLeaves(jsontext.Value(`{"a/b":{"x~y":1},"arr":[null,true]}`))
	if err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]struct{}, len(leaves))
	for _, leaf := range leaves {
		paths[leaf.Path] = struct{}{}
	}
	for _, path := range []string{"/a~1b/x~0y", "/arr/0", "/arr/1"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("missing escaped JSON pointer %q in %v", path, paths)
		}
	}
	for _, path := range []string{"a/b", "/bad~2escape", "/bad\x00control"} {
		if ValidateJSONPath(path) == nil {
			t.Fatalf("invalid JSON pointer accepted: %q", path)
		}
	}
	if ValidateJSONPath("") != nil {
		t.Fatal("root JSON pointer rejected")
	}
	if strings.Contains(string(leaves[0].Raw), " ") {
		t.Fatalf("leaf was not canonicalized: %s", leaves[0].Raw)
	}
}
