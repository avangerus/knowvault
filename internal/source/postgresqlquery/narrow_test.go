package postgresqlquery

import "testing"

func testTableProjection() Projection {
	return Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "lineage_demo",
		Revision: 1, ContractHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchemaName: "public", RelationName: "accounts", RelationKind: "TABLE",
		EmptySnapshotPolicy: "HELD",
		Columns: []Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: TypeUUID, Roles: []Role{RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: TypeText, Roles: []Role{RoleEvidence}, MaxBytes: 1024},
			{Ordinal: 3, Name: "phone", TypeFingerprint: "oid:25", LogicalType: TypeText, Roles: []Role{RoleEvidence}, Nullable: true, MaxBytes: 64},
		},
	}
}

// TestNarrowProjectionExcludesEvidenceColumnAndChangesLineage is the S1
// acceptance test: excluding a plain EVIDENCE column narrows the projection,
// renumbers the surviving columns and changes both ContractHash and
// LineageID -- a narrowed table is a distinct immutable content contract, not
// a silent subset of the original one.
func TestNarrowProjectionExcludesEvidenceColumnAndChangesLineage(t *testing.T) {
	original := testTableProjection()
	narrowed, err := NarrowProjection(original, map[int]bool{3: true})
	if err != nil {
		t.Fatalf("narrow projection: %v", err)
	}
	if err := narrowed.Validate(); err != nil {
		t.Fatalf("narrowed projection invalid: %v", err)
	}
	if len(narrowed.Columns) != 2 {
		t.Fatalf("narrowed columns=%#v, want 2", narrowed.Columns)
	}
	for _, column := range narrowed.Columns {
		if column.Name == "phone" {
			t.Fatalf("excluded column still present: %#v", narrowed.Columns)
		}
	}
	if narrowed.ContractHash == original.ContractHash {
		t.Fatal("excluding a column did not change ContractHash")
	}
	if narrowed.LineageID == original.LineageID {
		t.Fatal("excluding a column did not change LineageID")
	}
	if _, err := narrowed.SelectSQL(); err != nil {
		t.Fatalf("narrowed projection SQL: %v", err)
	}
	// Repeating the same exclusion must converge on the same narrowed
	// contract, not mint a fresh one each call.
	again, err := NarrowProjection(original, map[int]bool{3: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.ContractHash != narrowed.ContractHash || again.LineageID != narrowed.LineageID {
		t.Fatalf("narrowing the same exclusion twice diverged: %q/%q vs %q/%q",
			again.ContractHash, again.LineageID, narrowed.ContractHash, narrowed.LineageID)
	}
}

// TestNarrowProjectionRejectsExcludingIdentityColumn is the S1 acceptance
// test: an exclusion may only narrow EVIDENCE, never remove the primary-key
// column identity was derived from.
func TestNarrowProjectionRejectsExcludingIdentityColumn(t *testing.T) {
	original := testTableProjection()
	if _, err := NarrowProjection(original, map[int]bool{1: true}); CodeOf(err) != CodeInvalidProjection {
		t.Fatalf("excluding the identity column code=%s, want %s", CodeOf(err), CodeInvalidProjection)
	}
}

// TestNarrowProjectionRejectsUnknownOrdinal proves an exclusion ordinal that
// is not a real column of the sealed discovery result is refused, not
// silently ignored.
func TestNarrowProjectionRejectsUnknownOrdinal(t *testing.T) {
	original := testTableProjection()
	if _, err := NarrowProjection(original, map[int]bool{99: true}); CodeOf(err) != CodeInvalidProjection {
		t.Fatalf("unknown ordinal code=%s, want %s", CodeOf(err), CodeInvalidProjection)
	}
}

// TestNarrowProjectionNoExclusionsReturnsOriginal proves an empty exclusion
// set is a no-op: the caller does not pay for a fresh hash derivation when
// nothing was excluded.
func TestNarrowProjectionNoExclusionsReturnsOriginal(t *testing.T) {
	original := testTableProjection()
	narrowed, err := NarrowProjection(original, nil)
	if err != nil {
		t.Fatal(err)
	}
	if narrowed.ContractHash != original.ContractHash || narrowed.LineageID != original.LineageID {
		t.Fatalf("no-op narrowing changed the contract: %#v", narrowed)
	}
}
