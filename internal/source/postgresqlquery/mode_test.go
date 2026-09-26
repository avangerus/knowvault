package postgresqlquery

import "testing"

// TestWithQueryOnlyMintsDistinctContract is S3 card 4's contract-level
// acceptance test: the registration mode is part of the immutable table
// contract, so a query-only projection is a distinct lineage with its own
// ContractHash and LineageID -- never the indexed projection with a mutable
// flag -- and its generated SELECT is unchanged (SQL still reads the same
// columns).
func TestWithQueryOnlyMintsDistinctContract(t *testing.T) {
	original := testTableProjection()
	if original.QueryOnly {
		t.Fatal("test projection unexpectedly starts query-only")
	}
	modeOnly, err := WithQueryOnly(original, true)
	if err != nil {
		t.Fatalf("WithQueryOnly: %v", err)
	}
	if err := modeOnly.Validate(); err != nil {
		t.Fatalf("query-only projection invalid: %v", err)
	}
	if !modeOnly.QueryOnly {
		t.Fatal("query-only projection is not marked query-only")
	}
	if modeOnly.ContractHash == original.ContractHash {
		t.Fatal("query-only mode did not change ContractHash")
	}
	if modeOnly.LineageID == original.LineageID {
		t.Fatal("query-only mode did not change LineageID")
	}
	if len(modeOnly.Columns) != len(original.Columns) {
		t.Fatalf("query-only mode changed the column contract: %#v", modeOnly.Columns)
	}
	indexedSQL, err := original.SelectSQL()
	if err != nil {
		t.Fatal(err)
	}
	queryOnlySQL, err := modeOnly.SelectSQL()
	if err != nil {
		t.Fatal(err)
	}
	if indexedSQL != queryOnlySQL {
		t.Fatalf("query-only changed the generated SQL: %q vs %q", indexedSQL, queryOnlySQL)
	}
	// The same mode twice must converge on the same immutable contract.
	again, err := WithQueryOnly(original, true)
	if err != nil {
		t.Fatal(err)
	}
	if again.ContractHash != modeOnly.ContractHash || again.LineageID != modeOnly.LineageID {
		t.Fatalf("deriving the same mode twice diverged: %q/%q vs %q/%q",
			again.ContractHash, again.LineageID, modeOnly.ContractHash, modeOnly.LineageID)
	}
	// And a projection already in the requested mode is returned unchanged.
	same, err := WithQueryOnly(modeOnly, true)
	if err != nil {
		t.Fatal(err)
	}
	if same.ContractHash != modeOnly.ContractHash || same.LineageID != modeOnly.LineageID {
		t.Fatal("re-applying the same mode changed the contract")
	}
}

// TestWithQueryOnlyFalseIsNoOp proves the indexed default is byte-identical to
// discovery's own contract: an indexed registration must not pay for or
// diverge from the original hashes.
func TestWithQueryOnlyFalseIsNoOp(t *testing.T) {
	original := testTableProjection()
	indexed, err := WithQueryOnly(original, false)
	if err != nil {
		t.Fatal(err)
	}
	if indexed.QueryOnly || indexed.ContractHash != original.ContractHash || indexed.LineageID != original.LineageID {
		t.Fatalf("indexed mode changed the contract: %#v", indexed)
	}
}

// TestValidProjectionMode is the closed mode vocabulary the HTTP boundary and
// the registration service both validate against.
func TestValidProjectionMode(t *testing.T) {
	for _, value := range []string{"", ProjectionModeIndexed, ProjectionModeQueryOnly} {
		if !ValidProjectionMode(value) {
			t.Fatalf("mode %q should be valid", value)
		}
	}
	for _, value := range []string{"query_only", "INDEXED ", "QUERY", "NOT_INDEXED"} {
		if ValidProjectionMode(value) {
			t.Fatalf("mode %q should be refused", value)
		}
	}
}
