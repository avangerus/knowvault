package repository

// S3 card 2 focused unit test for the source SQL scope decoding. The database
// read itself is exercised by the PostgreSQL integration suite; this proves the
// pure part: the projection's own columns_json is decoded in projection ordinal
// order and no catalog or request input can widen it.

import "testing"

func TestSourceQueryColumnsFollowProjectionOrder(t *testing.T) {
	raw := []byte(`[
		{"ordinal":3,"name":"amount","logical_type":"NUMERIC","roles":["EVIDENCE"],"nullable":true},
		{"ordinal":1,"name":"id","logical_type":"UUID","roles":["IDENTITY"],"nullable":false},
		{"ordinal":2,"name":"status","logical_type":"TEXT","roles":["EVIDENCE"],"nullable":true}
	]`)
	columns, err := sourceQueryColumns(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(columns) != 3 || columns[0] != "id" || columns[1] != "status" || columns[2] != "amount" {
		t.Fatalf("columns = %v, want the projection ordinal order [id status amount]", columns)
	}
	if _, err := sourceQueryColumns([]byte(`not-json`)); err == nil {
		t.Fatal("a malformed projection was accepted")
	}
}

// TestSourceQueryMixedScopeRowsAreRefused is card S3.2c's scope-consistency
// rule: every row of one call must share the same scope, scope revision and
// connection revision, so a workspace that bound the same connection twice can
// never merge two scopes into one agent-visible schema.
func TestSourceQueryMixedScopeRowsAreRefused(t *testing.T) {
	source := SourceQuerySource{SourceScopeID: "scope_a", ScopeRevision: 4, ConnectionRevision: 2}
	if !sourceQueryScopeMatches(source, "scope_a", 4, 2) {
		t.Fatal("the first row did not match itself")
	}
	for name, candidate := range map[string]struct {
		scopeID            string
		scopeRevision      int64
		connectionRevision int64
	}{
		"another scope":               {"scope_b", 4, 2},
		"another scope revision":      {"scope_a", 5, 2},
		"another connection revision": {"scope_a", 4, 3},
	} {
		if sourceQueryScopeMatches(source, candidate.scopeID, candidate.scopeRevision, candidate.connectionRevision) {
			t.Fatalf("%s was merged into one scope", name)
		}
	}
}
