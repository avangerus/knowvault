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

// sourceQueryTestRow is one READY, trusted relation row of the given scope on
// connection revision 2 of database "pgdb:a".
func sourceQueryTestRow(scopeID string, scopeRevision int64, table string) sourceQueryRow {
	return sourceQueryRow{
		scopeID: scopeID, scopeRevision: scopeRevision, connectionRevision: 2,
		relation:         SourceQueryRelation{Schema: "public", Table: table, Columns: []string{"id"}},
		databaseIdentity: "pgdb:a", activationStatus: "READY", trustVerified: true,
	}
}

// Tables registered one per scope on one connection are one source: the agent
// sees every table, and the exposed-schema revision moves with any scope.
func TestSourceQueryScopesOfOneConnectionAreOneSource(t *testing.T) {
	single, ok := mergeSourceQueryRows("conn_a", []sourceQueryRow{sourceQueryTestRow("scope_a", 4, "contract")})
	if !ok || single.SourceScopeID != "scope_a" || single.ScopeRevision != 4 || len(single.Relations) != 1 ||
		single.ActivationStatus != "READY" || !single.TrustVerified {
		t.Fatalf("single scope = %+v ok=%v, want the scope itself unchanged", single, ok)
	}
	merged, ok := mergeSourceQueryRows("conn_a", []sourceQueryRow{
		sourceQueryTestRow("scope_a", 4, "contract"),
		sourceQueryTestRow("scope_b", 1, "contract_container_group"),
		sourceQueryTestRow("scope_c", 2, "stand"),
	})
	if !ok || merged.SourceID != "conn_a" || len(merged.Relations) != 3 || merged.ScopeRevision < 1 ||
		merged.ActivationStatus != "READY" || !merged.TrustVerified {
		t.Fatalf("three scopes on one connection = %+v ok=%v, want one READY source of 3 tables", merged, ok)
	}
	if merged.ScopeHash() == single.ScopeHash() {
		t.Fatal("the merged source kept the single-table scope hash, so a role proof of one table would pass for three")
	}
}

// The exposed-schema revision of a merged source is what audit and
// re-authorization compare: it must not depend on row order, and it must
// change when a table is swapped for another at the same revision or a scope
// is revised, so a disclosure from a removed table never re-authorizes.
func TestSourceQueryMergedRevisionChangesWithTheScopeSet(t *testing.T) {
	revision := func(rows ...sourceQueryRow) int64 {
		t.Helper()
		merged, ok := mergeSourceQueryRows("conn_a", rows)
		if !ok {
			t.Fatalf("rows refused: %+v", rows)
		}
		return merged.ScopeRevision
	}
	base := revision(sourceQueryTestRow("scope_a", 1, "contract"), sourceQueryTestRow("scope_b", 1, "stand"))
	if again := revision(sourceQueryTestRow("scope_b", 1, "stand"), sourceQueryTestRow("scope_a", 1, "contract")); again != base {
		t.Fatalf("row order changed the revision: %d vs %d", again, base)
	}
	for name, changed := range map[string]int64{
		"stand swapped for another table at revision 1": revision(sourceQueryTestRow("scope_a", 1, "contract"), sourceQueryTestRow("scope_c", 1, "client")),
		"stand revised":       revision(sourceQueryTestRow("scope_a", 1, "contract"), sourceQueryTestRow("scope_b", 2, "stand")),
		"a third table added": revision(sourceQueryTestRow("scope_a", 1, "contract"), sourceQueryTestRow("scope_b", 1, "stand"), sourceQueryTestRow("scope_c", 1, "client")),
		"stand removed":       revision(sourceQueryTestRow("scope_a", 1, "contract")),
	} {
		if changed == base {
			t.Fatalf("%s kept the exposed-schema revision %d", name, base)
		}
	}
}

// The merged source is readable only when every scope in it is: a pending or
// revoked table, or an untrusted one, keeps the whole connection from running SQL.
func TestSourceQueryMergedSourceIsReadyOnlyWhenEveryScopeIs(t *testing.T) {
	for name, change := range map[string]func(*sourceQueryRow){
		"one scope still DRAFT": func(row *sourceQueryRow) { row.activationStatus = "DRAFT" },
		"one scope REVOKED":     func(row *sourceQueryRow) { row.activationStatus = "REVOKED" },
		"one scope not trusted": func(row *sourceQueryRow) { row.trustVerified = false },
	} {
		second := sourceQueryTestRow("scope_b", 1, "stand")
		change(&second)
		merged, ok := mergeSourceQueryRows("conn_a", []sourceQueryRow{sourceQueryTestRow("scope_a", 1, "contract"), second})
		if !ok {
			t.Fatalf("%s: the rows were refused instead of reported as not ready", name)
		}
		if merged.ActivationStatus == "READY" && merged.TrustVerified {
			t.Fatalf("%s: the merged source is READY and trusted: %+v", name, merged)
		}
	}
}

// Rows that do not describe one database at one connection revision, one scope
// at two revisions, or one table registered twice are refused, never merged.
func TestSourceQueryInconsistentRowsAreRefused(t *testing.T) {
	for name, rows := range map[string][]sourceQueryRow{
		"no rows": nil,
		"another connection revision": {sourceQueryTestRow("scope_a", 1, "contract"),
			func() sourceQueryRow {
				row := sourceQueryTestRow("scope_b", 1, "stand")
				row.connectionRevision = 3
				return row
			}()},
		"another database": {sourceQueryTestRow("scope_a", 1, "contract"),
			func() sourceQueryRow {
				row := sourceQueryTestRow("scope_b", 1, "stand")
				row.databaseIdentity = "pgdb:b"
				return row
			}()},
		"one scope at two revisions": {sourceQueryTestRow("scope_a", 1, "contract"), sourceQueryTestRow("scope_a", 2, "stand")},
		"one table in two scopes":    {sourceQueryTestRow("scope_a", 1, "contract"), sourceQueryTestRow("scope_b", 1, "contract")},
	} {
		if merged, ok := mergeSourceQueryRows("conn_a", rows); ok {
			t.Fatalf("%s was merged: %+v", name, merged)
		}
	}
}
