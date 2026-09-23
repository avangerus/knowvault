package governedquery

import "testing"

func TestVerifyTextTableResultDigestRejectsTableTampering(t *testing.T) {
	count := "2"
	columns := []string{"name", "count"}
	rows := [][]*string{{nil, &count}}
	digest := resultDigest(QueryResult{Columns: columns, RowCount: 1, Rows: rows})
	if !VerifyTextTableResultDigest(columns, 1, rows, digest) {
		t.Fatal("valid canonical text-table digest was refused")
	}
	changed := "3"
	if VerifyTextTableResultDigest(columns, 1, [][]*string{{nil, &changed}}, digest) {
		t.Fatal("tampered table retained the original digest")
	}
	if VerifyTextTableResultDigest(columns, 0, rows, digest) {
		t.Fatal("row-count mismatch was accepted")
	}
	if VerifyTextTableResultDigest(columns, 1, rows, "sha256:invalid") {
		t.Fatal("invalid sha256 spelling was accepted")
	}
}
