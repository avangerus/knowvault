package analyticsource

import (
	"fmt"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// TestScalarSumRealisticGrainFixture proves one realistic already-authorized
// snapshot of exactly 407 unique composite-grain rows, each carrying a canonical
// NUMERIC(24,6) measure, reduces to the controlled total 3888 with 407
// contributing rows and the retained validated snapshot hash. It also proves the
// reducer does not mutate the caller's rows.
func TestScalarSumRealisticGrainFixture(t *testing.T) {
	columns := scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6)
	raw := make([][]any, 0, 407)
	for index := 0; index < 406; index++ {
		raw = append(raw, []any{fmt.Sprintf("grain-%03d", index), "9.552000"})
	}
	raw = append(raw, []any{"grain-406", "9.888000"})

	read := scalarSumReadFrom(t, columns, raw, 2, []int{1})
	before := scalarSumCopyRows(read.snapshot.Rows)

	result := scalarSumReduce(t, read)
	if result.value != "3888" {
		t.Fatalf("reduced value = %q want 3888", result.value)
	}
	if result.contributingRows != 407 {
		t.Fatalf("contributing rows = %d want 407", result.contributingRows)
	}
	if result.snapshotHash != read.snapshot.SnapshotHash {
		t.Fatalf("retained hash = %q want %q", result.snapshotHash, read.snapshot.SnapshotHash)
	}
	if !scalarSumHashPattern.MatchString(result.snapshotHash) {
		t.Fatalf("retained hash %q is not canonical sha256", result.snapshotHash)
	}
	if !reflect.DeepEqual(read.snapshot.Rows, before) {
		t.Fatal("successful reduction mutated the caller-owned rows")
	}
}

// TestScalarSumExactArithmetic proves the summation is exact integer/decimal
// arithmetic rather than float arithmetic: 0.1+0.2 is exactly 0.3, an integer
// above 2^53 is retained digit for digit, and a signed cancellation normalizes
// to "0".
func TestScalarSumExactArithmetic(t *testing.T) {
	t.Run("decimal accumulation", func(t *testing.T) {
		columns := scalarSumNumericColumns("oid:1700:p:6:s:1", 6, 1)
		read := scalarSumReadFrom(t, columns, [][]any{{"grain-a", "0.1"}, {"grain-b", "0.2"}}, 2, []int{1})
		if got := scalarSumReduce(t, read).value; got != "0.3" {
			t.Fatalf("0.1 + 0.2 = %q want 0.3", got)
		}
	})

	t.Run("integer above float53", func(t *testing.T) {
		columns := scalarSumIntegerColumns("oid:20")
		read := scalarSumReadFrom(t, columns,
			[][]any{{"grain-a", "9007199254740993"}, {"grain-b", "9007199254740993"}}, 2, []int{1})
		if got := scalarSumReduce(t, read).value; got != "18014398509481986" {
			t.Fatalf("2^53 + 2^53 + 2 = %q want 18014398509481986", got)
		}
	})

	t.Run("signed cancellation", func(t *testing.T) {
		columns := scalarSumNumericColumns("oid:1700:p:6:s:3", 6, 3)
		read := scalarSumReadFrom(t, columns, [][]any{{"grain-a", "5.000"}, {"grain-b", "-5.000"}}, 2, []int{1})
		result := scalarSumReduce(t, read)
		if result.value != "0" {
			t.Fatalf("5.000 + -5.000 = %q want 0", result.value)
		}
		if result.contributingRows != 2 {
			t.Fatalf("contributing rows = %d want 2", result.contributingRows)
		}
	})
}

// TestScalarSumRefusals proves every malformed read outside the accepted shape
// is refused with the exact zero scalarSum and the exact unwrapped errMismatch,
// and that no refusal mutates the caller-owned rows.
func TestScalarSumRefusals(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) ScalarRead
	}{
		{"zero read", func(*testing.T) ScalarRead { return ScalarRead{} }},
		{"zero measure ordinal", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.measureOrdinal = 0
			return read
		}},
		{"empty identity ordinals", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.identityOrdinals = nil
			return read
		}},
		{"duplicate identity ordinal", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.identityOrdinals = []int{1, 1}
			return read
		}},
		{"identity ordinal equals measure", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.identityOrdinals = []int{2}
			return read
		}},
		{"negative identity ordinal", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.identityOrdinals = []int{-1}
			return read
		}},
		{"incomplete snapshot", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.snapshot.CoverageComplete = false
			return read
		}},
		{"empty snapshot", func(t *testing.T) ScalarRead {
			return ScalarRead{
				snapshot:         postgresqlquery.Snapshot{CoverageComplete: true},
				measureOrdinal:   2,
				identityOrdinals: []int{1},
			}
		}},
		{"row count drift", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.snapshot.RowCount++
			return read
		}},
		{"decoded bytes drift", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.snapshot.DecodedBytes++
			return read
		}},
		{"snapshot hash drift", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.snapshot.SnapshotHash = canon.Hash([]byte("snapshot drift"))
			return read
		}},
		{"row canonical drift", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.snapshot.Rows[0].Canonical[2] = 'Z'
			return read
		}},
		{"row hash drift", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.snapshot.Rows[0].Hash = canon.Hash([]byte("row drift"))
			hash, err := postgresqlquery.SnapshotSetHash(read.snapshot.Rows)
			if err != nil {
				t.Fatalf("recompute drifted snapshot hash: %v", err)
			}
			read.snapshot.SnapshotHash = hash
			return read
		}},
		{"missing selected ordinal", func(t *testing.T) ScalarRead {
			read := scalarSumBaseRead(t)
			read.measureOrdinal = 7
			return read
		}},
		{"duplicate row ordinal", func(t *testing.T) ScalarRead {
			row := scalarSumForgedRow(t, []postgresqlquery.ValueEntry{
				{Ordinal: 1, TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, ValueTag: "TEXT", Value: "grain-a"},
				{Ordinal: 1, TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, ValueTag: "TEXT", Value: "grain-b"},
				{Ordinal: 2, TypeFingerprint: "oid:1700:p:24:s:6", LogicalType: postgresqlquery.TypeNumeric, ValueTag: "NUMERIC", Value: "1.000000"},
			})
			return ScalarRead{
				snapshot:         scalarSumSnapshotFromRows(t, []postgresqlquery.Row{row}),
				measureOrdinal:   2,
				identityOrdinals: []int{1},
			}
		}},
		{"NULL measure", func(t *testing.T) ScalarRead {
			columns := scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6)
			columns[1].Nullable = true
			return scalarSumReadFrom(t, columns, [][]any{{"grain-a", nil}, {"grain-b", "1.000000"}}, 2, []int{1})
		}},
		{"NULL identity", func(t *testing.T) ScalarRead {
			columns := scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6)
			columns[0].Nullable = true
			return scalarSumReadFrom(t, columns, [][]any{{nil, "1.000000"}}, 2, []int{1})
		}},
		{"unsupported measure type", func(t *testing.T) ScalarRead {
			columns := []postgresqlquery.Column{
				{Ordinal: 1, Name: "grain_key", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
					Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
				{Ordinal: 2, Name: "measure_value", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
					Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 64},
			}
			return scalarSumReadFrom(t, columns, [][]any{{"grain-a", "not-a-number"}}, 2, []int{1})
		}},
		{"mixed measure type", func(t *testing.T) ScalarRead {
			first := scalarSumCanonicalRow(t, scalarSumIntegerColumns("oid:20"), []any{"grain-a", "7"})
			second := scalarSumCanonicalRow(t, scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6), []any{"grain-b", "1.000000"})
			return ScalarRead{
				snapshot:         scalarSumSnapshotFromRows(t, []postgresqlquery.Row{first, second}),
				measureOrdinal:   2,
				identityOrdinals: []int{1},
			}
		}},
		{"mixed measure fingerprint", func(t *testing.T) ScalarRead {
			first := scalarSumCanonicalRow(t, scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6), []any{"grain-a", "1.000000"})
			second := scalarSumCanonicalRow(t, scalarSumNumericColumns("oid:1700:p:30:s:6", 30, 6), []any{"grain-b", "2.000000"})
			return ScalarRead{
				snapshot:         scalarSumSnapshotFromRows(t, []postgresqlquery.Row{first, second}),
				measureOrdinal:   2,
				identityOrdinals: []int{1},
			}
		}},
		{"inconsistent numeric scale", func(t *testing.T) ScalarRead {
			first := scalarSumCanonicalRow(t, scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6), []any{"grain-a", "1.000000"})
			second := scalarSumCanonicalRow(t, scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 2), []any{"grain-b", "2.00"})
			return ScalarRead{
				snapshot:         scalarSumSnapshotFromRows(t, []postgresqlquery.Row{first, second}),
				measureOrdinal:   2,
				identityOrdinals: []int{1},
			}
		}},
		{"duplicate grain", func(t *testing.T) ScalarRead {
			columns := scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6)
			return scalarSumReadFrom(t, columns, [][]any{{"grain-a", "1.000000"}, {"grain-a", "2.000000"}}, 2, []int{1})
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			read := test.build(t)
			before := scalarSumCopyRows(read.snapshot.Rows)

			result, err := reduceScalarSum(read)
			if err != errMismatch {
				t.Fatalf("refusal = %v want the exact unwrapped errMismatch", err)
			}
			if !reflect.DeepEqual(result, scalarSum{}) {
				t.Fatalf("refused result = %+v want the exact zero value", result)
			}
			if !reflect.DeepEqual(read.snapshot.Rows, before) {
				t.Fatalf("refusal mutated the caller-owned rows: %+v want %+v", read.snapshot.Rows, before)
			}
		})
	}
}

// scalarSumNumericColumns builds the two selected columns of a numeric scalar
// read: a non-NULL text identity grain and one NUMERIC measure.
func scalarSumNumericColumns(fingerprint string, precision, scale int) []postgresqlquery.Column {
	return []postgresqlquery.Column{
		{Ordinal: 1, Name: "grain_key", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
			Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
		{Ordinal: 2, Name: "measure_value", TypeFingerprint: fingerprint, LogicalType: postgresqlquery.TypeNumeric,
			Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: precision, Scale: scale, MaxBytes: 64},
	}
}

// scalarSumIntegerColumns builds the two selected columns of an INT scalar read.
func scalarSumIntegerColumns(fingerprint string) []postgresqlquery.Column {
	return []postgresqlquery.Column{
		{Ordinal: 1, Name: "grain_key", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
			Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
		{Ordinal: 2, Name: "measure_value", TypeFingerprint: fingerprint, LogicalType: postgresqlquery.TypeInt,
			Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 64},
	}
}

func scalarSumReadFrom(t *testing.T, columns []postgresqlquery.Column, raw [][]any, measure int, identity []int) ScalarRead {
	t.Helper()
	return ScalarRead{
		snapshot:         scalarSumBuildSnapshot(t, columns, raw),
		measureOrdinal:   measure,
		identityOrdinals: identity,
	}
}

func scalarSumReduce(t *testing.T, read ScalarRead) scalarSum {
	t.Helper()
	result, err := reduceScalarSum(read)
	if err != nil {
		t.Fatalf("reduce scalar sum: %v", err)
	}
	return result
}

func scalarSumBaseRead(t *testing.T) ScalarRead {
	t.Helper()
	columns := scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6)
	return scalarSumReadFrom(t, columns, [][]any{{"grain-a", "1.250000"}, {"grain-b", "2.500000"}}, 2, []int{1})
}

// scalarSumBuildSnapshot uses the production postgresqlquery row canonicalizer
// and snapshot-set hash rather than forging valid rows by hand.
func scalarSumBuildSnapshot(t *testing.T, columns []postgresqlquery.Column, raw [][]any) postgresqlquery.Snapshot {
	t.Helper()
	rows := make([]postgresqlquery.Row, 0, len(raw))
	for _, values := range raw {
		row, err := postgresqlquery.CanonicalizeRow(columns, values)
		if err != nil {
			t.Fatalf("canonicalize row: %v", err)
		}
		rows = append(rows, row)
	}
	return scalarSumSnapshotFromRows(t, rows)
}

func scalarSumCanonicalRow(t *testing.T, columns []postgresqlquery.Column, raw []any) postgresqlquery.Row {
	t.Helper()
	row, err := postgresqlquery.CanonicalizeRow(columns, raw)
	if err != nil {
		t.Fatalf("canonicalize row: %v", err)
	}
	return row
}

func scalarSumSnapshotFromRows(t *testing.T, rows []postgresqlquery.Row) postgresqlquery.Snapshot {
	t.Helper()
	decoded := 0
	for _, row := range rows {
		decoded += len(row.Canonical)
	}
	hash, err := postgresqlquery.SnapshotSetHash(rows)
	if err != nil {
		t.Fatalf("snapshot set hash: %v", err)
	}
	return postgresqlquery.Snapshot{
		Rows: rows, RowCount: len(rows), DecodedBytes: decoded,
		CoverageComplete: true, SnapshotHash: hash,
	}
}

func scalarSumForgedRow(t *testing.T, values []postgresqlquery.ValueEntry) postgresqlquery.Row {
	t.Helper()
	canonical, err := canon.CanonicalJSON(values)
	if err != nil {
		t.Fatalf("canonicalize forged row: %v", err)
	}
	return postgresqlquery.Row{Values: values, Canonical: canonical, Hash: canon.Hash(canonical)}
}

func scalarSumCopyRows(rows []postgresqlquery.Row) []postgresqlquery.Row {
	if rows == nil {
		return nil
	}
	copied := make([]postgresqlquery.Row, len(rows))
	for index, row := range rows {
		values := make([]postgresqlquery.ValueEntry, len(row.Values))
		copy(values, row.Values)
		copied[index] = postgresqlquery.Row{
			Values:    values,
			Canonical: append([]byte(nil), row.Canonical...),
			Hash:      row.Hash,
		}
	}
	return copied
}
