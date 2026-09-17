package question

import (
	"reflect"
	"testing"
)

// cellOf builds a cell from the three fields the column assembly reads.
func cellOf(ordinal int, column, value string) snapshotCell {
	return snapshotCell{ordinal: ordinal, column: column, value: value}
}

func rowOf(versionID string, cells ...snapshotCell) snapshotRow {
	return snapshotRow{versionID: versionID, cells: cells}
}

// TestSnapshotRowsetColumnsKeepsLaterPopulatedNullableColumn asserts on the
// maps the rowset table actually returns: a column absent from the first
// rendered row (NULL/empty SQL value) but present later stays a header and its
// value stays visible, and absent cells never appear as keys.
func TestSnapshotRowsetColumnsKeepsLaterPopulatedNullableColumn(t *testing.T) {
	displayed := []snapshotRow{
		rowOf("sv_1", cellOf(0, "name", "ann"), cellOf(2, "note", "")),
		rowOf("sv_2", cellOf(0, "name", "bo"), cellOf(1, "phone", "555-0101"), cellOf(2, "note", "vip")),
	}

	columns, rows := snapshotRowsetTable(displayed)
	want := []string{"name", "phone", "note"}
	if !reflect.DeepEqual(columns, want) {
		t.Fatalf("columns = %v, want %v (later populated nullable column preserved)", columns, want)
	}
	if len(rows) != len(displayed) {
		t.Fatalf("rows returned = %d, want %d (one map per rendered row, order preserved)", len(rows), len(displayed))
	}

	// First rendered row: no phone cell, so no phone key -- absent stays absent.
	if _, present := rows[0]["phone"]; present {
		t.Fatalf("rows[0] = %v carries a phone key though sv_1 has no phone cell", rows[0])
	}
	if got := rows[0]["name"]; got != "ann" {
		t.Fatalf("rows[0][name] = %q, want %q", got, "ann")
	}
	if got, present := rows[0]["note"]; !present || got != "" {
		t.Fatalf("rows[0][note] = (%q, %v), want empty string present at key note", got, present)
	}
	// Later rendered row: exact value carried under the phone header.
	if got := rows[1]["phone"]; got != "555-0101" {
		t.Fatalf("rows[1][phone] = %q, want %q", got, "555-0101")
	}
	if got := rows[1]["name"]; got != "bo" {
		t.Fatalf("rows[1][name] = %q, want %q", got, "bo")
	}
	if got := rows[1]["note"]; got != "vip" {
		t.Fatalf("rows[1][note] = %q, want %q", got, "vip")
	}

	// Every returned data key and input cell has a corresponding header.
	headers := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		headers[column] = struct{}{}
	}
	for i, row := range rows {
		for key := range row {
			if _, ok := headers[key]; !ok {
				t.Fatalf("rows[%d] key %q has no matching header", i, key)
			}
		}
	}
	for _, row := range displayed {
		for _, cell := range row.cells {
			if _, ok := headers[cell.column]; !ok {
				t.Fatalf("cell %q in row %s has no header", cell.column, row.versionID)
			}
		}
	}
}

// TestSnapshotRowsetColumnsDeclaredOrdinalOrderWithMissingMiddle proves declared
// ordinal order wins over appearance order, duplicate names collapse to their
// first-seen ordinal, ordinal ties keep first-seen order, and empty input is a
// non-nil empty slice.
func TestSnapshotRowsetColumnsDeclaredOrdinalOrderWithMissingMiddle(t *testing.T) {
	displayed := []snapshotRow{
		rowOf("sv_1", cellOf(0, "a", "1"), cellOf(2, "c", "3")),
		rowOf("sv_2", cellOf(1, "b", "2"), cellOf(2, "c", "3")),
	}
	cols, _ := snapshotRowsetTable(displayed)
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(cols, want) {
		t.Fatalf("missing middle column order = %v, want %v", cols, want)
	}

	// Duplicate names: first seen keeps its ordinal and is emitted once.
	dupes := []snapshotRow{
		rowOf("sv_1", cellOf(0, "x", "1"), cellOf(1, "x", "1b"), cellOf(2, "y", "2")),
	}
	if cols, _ := snapshotRowsetTable(dupes); !reflect.DeepEqual(cols, []string{"x", "y"}) {
		t.Fatalf("duplicate-name order = %v, want [x y]", cols)
	}

	// A duplicate name whose later occurrence carries a LOWER ordinal stays at
	// its first-seen (higher) ordinal: first-seen wins, ordinals are not
	// reconciled. Here "y" is seen first at ordinal 3 then again at ordinal 1;
	// "x" ties "y" at 3 and is seen first, so order is [x y z].
	lateDup := []snapshotRow{
		rowOf("sv_1", cellOf(3, "x", "1"), cellOf(3, "y", "2")),
		rowOf("sv_2", cellOf(1, "y", "2b"), cellOf(4, "z", "3")),
	}
	if cols, _ := snapshotRowsetTable(lateDup); !reflect.DeepEqual(cols, []string{"x", "y", "z"}) {
		t.Fatalf("later-lower-ordinal duplicate = %v, want [x y z] (first-seen ordinal wins)", cols)
	}

	// Ordinal tie: stable sort keeps first encounter order.
	tied := []snapshotRow{
		rowOf("sv_1", cellOf(5, "p", "1")),
		rowOf("sv_2", cellOf(5, "q", "2"), cellOf(5, "p", "3")),
	}
	if cols, _ := snapshotRowsetTable(tied); !reflect.DeepEqual(cols, []string{"p", "q"}) {
		t.Fatalf("ordinal-tie order = %v, want [p q] (first encounter)", cols)
	}
	a, _ := snapshotRowsetTable(tied)
	b, _ := snapshotRowsetTable(tied)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("non-deterministic order: %v vs %v", a, b)
	}

	empty, _ := snapshotRowsetTable(nil)
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty input = %#v, want non-nil empty slice", empty)
	}
}

// TestSnapshotRowsetColumnsRespectsFiftyRowCap proves a column appearing only
// on row 51 of the authorized selection never reaches the returned headers or
// row maps: both the display cap and the table functions operate on rows
// actually rendered.
func TestSnapshotRowsetColumnsRespectsFiftyRowCap(t *testing.T) {
	selected := make([]snapshotRow, 0, 51)
	for i := 0; i < 50; i++ {
		selected = append(selected, rowOf("sv_common", cellOf(0, "common", "c")))
	}
	selected = append(selected, rowOf("sv_late", cellOf(0, "common", "c"), cellOf(1, "late_only", "x")))

	displayed := snapshotRowsetDisplayRows(selected)
	if len(displayed) != 50 {
		t.Fatalf("displayed rows = %d, want 50", len(displayed))
	}
	if rowsetDisplayRowLimit != 50 {
		t.Fatalf("rowsetDisplayRowLimit = %d, want 50", rowsetDisplayRowLimit)
	}
	if len(selected) != 51 {
		t.Fatalf("selection size = %d, want 51 (cap is display-only)", len(selected))
	}

	columns, rows := snapshotRowsetTable(displayed)
	if len(rows) != 50 {
		t.Fatalf("cap output rows length = %d, want 50", len(rows))
	}
	if !reflect.DeepEqual(columns, []string{"common"}) {
		t.Fatalf("columns = %v, want [common] (row 51 beyond the cap)", columns)
	}
	for i, row := range rows {
		if _, present := row["late_only"]; present {
			t.Fatalf("rows[%d] = %v carries late_only though row 51 is beyond the cap", i, row)
		}
		for key := range row {
			if key != "common" {
				t.Fatalf("rows[%d] key %q not in returned headers", i, key)
			}
		}
	}

	// Control: the same late column inside the window does appear.
	inside := []snapshotRow{
		rowOf("sv_1", cellOf(0, "common", "c")),
		rowOf("sv_2", cellOf(0, "common", "c"), cellOf(1, "late_only", "x")),
	}
	insideCols, insideRows := snapshotRowsetTable(snapshotRowsetDisplayRows(inside))
	if !reflect.DeepEqual(insideCols, []string{"common", "late_only"}) {
		t.Fatalf("in-window late column = %v, want [common late_only]", insideCols)
	}
	if got := insideRows[1]["late_only"]; got != "x" {
		t.Fatalf("in-window rows[1][late_only] = %q, want %q", got, "x")
	}
}
