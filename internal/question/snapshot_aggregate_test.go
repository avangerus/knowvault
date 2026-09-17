package question

import (
	"context"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/planner"
)

func snapshotDate(value string) *time.Time {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		panic(err)
	}
	return &parsed
}

// fleetSnapshot mirrors the shape a POSTGRESQL_QUERY projection publishes: one
// row per source_version, one typed cell per declared EVIDENCE column, with the
// operator's TITLE role on the column that names the row's subject.
func fleetSnapshot(today time.Time) []snapshotRow {
	rows := []struct {
		id      string
		vehicle string
		status  string
		started string
	}{
		{"ver_a", "V-101", "IN_TRANSIT", today.Format("2006-01-02")},
		{"ver_b", "V-102", "IN_TRANSIT", today.Format("2006-01-02")},
		{"ver_c", "V-103", "IN_TRANSIT", today.Format("2006-01-02")},
		{"ver_d", "V-201", "DONE", today.AddDate(0, 0, -1).Format("2006-01-02")},
		{"ver_e", "V-202", "DONE", today.AddDate(0, 0, -1).Format("2006-01-02")},
		{"ver_f", "V-205", "CANCELLED", today.AddDate(0, 0, -1).Format("2006-01-02")},
		{"ver_g", "V-301", "DONE", today.AddDate(0, 0, -9).Format("2006-01-02")},
	}
	snapshot := make([]snapshotRow, 0, len(rows))
	for _, row := range rows {
		snapshot = append(snapshot, snapshotRow{versionID: row.id, cells: []snapshotCell{
			{fragmentID: "frg_" + row.id + "_1", ordinal: 2, column: "vehicle", logicalType: "TEXT", title: true, value: row.vehicle},
			{fragmentID: "frg_" + row.id + "_2", ordinal: 5, column: "started_at", logicalType: "TIMESTAMPTZ",
				value: row.started, calendarDate: snapshotDate(row.started)},
			{fragmentID: "frg_" + row.id + "_3", ordinal: 7, column: "status", logicalType: "TEXT", value: row.status},
		}})
	}
	return snapshot
}

// fleetSnapshotWithVolume adds one unrelated numeric column to the typed
// snapshot. It exercises the distinction between an unresolved SUM metric
// and an explicit COUNT operation.
func fleetSnapshotWithVolume(today time.Time) []snapshotRow {
	rows := fleetSnapshot(today)
	for index := range rows {
		rows[index].cells = append(rows[index].cells, snapshotCell{
			fragmentID: "frg_" + rows[index].versionID + "_4", ordinal: 8,
			column: "volume_m3", logicalType: "NUMERIC", numeric: "12.500", value: "12.500",
		})
	}
	return rows
}

func mustPlan(t *testing.T, question string) planner.Plan {
	t.Helper()
	plan, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatalf("plan %q: %v", question, err)
	}
	return plan
}

func TestSnapshotAggregateCountsTodayOverTheWholeSnapshot(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	if plan.Operation != planner.Aggregate {
		t.Fatalf("operation=%s want AGGREGATE", plan.Operation)
	}
	result, ok := reduceStructuredSnapshot(fleetSnapshot(today), plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable count")
	}
	if result.function != "COUNT" || result.count != 3 {
		t.Fatalf("function=%s count=%d want COUNT 3", result.function, result.count)
	}
	// The count is taken over every row in the snapshot, not over a retrieval
	// window: all seven rows were considered, three matched.
	if result.rowsInSnapshot != 7 || result.rowsMatched != 3 {
		t.Fatalf("rows_in_snapshot=%d rows_matched=%d want 7/3", result.rowsInSnapshot, result.rowsMatched)
	}
	if len(result.witnesses) != 3 {
		t.Fatalf("witnesses=%d want one per counted row", len(result.witnesses))
	}
}

func TestSnapshotAggregateDeclinesUnknownMetricWhenNumericColumnExists(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	if plan.Operation != planner.Aggregate || plan.Aggregate == nil || plan.Aggregate.Function != "SUM" {
		t.Fatalf("plan=%+v want an unresolved SUM aggregate", plan.Aggregate)
	}
	result, ok := reduceStructuredSnapshot(fleetSnapshotWithVolume(today), plan, today, "UTC")
	if ok {
		t.Fatal("reducer accepted an unresolved SUM metric despite available numeric columns")
	}
	if result.refusal != snapshotAggregateRefusalUnresolvedMetric {
		t.Fatalf("refusal=%d want unresolved metric", result.refusal)
	}
}

func TestResolveStructuredSnapshotCarriesUnresolvedMetricRefusal(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	result, ok, ambiguous := (&Service{}).resolveStructuredSnapshotGroup(
		context.Background(), questionAccess(""), "qrun_0001", "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?",
		fleetSnapshotWithVolume(today), plan, today, "UTC")
	if ok || ambiguous != nil {
		t.Fatalf("resolution=(ok=%v ambiguous=%v) want terminal typed refusal", ok, ambiguous)
	}
	if result.refusal != snapshotAggregateRefusalUnresolvedMetric {
		t.Fatalf("refusal=%d want unresolved metric", result.refusal)
	}
}

func TestSnapshotAggregateKeepsExplicitCountWithNumericColumn(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := planner.Plan{
		Status:    planner.Ready,
		Operation: planner.Aggregate,
		Aggregate: &planner.AggregateSpec{Function: "COUNT"},
	}
	result, ok := reduceStructuredSnapshot(fleetSnapshotWithVolume(today), plan, today, "UTC")
	if !ok {
		t.Fatal("reducer declined an explicit count when an unrelated numeric column exists")
	}
	if result.function != "COUNT" || result.count != 7 {
		t.Fatalf("function=%s count=%d want COUNT 7", result.function, result.count)
	}
}

func TestSnapshotAggregateSumsExplicitNumericMetric(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := planner.Plan{
		Status:    planner.Ready,
		Operation: planner.Aggregate,
		Aggregate: &planner.AggregateSpec{Function: "SUM", Metric: "volume_m3"},
	}
	result, ok := reduceStructuredSnapshot(fleetSnapshotWithVolume(today), plan, today, "UTC")
	if !ok {
		t.Fatal("reducer declined an explicit numeric sum")
	}
	if result.function != "SUM" || result.numericTotal != "87.500" {
		t.Fatalf("function=%s total=%s want SUM 87.500", result.function, result.numericTotal)
	}
}

func TestSnapshotAggregateListsYesterdaySubjects(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u041a\u0430\u043a\u0438\u0435 \u043c\u0430\u0448\u0438\u043d\u044b \u0431\u044b\u043b\u0438 \u0432 \u0440\u0435\u0439\u0441\u0435 \u0432\u0447\u0435\u0440\u0430?")
	if plan.Operation != planner.Aggregate || plan.Aggregate == nil || plan.Aggregate.Function != "LIST" {
		t.Fatalf("plan=%+v want AGGREGATE/LIST", plan.Aggregate)
	}
	result, ok := reduceStructuredSnapshot(fleetSnapshot(today), plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable enumeration")
	}
	want := []string{"V-201", "V-202", "V-205"}
	if len(result.values) != len(want) {
		t.Fatalf("values=%v want %v", result.values, want)
	}
	for index, value := range want {
		if result.values[index] != value {
			t.Fatalf("values=%v want %v", result.values, want)
		}
	}
}

func TestSnapshotAggregateAppliesEqualityAndRelativeWindow(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0440\u0435\u0439\u0441\u043e\u0432 \u0431\u044b\u043b\u043e \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u043e \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 7 \u0434\u043d\u0435\u0439, status = DONE?")
	result, ok := reduceStructuredSnapshot(fleetSnapshot(today), plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable filtered count")
	}
	// ver_d and ver_e are DONE yesterday; ver_g is DONE nine days ago and is
	// outside the window; ver_f is CANCELLED.
	if result.count != 2 {
		t.Fatalf("count=%d want 2 (answer=%q)", result.count, renderSnapshotAnswer(result, nil))
	}
	if len(result.equality) != 1 || result.equality[0].Name != "status" || !strings.EqualFold(result.equality[0].Value, "DONE") {
		t.Fatalf("equality=%+v want status=DONE", result.equality)
	}
}

func TestSnapshotAggregateDeclinesUnknownEqualityColumn(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0440\u0435\u0439\u0441\u043e\u0432 \u0441\u0435\u0433\u043e\u0434\u043d\u044f, region = EAST?")
	if _, ok := reduceStructuredSnapshot(fleetSnapshot(today), plan, today, "UTC"); ok {
		t.Fatalf("reducer answered a question whose predicate names no column in the snapshot")
	}
}

func TestSnapshotAggregateDeclinesPeriodWithoutTemporalColumn(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	rows := []snapshotRow{{versionID: "ver_a", cells: []snapshotCell{
		{fragmentID: "frg_1", ordinal: 1, column: "vehicle", logicalType: "TEXT", title: true, value: "V-101"},
	}}}
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	if _, ok := reduceStructuredSnapshot(rows, plan, today, "UTC"); ok {
		t.Fatalf("a period-scoped question over a snapshot with no date must not be counted unscoped")
	}
}

// citizenAppealsSnapshot mirrors an "overdue citizen appeals" projection: one
// declared TITLE column (address) that repeats across several appeal rows
// for the same address, including one case/whitespace-only variant of an
// existing address -- exactly the kind of import artefact behind the
// real-stand defect where LIST enumerated 4 addresses when only 3 distinct
// ones exist (FIX-1 #3).
func citizenAppealsSnapshot() []snapshotRow {
	rows := []struct{ id, address string }{
		{"ver_1", "ul. Lenina 5"},
		{"ver_2", "ul. Lenina 5"},
		{"ver_3", "ul. Mira 10"},
		{"ver_4", "ul. Mira 10"},
		{"ver_5", " ul. mira 10 "}, // same address as ver_3/ver_4: case + padding only
		{"ver_6", "ul. Sovetskaya 2"},
	}
	snapshot := make([]snapshotRow, 0, len(rows))
	for _, row := range rows {
		snapshot = append(snapshot, snapshotRow{versionID: row.id, cells: []snapshotCell{
			{fragmentID: "frg_" + row.id, ordinal: 2, column: "address", logicalType: "TEXT", title: true, value: row.address},
		}})
	}
	return snapshot
}

// TestSnapshotAggregateCountAndListAgreeOnDistinctEntities is the FIX-1 #3
// regression: 6 rows over 3 real distinct addresses (one repeated verbatim,
// one repeated with only a casing/whitespace difference) must make LIST
// report exactly those 3 addresses and COUNT report the same 3 -- never a
// raw row count (6) and never a naive case-sensitive dedup (4).
func TestSnapshotAggregateCountAndListAgreeOnDistinctEntities(t *testing.T) {
	rows := citizenAppealsSnapshot()
	countPlan := planner.Plan{Status: planner.Ready, Operation: planner.Aggregate, Aggregate: &planner.AggregateSpec{Function: "COUNT"}}
	countResult, ok := reduceStructuredSnapshot(rows, countPlan, time.Now().UTC(), "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable count")
	}
	if countResult.rowsMatched != 6 {
		t.Fatalf("rows_matched=%d want 6 (every row unscoped)", countResult.rowsMatched)
	}
	if countResult.count != 3 {
		t.Fatalf("COUNT=%d want 3 distinct addresses, not the raw row count", countResult.count)
	}

	listPlan := planner.Plan{Status: planner.Ready, Operation: planner.Aggregate, Aggregate: &planner.AggregateSpec{Function: "LIST"}}
	listResult, ok := reduceStructuredSnapshot(rows, listPlan, time.Now().UTC(), "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable enumeration")
	}
	want := []string{"ul. Lenina 5", "ul. Mira 10", "ul. Sovetskaya 2"}
	if len(listResult.values) != len(want) {
		t.Fatalf("values=%v want %v", listResult.values, want)
	}
	for index, value := range want {
		if !strings.EqualFold(strings.TrimSpace(listResult.values[index]), value) {
			t.Fatalf("values=%v want %v", listResult.values, want)
		}
	}
	if listResult.count != countResult.count {
		t.Fatalf("LIST count=%d and COUNT=%d disagree on the same matched set", listResult.count, countResult.count)
	}
}

// TestSnapshotWitnessesOneRowPerDistinctEntityNotPerMatchedRow is the FIX-6
// basis-card regression: a vehicle with more than one matched row today (two
// trips) must still contribute exactly ONE citation naming it, not one per
// row -- otherwise citation k no longer names the k-th distinct key the
// answer text (LIST's own distinct values) actually enumerated, and two
// basis cards can show the very same entity while a third distinct entity
// gets none.
func TestSnapshotWitnessesOneRowPerDistinctEntityNotPerMatchedRow(t *testing.T) {
	today := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	rows := fleetSnapshot(today)
	// Give V-102 a second trip today (a distinct row, same declared entity).
	rows = append(rows, snapshotRow{versionID: "ver_b2", cells: []snapshotCell{
		{fragmentID: "frg_ver_b2_1", ordinal: 2, column: "vehicle", logicalType: "TEXT", title: true, value: "V-102"},
		{fragmentID: "frg_ver_b2_2", ordinal: 5, column: "started_at", logicalType: "TIMESTAMPTZ",
			value: today.Format("2006-01-02"), calendarDate: snapshotDate(today.Format("2006-01-02"))},
		{fragmentID: "frg_ver_b2_3", ordinal: 7, column: "status", logicalType: "TEXT", value: "IN_TRANSIT"},
	}})
	plan := mustPlan(t, "\u041a\u0430\u043a\u0438\u0435 \u043c\u0430\u0448\u0438\u043d\u044b \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	result, ok := reduceStructuredSnapshot(rows, plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable enumeration")
	}
	if result.count != 3 || len(result.values) != 3 {
		t.Fatalf("count=%d values=%v want 3 distinct vehicles", result.count, result.values)
	}
	if result.rowsMatched != 4 {
		t.Fatalf("rowsMatched=%d want 4 (V-102's second trip still matched)", result.rowsMatched)
	}
	if len(result.witnesses) != 3 {
		t.Fatalf("witnesses=%d want exactly one per distinct entity (3), got %v", len(result.witnesses), result.witnesses)
	}
	seen := make(map[string]struct{}, len(result.witnesses))
	for _, witness := range result.witnesses {
		if _, dup := seen[witness]; dup {
			t.Fatalf("witnesses contain a duplicate fragment id: %v", result.witnesses)
		}
		seen[witness] = struct{}{}
	}
}

// TestSnapshotAggregateDeclinesAmbiguousDateRole is the FIX-1 #3 regression
// for the reducer's other silent guess: a snapshot with two date columns
// (e.g. a created-at next to a due/deadline date) and no declared role
// saying which one a period-scoped question means. The reducer used to pick
// whichever date column had the lowest ordinal; it must now decline instead,
// so a "overdue"-style question over the wrong date column never silently
// answers with the wrong window.
func TestSnapshotAggregateDeclinesAmbiguousDateRole(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	rows := []snapshotRow{{versionID: "ver_a", cells: []snapshotCell{
		{fragmentID: "frg_1_title", ordinal: 1, column: "address", logicalType: "TEXT", title: true, value: "ul. Lenina 5"},
		{fragmentID: "frg_1_created", ordinal: 2, column: "created_at", logicalType: "TIMESTAMPTZ",
			value: today.Format("2006-01-02"), calendarDate: &today},
		{fragmentID: "frg_1_due", ordinal: 3, column: "due_at", logicalType: "TIMESTAMPTZ",
			value: today.Format("2006-01-02"), calendarDate: &today},
	}}}
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	if _, ok := reduceStructuredSnapshot(rows, plan, today, "UTC"); ok {
		t.Fatalf("reducer must decline a period-scoped question over a snapshot with two undeclared date columns, not guess the lowest-ordinal one")
	}
}

// TestSnapshotAggregateUsesDeclaredPeriodRoleAmongTwoDateColumns is FIX-3
// #1's positive counterpart to TestSnapshotAggregateDeclinesAmbiguousDateRole:
// once the owner has declared PERIOD on one of the two temporal columns at
// registration (contract.go RolePeriod), the reducer must use exactly that
// column instead of declining, regardless of its ordinal position.
func TestSnapshotAggregateUsesDeclaredPeriodRoleAmongTwoDateColumns(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	yesterday := today.AddDate(0, 0, -1)
	rows := []snapshotRow{
		{versionID: "ver_a", cells: []snapshotCell{
			{fragmentID: "frg_a_title", ordinal: 1, column: "address", logicalType: "TEXT", title: true, value: "ul. Lenina 5"},
			// created_at has the LOWER ordinal, so the pre-FIX-3 "lowest
			// ordinal wins" guess would have picked this column and put the
			// row outside "today" -- the declared PERIOD column
			// (due_at) is what must actually be used.
			{fragmentID: "frg_a_created", ordinal: 2, column: "created_at", logicalType: "TIMESTAMPTZ",
				value: yesterday.Format("2006-01-02"), calendarDate: &yesterday},
			{fragmentID: "frg_a_due", ordinal: 3, column: "due_at", logicalType: "TIMESTAMPTZ",
				value: today.Format("2006-01-02"), calendarDate: &today, period: true},
		}},
		{versionID: "ver_b", cells: []snapshotCell{
			{fragmentID: "frg_b_title", ordinal: 1, column: "address", logicalType: "TEXT", title: true, value: "ul. Gagarina 21"},
			{fragmentID: "frg_b_created", ordinal: 2, column: "created_at", logicalType: "TIMESTAMPTZ",
				value: today.Format("2006-01-02"), calendarDate: &today},
			{fragmentID: "frg_b_due", ordinal: 3, column: "due_at", logicalType: "TIMESTAMPTZ",
				value: yesterday.Format("2006-01-02"), calendarDate: &yesterday, period: true},
		}},
	}
	plan := mustPlan(t, "\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0441\u0435\u0433\u043e\u0434\u043d\u044f?")
	result, ok := reduceStructuredSnapshot(rows, plan, today, "UTC")
	if !ok {
		t.Fatalf("expected the reducer to resolve using the declared PERIOD column instead of declining")
	}
	if result.temporalColumn != "due_at" {
		t.Fatalf("expected the declared PERIOD column due_at to be used, got %q", result.temporalColumn)
	}
	if result.rowsMatched != 1 || len(result.values) != 1 || result.values[0] != "ul. Lenina 5" {
		t.Fatalf("expected exactly the row whose due_at falls today (ul. Lenina 5), got matched=%d values=%v",
			result.rowsMatched, result.values)
	}
}

func TestSnapshotAggregateDeclinesGroupedRequest(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0440\u0435\u0439\u0441\u043e\u0432 \u0441\u0435\u0433\u043e\u0434\u043d\u044f group_by=status?")
	if plan.Operation != planner.Aggregate {
		t.Skip("planner did not classify the grouped request as an aggregate")
	}
	if _, ok := reduceStructuredSnapshot(fleetSnapshot(today), plan, today, "UTC"); ok {
		t.Fatalf("grouped aggregates belong to the typed Evidence adapter, not this reducer")
	}
}

func TestSnapshotWindowIsEndExclusiveAndTenantDated(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	start, end, scoped, ok := snapshotWindow([]planner.Filter{{Name: "time_period", Value: "\u0432\u0447\u0435\u0440\u0430"}}, today)
	if !ok || !scoped || !start.Equal(today.AddDate(0, 0, -1)) || !end.Equal(today) {
		t.Fatalf("yesterday window = [%s,%s) scoped=%v ok=%v", start, end, scoped, ok)
	}
	start, end, scoped, ok = snapshotWindow([]planner.Filter{{Name: "time_window", Value: "last_days:7"}}, today)
	if !ok || !scoped || !start.Equal(today.AddDate(0, 0, -6)) || !end.Equal(today.AddDate(0, 0, 1)) {
		t.Fatalf("last 7 days window = [%s,%s) scoped=%v ok=%v", start, end, scoped, ok)
	}
	if _, _, scoped, ok = snapshotWindow(nil, today); !ok || scoped {
		t.Fatalf("an unscoped plan must be resolvable and unscoped, got scoped=%v ok=%v", scoped, ok)
	}
}

func TestRenderSnapshotAnswerStatesTheExactResultAndItsBasis(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	result, ok := reduceStructuredSnapshot(fleetSnapshot(today), plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined")
	}
	answer := renderSnapshotAnswer(result, []Citation{{Number: 1}})
	for _, want := range []string{"Answer: 3.", "rows in snapshot — 7", "matching the condition — 3", "started_at", "UTC"} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer %q is missing %q", answer, want)
		}
	}
}

// --- Two simultaneously active structured sources (scope isolation) -------
//
// Before this fix, loadStructuredSnapshot's rows carried no per-source
// identity at all, so with two active structured sources bound to the same
// workspace reduceStructuredSnapshot ran over the UNION of both sources' rows
// and COUNT/LIST silently mixed them. The tests below build exactly that
// situation -- a fleet-of-vehicles source and an unrelated citizen-requests
// source, both "active" in one combined row set -- and prove
// selectStructuredSnapshotGroup answers only from the source the question is
// actually about, or declines rather than mixing when column shape alone
// cannot tell the two apart.

// fleetSnapshotScoped is fleetSnapshot tagged with a source scope identity, as
// loadStructuredSnapshot's own query now attaches to every row it loads.
func fleetSnapshotScoped(today time.Time, scopeID string) []snapshotRow {
	rows := fleetSnapshot(today)
	for index := range rows {
		rows[index].sourceScopeID = scopeID
	}
	return rows
}

// citizenRequestsSnapshot mirrors the shape the OTHER demo structured source
// ("Citizen requests") publishes: a different table entirely, with its own
// TITLE column (address, not vehicle) and no "status" column at all -- the
// equality test below relies on that absence for real schema-based
// disambiguation, not a coincidence. Its date column is deliberately named
// "started_at" too (an unremarkable name two independent operational tables
// could easily share) so the window-decline test below demonstrates the
// actual historical failure mode: two sources' rows sharing a column name and
// getting silently combined under it, not merely two differently-named
// columns that happen not to collide.
func citizenRequestsSnapshot(today time.Time, scopeID string) []snapshotRow {
	rows := []struct {
		id, address, priority, opened string
	}{
		{"ver_c1", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, 5", "HIGH", today.Format("2006-01-02")},
		{"ver_c2", "\u0443\u043b. \u041c\u0438\u0440\u0430, 12", "LOW", today.AddDate(0, 0, -2).Format("2006-01-02")},
	}
	snapshot := make([]snapshotRow, 0, len(rows))
	for _, row := range rows {
		snapshot = append(snapshot, snapshotRow{versionID: row.id, sourceScopeID: scopeID, cells: []snapshotCell{
			{fragmentID: "frg_" + row.id + "_1", ordinal: 1, column: "address", logicalType: "TEXT", title: true, value: row.address},
			{fragmentID: "frg_" + row.id + "_2", ordinal: 2, column: "priority", logicalType: "TEXT", value: row.priority},
			{fragmentID: "frg_" + row.id + "_3", ordinal: 6, column: "started_at", logicalType: "TIMESTAMPTZ",
				value: row.opened, calendarDate: snapshotDate(row.opened)},
		}})
	}
	return snapshot
}

func twoActiveStructuredSourcesSnapshot(today time.Time) []snapshotRow {
	combined := fleetSnapshotScoped(today, "scope_fleet")
	return append(combined, citizenRequestsSnapshot(today, "scope_citizen")...)
}

// TestSnapshotAggregateResolvesTheRightSourceWhenTwoStructuredSourcesAreActive
// is the FIN-1 regression: an equality filter that names a column only the
// fleet source has ("status") lets selectStructuredSnapshotGroup identify and
// reduce only the fleet source's own rows, exactly as if the citizen-requests
// source were not bound at all.
func TestSnapshotAggregateResolvesTheRightSourceWhenTwoStructuredSourcesAreActive(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	combined := twoActiveStructuredSourcesSnapshot(today)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0440\u0435\u0439\u0441\u043e\u0432 \u0431\u044b\u043b\u043e \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u043e \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 7 \u0434\u043d\u0435\u0439, status = DONE?")
	result, ok := selectStructuredSnapshotGroup(combined, plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a question one of two active structured sources can resolve on its own")
	}
	if result.count != 2 {
		t.Fatalf("count=%d want 2 -- the fleet source's own count (ver_d, ver_e), not inflated or altered by the unrelated citizen-requests source", result.count)
	}
	if result.rowsInSnapshot != 7 {
		t.Fatalf("rows_in_snapshot=%d want 7 -- the fleet source's own snapshot size, not the %d rows across both active sources combined",
			result.rowsInSnapshot, len(combined))
	}
}

// TestSnapshotAggregateDeclinesWhenTwoStructuredSourcesBothResolveTheWindow is
// the fail-closed half: with no predicate that names a column unique to one
// source, both the fleet and the citizen-requests source independently
// resolve "today" (each has its own temporal column with a row dated today),
// so the reducer must decline rather than silently pick one arbitrarily.
func TestSnapshotAggregateDeclinesWhenTwoStructuredSourcesBothResolveTheWindow(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	combined := twoActiveStructuredSourcesSnapshot(today)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")

	// Document the exact regression this guards: reducing the UNION of both
	// sources' rows directly (the pre-fix code path) silently mixes ver_c1
	// (a citizen request opened today) into the fleet's own count of 3.
	unscoped, ok := reduceStructuredSnapshot(combined, plan, today, "UTC")
	if !ok || unscoped.count != 4 {
		t.Fatalf("sanity check on the union itself changed shape: ok=%v count=%d want ok=true count=4 (this fixture no longer demonstrates the historical bug)", ok, unscoped.count)
	}

	if _, ok := selectStructuredSnapshotGroup(combined, plan, today, "UTC"); ok {
		t.Fatalf("both sources resolve today's window with no distinguishing predicate: the fix must decline, not silently return either source's count (let alone the mixed union's)")
	}
}

// --- SEED-3 #1: "overdue"/overdue as a declarable condition -----------
//
// citizenRequestsOverdueSnapshot mirrors demo_ops.citizen_requests_v: a
// declared PERIOD column (deadline_at, the row's due date -- distinct from
// the undeclared "opened_at" a snapshot may also carry) and a declared STATUS
// column, three addresses repeated over 12 rows -- the psql truth the demo
// script verifies (12 Lenin Street x9, 21 Gagarin Street, Sadovaya Street,
// building 3) INCLUDES one real row whose deadline is earlier THE SAME calendar
// day as "now" (ver_9 below: this is the live acc regression -- comparing
// calendar dates instead of precise instants under-counted 9 as 7 there) --
// plus one address whose deadline has passed but whose status is already
// closed (must NOT count as overdue) and one address whose deadline is still
// in the future (must NOT count as overdue either).
func citizenRequestsOverdueSnapshot(now time.Time) []snapshotRow {
	past := now.AddDate(0, 0, -5)
	future := now.AddDate(0, 0, 5)
	// earlierToday is strictly before "now" but shares now's calendar date --
	// the exact shape that under-counted on the acc stand.
	earlierToday := now.Add(-2 * time.Hour)
	rows := []struct {
		id, address, status string
		deadline            time.Time
	}{
		{"ver_1", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		{"ver_2", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		{"ver_3", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		{"ver_4", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		{"ver_5", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		{"ver_6", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		{"ver_7", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		{"ver_8", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", past},
		// SEED-3 regression fixture: due earlier TODAY, still overdue.
		{"ver_9", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "OPEN", earlierToday},
		{"ver_10", "\u0443\u043b. \u0413\u0430\u0433\u0430\u0440\u0438\u043d\u0430, \u0434. 21", "OPEN", past},
		{"ver_11", "\u0443\u043b. \u0421\u0430\u0434\u043e\u0432\u0430\u044f, \u0434. 3", "OPEN", past},
		// Deadline passed but already closed: not overdue.
		{"ver_12", "\u0443\u043b. \u041c\u0438\u0440\u0430, \u0434. 45", "CLOSED", past},
		// Deadline still in the future: not overdue regardless of status.
		{"ver_13", "\u043f\u0440. \u041f\u043e\u0431\u0435\u0434\u044b, \u0434. 1", "OPEN", future},
	}
	snapshot := make([]snapshotRow, 0, len(rows))
	for _, row := range rows {
		snapshot = append(snapshot, snapshotRow{versionID: row.id, cells: []snapshotCell{
			{fragmentID: "frg_" + row.id + "_addr", ordinal: 1, column: "address", logicalType: "TEXT", title: true, value: row.address},
			{fragmentID: "frg_" + row.id + "_deadline", ordinal: 2, column: "deadline_at", logicalType: "TIMESTAMPTZ",
				value: row.deadline.Format("2006-01-02"), calendarDate: snapshotDatePtr(row.deadline), instant: snapshotInstantPtr(row.deadline), period: true},
			{fragmentID: "frg_" + row.id + "_status", ordinal: 3, column: "status", logicalType: "TEXT", value: row.status, status: true},
		}})
	}
	return snapshot
}

func snapshotDatePtr(value time.Time) *time.Time {
	date := time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
	return &date
}

func snapshotInstantPtr(value time.Time) *time.Time {
	instant := value
	return &instant
}

// TestSnapshotAggregateOverdueConditionUsesPeriodAndStatus is SEED-3 #1's
// positive case: "which citizen requests are overdue" resolves to the rows
// whose declared PERIOD column is before today AND whose declared STATUS
// column is not closed -- 11 rows over exactly 3 addresses, matching the
// demo's own psql-verified truth (deadline_at < now() AND status='OPEN').
func TestSnapshotAggregateOverdueConditionUsesPeriodAndStatus(t *testing.T) {
	today := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	plan := mustPlan(t, "\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0433\u0440\u0430\u0436\u0434\u0430\u043d \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u044b?")
	if plan.Operation != planner.Aggregate || plan.Aggregate == nil || plan.Aggregate.Function != "LIST" {
		t.Fatalf("plan=%+v want AGGREGATE/LIST", plan.Aggregate)
	}
	found := false
	for _, filter := range plan.Filters {
		if filter.Name == "condition" && filter.Value == "overdue" {
			found = true
		}
	}
	if !found {
		t.Fatalf("filters=%+v want a declared condition=overdue filter", plan.Filters)
	}

	result, ok := reduceStructuredSnapshot(citizenRequestsOverdueSnapshot(today), plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable overdue enumeration")
	}
	want := []string{"\u0443\u043b. \u0413\u0430\u0433\u0430\u0440\u0438\u043d\u0430, \u0434. 21", "\u0443\u043b. \u041b\u0435\u043d\u0438\u043d\u0430, \u0434. 12", "\u0443\u043b. \u0421\u0430\u0434\u043e\u0432\u0430\u044f, \u0434. 3"}
	if len(result.values) != len(want) {
		t.Fatalf("values=%v want %v", result.values, want)
	}
	for index, value := range want {
		if result.values[index] != value {
			t.Fatalf("values=%v want %v", result.values, want)
		}
	}
	if result.rowsMatched != 11 {
		t.Fatalf("rows_matched=%d want 11 (excludes the closed and the not-yet-due rows)", result.rowsMatched)
	}
	if !result.overdueCondition || !result.overdueStatusApplied {
		t.Fatalf("result=%+v want overdueCondition=true overdueStatusApplied=true (STATUS column declared)", result)
	}
	answer := renderSnapshotAnswer(result, nil)
	if !strings.Contains(answer, "Selection: overdue") || !strings.Contains(answer, "Status considered") {
		t.Fatalf("answer=%q must disclose the overdue condition and that status was applied", answer)
	}
}

// TestSnapshotAggregateOverdueConditionWithoutDeclaredStatusIsDateOnly is the
// contract's other branch: a projection with a declared PERIOD column but no
// declared STATUS column still answers "overdue", but by due date alone --
// the already-closed row (ver_12 above) now counts too, and the disclosed
// basis says so plainly rather than silently narrowing by an undeclared
// status.
func TestSnapshotAggregateOverdueConditionWithoutDeclaredStatusIsDateOnly(t *testing.T) {
	today := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	rows := citizenRequestsOverdueSnapshot(today)
	for rowIndex := range rows {
		for cellIndex := range rows[rowIndex].cells {
			rows[rowIndex].cells[cellIndex].status = false
		}
	}
	plan := mustPlan(t, "\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0433\u0440\u0430\u0436\u0434\u0430\u043d \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u044b?")
	result, ok := reduceStructuredSnapshot(rows, plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable overdue enumeration")
	}
	// ver_12 (45 Mira Street, CLOSED) now counts too: 11 + 1 = 12 rows over 4
	// addresses, since status is not considered without a declared column.
	if result.rowsMatched != 12 {
		t.Fatalf("rows_matched=%d want 12 (no declared STATUS column -> date-only)", result.rowsMatched)
	}
	if result.overdueStatusApplied {
		t.Fatalf("result=%+v want overdueStatusApplied=false: no STATUS column was declared", result)
	}
	answer := renderSnapshotAnswer(result, nil)
	if !strings.Contains(answer, "Status not considered") {
		t.Fatalf("answer=%q must disclose that status was not considered (\u043a\u0430\u043a \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u043e)", answer)
	}
}

// TestSnapshotAggregateOverdueConditionDeclinesWithoutDeclaredPeriod is SEED-3
// #1's fail-closed guard: "overdue" names the row's own declared due date,
// never a guessed temporal column -- with none declared (or more than one),
// the reducer must decline rather than pick one silently.
func TestSnapshotAggregateOverdueConditionDeclinesWithoutDeclaredPeriod(t *testing.T) {
	today := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	rows := citizenRequestsOverdueSnapshot(today)
	for rowIndex := range rows {
		for cellIndex := range rows[rowIndex].cells {
			rows[rowIndex].cells[cellIndex].period = false
		}
	}
	plan := mustPlan(t, "\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0433\u0440\u0430\u0436\u0434\u0430\u043d \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u044b?")
	if _, ok := reduceStructuredSnapshot(rows, plan, today, "UTC"); ok {
		t.Fatalf("reducer must decline an overdue condition with no declared PERIOD column, not guess one")
	}
}

// --- FIX-4 #1: name/column tie-break when two structured sources are both
// enabled and schema shape alone leaves more than one able to answer ------
//
// These mirror the demo stand's actual two structured sources by name
// ("Garbage truck trips (operational database)" / "Citizen requests (operational
// database)") and its two problem questions from knowvault-DEMO-SCRIPT.md, at the
// level disambiguateStructuredScopeByName itself operates: given the two
// scopes' own rows/columns, a question, and their declared display names
// (source_connection.name, as structuredScopeNames would resolve them), it
// must pick the one source_scope_id the question is actually about.
func demoStructuredSourceNames() map[string]string {
	return map[string]string{
		"scope_fleet":   "\u0420\u0435\u0439\u0441\u044b \u043c\u0443\u0441\u043e\u0440\u043e\u0432\u043e\u0437\u043e\u0432 (\u043e\u043f\u0435\u0440\u0430\u0442\u0438\u0432\u043d\u0430\u044f \u0431\u0430\u0437\u0430)",
		"scope_citizen": "\u041e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0433\u0440\u0430\u0436\u0434\u0430\u043d (\u043e\u043f\u0435\u0440\u0430\u0442\u0438\u0432\u043d\u0430\u044f \u0431\u0430\u0437\u0430)",
	}
}

func TestDisambiguateStructuredScopeByNamePicksFleetForVehicleQuestion(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	rows := twoActiveStructuredSourcesSnapshot(today)
	order := []string{"scope_citizen", "scope_fleet"}
	scopeID, ok := disambiguateStructuredScopeByName(rows, order, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?", demoStructuredSourceNames())
	if !ok || scopeID != "scope_fleet" {
		t.Fatalf("disambiguateStructuredScopeByName=(%q,%v) want (scope_fleet,true) -- \"\u0440\u0435\u0439\u0441\u0435\" stem-matches the fleet source's own declared name", scopeID, ok)
	}
}

func TestDisambiguateStructuredScopeByNamePicksCitizenForOverdueQuestion(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	rows := twoActiveStructuredSourcesSnapshot(today)
	order := []string{"scope_citizen", "scope_fleet"}
	scopeID, ok := disambiguateStructuredScopeByName(rows, order, "\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0433\u0440\u0430\u0436\u0434\u0430\u043d \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u044b?", demoStructuredSourceNames())
	if !ok || scopeID != "scope_citizen" {
		t.Fatalf("disambiguateStructuredScopeByName=(%q,%v) want (scope_citizen,true) -- \"\u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f\"/\"\u0433\u0440\u0430\u0436\u0434\u0430\u043d\" stem-match the citizen source's own declared name", scopeID, ok)
	}
}

func TestDisambiguateStructuredScopeByNameDeclinesOnRealTie(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	rows := twoActiveStructuredSourcesSnapshot(today)
	order := []string{"scope_citizen", "scope_fleet"}
	if scopeID, ok := disambiguateStructuredScopeByName(rows, order, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u0441\u0435\u0433\u043e \u0441\u0442\u0440\u043e\u043a \u0432 \u0431\u0430\u0437\u0435?", demoStructuredSourceNames()); ok {
		t.Fatalf("a question naming neither source must not guess -- got scope=%q", scopeID)
	}
}

// TestSnapshotAggregateBothQualifyWhenNoDistinguishingPredicate documents the
// exact ambiguity qualifyingStructuredSnapshotGroups must report as ">1", the
// same fixture TestSnapshotAggregateDeclinesWhenTwoStructuredSourcesBothResolveTheWindow
// exercises through selectStructuredSnapshotGroup's collapsed decline: with
// no predicate naming a column unique to one source, both the fleet and the
// citizen-requests source resolve "today" on their own.
func TestSnapshotAggregateBothQualifyWhenNoDistinguishingPredicate(t *testing.T) {
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	combined := twoActiveStructuredSourcesSnapshot(today)
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	qualifying, order := qualifyingStructuredSnapshotGroups(combined, plan, today, "UTC")
	if len(order) != 2 {
		t.Fatalf("qualifying order=%v want exactly 2 (both sources resolve today's window)", order)
	}
	if _, ok := qualifying["scope_fleet"]; !ok {
		t.Fatalf("expected scope_fleet among the qualifying groups: %v", order)
	}
	if _, ok := qualifying["scope_citizen"]; !ok {
		t.Fatalf("expected scope_citizen among the qualifying groups: %v", order)
	}
}

func TestPlannerRecognizesOverdueConditionMarker(t *testing.T) {
	for _, question := range []string{
		"\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0433\u0440\u0430\u0436\u0434\u0430\u043d \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u044b?",
		"\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u043d\u044b\u0435?",
		"which requests are overdue?",
	} {
		plan := mustPlan(t, question)
		found := false
		for _, filter := range plan.Filters {
			if filter.Name == "condition" && filter.Value == "overdue" {
				found = true
			}
		}
		if !found {
			t.Fatalf("question=%q filters=%+v want a declared condition=overdue filter", question, plan.Filters)
		}
	}
}
