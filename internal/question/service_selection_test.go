package question

import (
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func testPostgreSQLCell(row, column string) []byte {
	return []byte(`{"kind":"POSTGRESQL_QUERY_CELL","projection_lineage_id":"lineage-waste","row_version_hash":"` + row + `","column_name":"` + column + `"}`)
}

func testPostgreSQLCandidate(id, row, column, text string) candidate {
	anchor := testPostgreSQLCell(row, column)
	return candidate{
		ID: id, SourceObjectID: "object_" + row, SourceVersionID: "version_" + row,
		ExtractionID: "extraction_" + row, Text: []byte(text), Anchor: anchor,
		ContentHash: canon.Hash([]byte("content:" + row)), TextHash: "hmac-sha256:k1:" + strings.Repeat("b", 64),
		AnchorHash: "hmac-sha256:k1:" + strings.Repeat("c", 64),
	}
}

func TestSelectCandidatesExpandsDateScopedAggregateWithinRows(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("label_today_1", "row_1", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("date_today_1", "row_1", "collected_at", "collected_at = 2026-08-29T09:34:56Z"),
		testPostgreSQLCandidate("tonnes_today_1", "row_1", "tonnes", "tonnes = 12.345"),
		testPostgreSQLCandidate("label_today_2", "row_2", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("date_today_2", "row_2", "collected_at", "collected_at = 2026-08-29T10:34:56Z"),
		testPostgreSQLCandidate("tonnes_today_2", "row_2", "tonnes", "tonnes = 7.125"),
		testPostgreSQLCandidate("label_yesterday", "row_3", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("date_yesterday", "row_3", "collected_at", "collected_at = 2026-08-28T10:34:56Z"),
		testPostgreSQLCandidate("tonnes_yesterday", "row_3", "tonnes", "tonnes = 100.000"),
	}
	question := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?"
	planned, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatal(err)
	}
	selected := selectCandidatesAt(candidates, question, now)
	answer, citations := renderAnswerPlanAt("ws_demo", question, planned, selected, now)
	if answer != "Total: 19.470" || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%d selected=%d", answer, len(citations), len(selected))
	}
	for _, citation := range citations {
		if strings.Contains(citation.Excerpt, "100.000") {
			t.Fatal("yesterday row entered today's aggregate")
		}
	}
}

func TestSelectCandidatesExpandsCurrentMonthAndExcludesPriorMonth(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("label_aug_1", "row_aug_1", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("date_aug_1", "row_aug_1", "collected_at", "collected_at = 2026-08-05T09:34:56Z"),
		testPostgreSQLCandidate("tonnes_aug_1", "row_aug_1", "tonnes", "tonnes = 12.345"),
		testPostgreSQLCandidate("label_aug_2", "row_aug_2", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("date_aug_2", "row_aug_2", "collected_at", "collected_at = 2026-08-20T10:34:56Z"),
		testPostgreSQLCandidate("tonnes_aug_2", "row_aug_2", "tonnes", "tonnes = 7.125"),
		testPostgreSQLCandidate("label_jul", "row_jul", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("date_jul", "row_jul", "collected_at", "collected_at = 2026-07-31T10:34:56Z"),
		testPostgreSQLCandidate("tonnes_jul", "row_jul", "tonnes", "tonnes = 100.000"),
	}
	question := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0432 \u044d\u0442\u043e\u043c \u043c\u0435\u0441\u044f\u0446\u0435?"
	planned, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatal(err)
	}
	selected := selectCandidatesAt(candidates, question, now)
	answer, citations := renderAnswerPlanAt("ws_demo", question, planned, selected, now)
	if answer != "Total: 19.470" || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%d selected=%d", answer, len(citations), len(selected))
	}
	for _, citation := range citations {
		if strings.Contains(citation.Excerpt, "100.000") {
			t.Fatal("prior-month row entered current-month aggregate")
		}
	}
}

func TestSelectCandidatesHonorsExplicitAndRelativeDateRanges(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("label_in", "row_in", "stream", "stream = requests"),
		testPostgreSQLCandidate("date_in", "row_in", "collected_at", "collected_at = 2026-08-10T09:00:00Z"),
		testPostgreSQLCandidate("amount_in", "row_in", "tonnes", "tonnes = 4.000"),
		testPostgreSQLCandidate("label_edge", "row_edge", "stream", "stream = requests"),
		testPostgreSQLCandidate("date_edge", "row_edge", "collected_at", "collected_at = 2026-08-16T09:00:00Z"),
		testPostgreSQLCandidate("amount_edge", "row_edge", "tonnes", "tonnes = 6.000"),
		testPostgreSQLCandidate("label_old", "row_old", "stream", "stream = requests"),
		testPostgreSQLCandidate("date_old", "row_old", "collected_at", "collected_at = 2026-06-30T09:00:00Z"),
		testPostgreSQLCandidate("amount_old", "row_old", "tonnes", "tonnes = 100.000"),
	}
	for _, tc := range []struct {
		question string
		want     string
	}{
		{question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e requests \u0441 2026-08-02 \u043f\u043e 2026-08-15?", want: "Total: 4.000"},
		{question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e requests \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 30 \u0434\u043d\u0435\u0439?", want: "Total: 10.000"},
	} {
		planned, err := planner.Default().Plan(tc.question)
		if err != nil {
			t.Fatalf("%q: %v", tc.question, err)
		}
		selected := selectCandidatesAt(candidates, tc.question, now)
		answer, citations := renderAnswerPlanAt("ws_demo", tc.question, planned, selected, now)
		if answer != tc.want || len(citations) != 1 && tc.want == "Total: 4.000" || len(citations) != 2 && tc.want == "Total: 10.000" {
			t.Fatalf("%q answer=%q citations=%d selected=%d", tc.question, answer, len(citations), len(selected))
		}
		for _, citation := range citations {
			if strings.Contains(citation.Excerpt, "100.000") {
				t.Fatalf("%q included out-of-range row", tc.question)
			}
		}
	}
}

func TestSelectCandidatesHonorsGenericEqualityFilter(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("status_active", "row_active", "status", "status = active"),
		testPostgreSQLCandidate("amount_active", "row_active", "amount", "amount = 4.000"),
		testPostgreSQLCandidate("status_inactive", "row_inactive", "status", "status = inactive"),
		testPostgreSQLCandidate("amount_inactive", "row_inactive", "amount", "amount = 100.000"),
	}
	question := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e requests \u0433\u0434\u0435 status = active?"
	planned, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatal(err)
	}
	selected := selectCandidatesAt(candidates, question, now)
	answer, citations := renderAnswerPlanAt("ws_demo", question, planned, selected, now)
	if answer != "Total: 4.000" || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%d selected=%d planned=%+v", answer, len(citations), len(selected), planned)
	}
	for _, citation := range citations {
		if strings.Contains(citation.Excerpt, "100.000") || strings.Contains(citation.Excerpt, "inactive") {
			t.Fatal("inactive row entered filtered aggregate")
		}
	}
}

func TestSelectCandidatesAggregateRequiresConjunctiveEqualityWitnesses(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("status_good", "row_good", "status", "status = active"),
		testPostgreSQLCandidate("region_good", "row_good", "region", "region = north"),
		testPostgreSQLCandidate("amount_good", "row_good", "amount", "amount = 4.000"),
		testPostgreSQLCandidate("status_partial", "row_status_only", "status", "status = active"),
		testPostgreSQLCandidate("region_partial", "row_status_only", "region", "region = south"),
		testPostgreSQLCandidate("amount_partial", "row_status_only", "amount", "amount = 100.000"),
		testPostgreSQLCandidate("status_other", "row_region_only", "status", "status = inactive"),
		testPostgreSQLCandidate("region_other", "row_region_only", "region", "region = north"),
		testPostgreSQLCandidate("amount_other", "row_region_only", "amount", "amount = 200.000"),
	}
	question := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e amount \u0433\u0434\u0435 status = active \u0438 region = north?"
	planned, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatal(err)
	}
	if planned.Operation != planner.Aggregate || len(planned.Filters) != 2 {
		t.Fatalf("unexpected plan: %+v", planned)
	}
	selected := selectCandidatesAt(candidates, question, now)
	foundGoodMetric := false
	for _, item := range selected {
		switch item.ID {
		case "amount_good":
			foundGoodMetric = true
		case "amount_partial", "amount_other", "status_partial", "region_partial", "status_other", "region_other":
			t.Fatalf("aggregate admitted a row without the complete equality conjunction: %+v", selected)
		}
	}
	if !foundGoodMetric {
		t.Fatalf("aggregate dropped sibling metric from the row satisfying every equality predicate: %+v", selected)
	}
	answer, citations := renderAnswerPlanAt("ws_demo", question, planned, selected, now)
	if answer != "Total: 4.000" || len(citations) == 0 {
		t.Fatalf("answer=%q citations=%d selected=%d", answer, len(citations), len(selected))
	}
}

func TestSelectCandidatesAppliesTemporalScopeToNonAggregateOperations(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("label_in", "row_in", "stream", "stream = requests"),
		testPostgreSQLCandidate("date_in", "row_in", "collected_at", "collected_at = 2026-08-29T09:00:00Z"),
		testPostgreSQLCandidate("label_out", "row_out", "stream", "stream = requests"),
		testPostgreSQLCandidate("date_out", "row_out", "collected_at", "collected_at = 2026-08-28T09:00:00Z"),
	}
	for _, question := range []string{
		"\u043f\u043e\u043a\u0430\u0436\u0438 requests \u0441\u0435\u0433\u043e\u0434\u043d\u044f",
		"\u0441\u0440\u0430\u0432\u043d\u0438 requests \u0441\u0435\u0433\u043e\u0434\u043d\u044f",
		"\u043f\u0440\u043e\u0432\u0435\u0440\u044c requests \u0441\u0435\u0433\u043e\u0434\u043d\u044f",
	} {
		planned, err := planner.Default().Plan(question)
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		selected := selectCandidatesAt(candidates, question, now)
		if len(selected) != 1 || selected[0].ID != "label_in" {
			t.Fatalf("%q selected=%v planned=%+v", question, selected, planned)
		}
	}
}

func TestSelectCandidatesAllowsDirectTemporalMentionInTextEvidence(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	anchor, err := canon.TextAnchorBytes(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	item := candidate{
		ID: "text_today", SourceObjectID: "document_today", SourceVersionID: "version_today",
		ExtractionID: "extraction_today", Text: []byte("\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432."), Anchor: anchor,
		ContentHash: canon.Hash([]byte("content-today")), TextHash: "hmac-sha256:k1:" + strings.Repeat("b", 64),
		AnchorHash: "hmac-sha256:k1:" + strings.Repeat("c", 64),
	}
	planned, err := planner.Default().Plan("\u041f\u043e\u043a\u0430\u0436\u0438 \u043e\u0442\u0445\u043e\u0434\u044b \u0441\u0435\u0433\u043e\u0434\u043d\u044f")
	if err != nil {
		t.Fatal(err)
	}
	if planned.Operation == planner.Aggregate {
		t.Fatalf("test query unexpectedly planned as aggregate: %+v", planned)
	}
	selected := selectCandidatesAtPlan([]candidate{item}, planned, now)
	if len(selected) != 1 || selected[0].ID != item.ID {
		t.Fatalf("direct temporal text Evidence was rejected: selected=%+v plan=%+v", selected, planned)
	}
}

func TestSelectCandidatesAppliesEqualityScopeToNonAggregateOperations(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("status_active", "row_active", "status", "status = active"),
		testPostgreSQLCandidate("amount_active", "row_active", "amount", "amount = 4.000"),
		testPostgreSQLCandidate("status_inactive", "row_inactive", "status", "status = inactive"),
		testPostgreSQLCandidate("amount_inactive", "row_inactive", "amount", "amount = 100.000"),
	}
	for _, question := range []string{
		"\u043f\u043e\u043a\u0430\u0436\u0438 amount \u0433\u0434\u0435 status = active",
		"\u0441\u0440\u0430\u0432\u043d\u0438 amount \u0433\u0434\u0435 status = active",
		"\u043f\u0440\u043e\u0432\u0435\u0440\u044c amount \u0433\u0434\u0435 status = active",
	} {
		planned, err := planner.Default().Plan(question)
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		selected := selectCandidatesAt(candidates, question, now)
		foundAmount := false
		for _, item := range selected {
			if item.ID == "amount_active" {
				foundAmount = true
			}
			if item.ID == "amount_inactive" || item.ID == "status_inactive" {
				t.Fatalf("%q disclosed inactive row: %+v", question, selected)
			}
		}
		if !foundAmount {
			t.Fatalf("%q dropped sibling answer Evidence: selected=%v planned=%+v", question, selected, planned)
		}
	}
}

func TestSelectCandidatesPrioritizesExplicitFactKeyForNaturalCompare(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	textAnchor, err := canon.TextAnchorBytes(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	// The prose fragment intentionally contains the source nouns more often
	// than the structured cells. A MatchAny lexical page therefore ranks it
	// highly unless the generic field identity is used as a bounded hint.
	prose := candidate{
		ID: "prose-contracts-dispatches", SourceObjectID: "document-prose", SourceVersionID: "version-prose",
		ExtractionID: "extraction-prose", Text: []byte("contracts dispatches contracts dispatches status between sources"), Anchor: textAnchor,
		ContentHash: canon.Hash([]byte("content-prose")), TextHash: "hmac-sha256:k1:" + strings.Repeat("b", 64),
		AnchorHash: "hmac-sha256:k1:" + strings.Repeat("c", 64),
	}
	candidates := []candidate{
		prose,
		testPostgreSQLCandidate("status_active", "row_active", "payload[/status]", `payload[/status] = "ACTIVE"`),
		testPostgreSQLCandidate("status_completed", "row_completed", "payload[/status]", `payload[/status] = "COMPLETED"`),
	}
	planned, err := planner.Default().Plan("\u0441\u0440\u0430\u0432\u043d\u0438 status \u043c\u0435\u0436\u0434\u0443 contracts \u0438 dispatches")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Compare {
		t.Fatalf("compare plan: %+v %v", planned, err)
	}
	selected := selectCandidatesAtPlan(candidates, planned, now)
	if len(selected) < 2 || selected[0].ID == prose.ID || selected[1].ID == prose.ID {
		t.Fatalf("explicit field facts were not prioritized: %+v", selected)
	}
	answer, citations := renderCompareFacts("ws_demo", planned, selected)
	if !strings.Contains(answer, "Conflict for payload[/status]") || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%d selected=%+v", answer, len(citations), selected)
	}
}

func TestSelectCandidatesRejectsEqualityScopeWithoutWitness(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("amount", "row_without_status", "amount", "amount = 4.000"),
	}
	selected := selectCandidatesAt(candidates, "\u043f\u043e\u043a\u0430\u0436\u0438 amount \u0433\u0434\u0435 status = active", now)
	if len(selected) != 0 {
		t.Fatalf("equality predicate without witness was disclosed: %+v", selected)
	}
}

func TestSelectCandidatesRejectsMalformedPostgreSQLAnchorFallback(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	label := testPostgreSQLCandidate("label_bad_anchor", "row_same", "stream", "stream = requests")
	label.Anchor = []byte(`{"kind":"POSTGRESQL_QUERY_CELL","projection_lineage_id":"lineage-waste","row_version_hash":"row_same"}`)
	candidates := []candidate{
		label,
		testPostgreSQLCandidate("date_witness", "row_same", "collected_at", "collected_at = 2026-08-29T09:00:00Z"),
	}
	if key := candidateScopeKey(label); key != "" {
		t.Fatalf("malformed PG anchor received a scope key: %q", key)
	}
	selected := selectCandidatesAt(candidates, "\u043f\u043e\u043a\u0430\u0436\u0438 requests \u0441\u0435\u0433\u043e\u0434\u043d\u044f", now)
	if len(selected) != 0 {
		t.Fatalf("malformed PG anchor inherited sibling temporal witness: %+v", selected)
	}
}

func TestSelectCandidatesRejectsTemporalScopeWithoutDateEvidence(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("label", "row_undated", "stream", "stream = requests"),
	}
	selected := selectCandidatesAt(candidates, "\u043f\u043e\u043a\u0430\u0436\u0438 requests \u0441\u0435\u0433\u043e\u0434\u043d\u044f", now)
	if len(selected) != 0 {
		t.Fatalf("undated temporal candidate was disclosed: %+v", selected)
	}
}

func TestSelectCandidatesDoesNotAggregateWithoutDateEvidence(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("label", "row_1", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("tonnes", "row_1", "tonnes", "tonnes = 12.345"),
	}
	question := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?"
	planned, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatal(err)
	}
	selected := selectCandidatesAt(candidates, question, now)
	answer, citations := renderAnswerPlanAt("ws_demo", question, planned, selected, now)
	if answer != "" || len(citations) != 0 {
		t.Fatalf("aggregate without date evidence was disclosed: answer=%q citations=%d", answer, len(citations))
	}
}

func TestSelectCandidatesDoesNotAggregateAmbiguousMetricColumns(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	candidates := []candidate{
		testPostgreSQLCandidate("label", "row_1", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("date", "row_1", "collected_at", "collected_at = 2026-08-29T09:34:56Z"),
		testPostgreSQLCandidate("tonnes", "row_1", "tonnes", "tonnes = 12.345"),
		testPostgreSQLCandidate("distance", "row_1", "distance", "distance = 7.125"),
	}
	question := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?"
	planned, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatal(err)
	}
	selected := selectCandidatesAt(candidates, question, now)
	answer, _ := renderAnswerPlanAt("ws_demo", question, planned, selected, now)
	if answer == "Total: 19.470" || answer == "Total: 12.345" || answer == "Total: 7.125" {
		t.Fatalf("ambiguous metric was aggregated: %q", answer)
	}
}
