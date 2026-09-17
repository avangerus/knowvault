package question

import (
	"context"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/planner"
)

const (
	testContentHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testTextHash    = "hmac-sha256:k1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testAnchorHash  = "hmac-sha256:k1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func testAggregateCandidate(id, row, text string) candidate {
	column := strings.TrimSpace(strings.SplitN(text, " = ", 2)[0])
	anchor := `{"kind":"POSTGRESQL_QUERY_CELL","projection_lineage_id":"lineage-test","row_version_hash":"` + row + `","column_name":"` + column + `"}`
	return candidate{
		ID: id, SourceObjectID: "object_" + row, SourceVersionID: "version_" + row,
		ExtractionID: "extraction_" + row, Text: []byte(text), Anchor: []byte(anchor),
		ContentHash: testContentHash, TextHash: testTextHash, AnchorHash: testAnchorHash,
	}
}

func testJSONAggregateCandidate(id, row, path, text string) candidate {
	return candidate{
		ID: id, SourceObjectID: "object_" + row, SourceVersionID: "version_" + row,
		ExtractionID: "extraction_" + row, Text: []byte(text),
		Anchor:      []byte(`{"kind":"POSTGRESQL_QUERY_CELL","projection_lineage_id":"lineage-json","row_version_hash":"` + row + `","column_name":"payload","json_path":"` + path + `"}`),
		ContentHash: testContentHash, TextHash: testTextHash, AnchorHash: testAnchorHash,
	}
}

func TestRenderAnswerAggregatesStructuredNumericEvidence(t *testing.T) {
	selected := []candidate{
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "row_a", "tonnes = 12.345"),
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAW", "row_b", "tonnes = 7.125"),
	}
	answer, citations := renderAnswer("ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", selected)
	if answer != "Total: 19.470" || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%d", answer, len(citations))
	}
}

func TestRenderCitationUsesTrustedKeyedEvidenceHash(t *testing.T) {
	selected := []candidate{
		{
			ID: "fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", Text: []byte("status = confirmed"),
			Anchor:         []byte(`{"kind":"TEXT","line_start":1,"line_end":1}`),
			SourceObjectID: "object_01ARZ3NDEKTSV4RRFFQ69G5FAV", SourceVersionID: "version_01ARZ3NDEKTSV4RRFFQ69G5FAV",
			ExtractionID: "extraction_01ARZ3NDEKTSV4RRFFQ69G5FAV", ContentHash: testContentHash,
			TextHash: testTextHash, AnchorHash: testAnchorHash,
		},
		{
			ID: "fragment_01ARZ3NDEKTSV4RRFFQ69G5FAW", Text: []byte("status = pending"),
			Anchor:         []byte(`{"kind":"TEXT","line_start":2,"line_end":2}`),
			SourceObjectID: "object_01ARZ3NDEKTSV4RRFFQ69G5FAW", SourceVersionID: "version_01ARZ3NDEKTSV4RRFFQ69G5FAW",
			ExtractionID: "extraction_01ARZ3NDEKTSV4RRFFQ69G5FAW", ContentHash: testContentHash,
			TextHash: testTextHash, AnchorHash: testAnchorHash,
		},
	}
	planned, err := planner.Default().Plan("\u0435\u0441\u0442\u044c \u043b\u0438 \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u043c\u0435\u0436\u0434\u0443 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u043c\u0438 status")
	if err != nil {
		t.Fatal(err)
	}
	_, citations := renderAnswerPlanAt("ws_demo", "\u0435\u0441\u0442\u044c \u043b\u0438 \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u043c\u0435\u0436\u0434\u0443 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u043c\u0438 status", planned, selected, time.Unix(1, 0).UTC())
	if len(citations) != 2 {
		t.Fatalf("citations=%d, want two trusted citations", len(citations))
	}
	if citations[0].EvidenceTextHash != testTextHash {
		t.Fatalf("citation hash=%q, want trusted keyed hash %q", citations[0].EvidenceTextHash, testTextHash)
	}
}

func TestUngroupedAggregateUsesSealedGenericToolReceipt(t *testing.T) {
	selected := []candidate{
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "row_a", "tonnes = 12.345"),
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAW", "row_b", "tonnes = 7.125"),
	}
	planned, err := planner.Default().Plan("\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?")
	if err != nil {
		t.Fatal(err)
	}
	answer, citations, receipt := renderAnswerPlanAtWithReceipt("ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", planned, selected, time.Unix(1, 0).UTC())
	if answer != "Total: 19.470" || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%d", answer, len(citations))
	}
	if receipt == nil || receipt.Status != "SUCCEEDED" || receipt.ToolID == "" || receipt.PlanHash != planned.PlanHash || receipt.ReceiptHash == "" {
		t.Fatalf("missing generic tool receipt: %+v", receipt)
	}
}

func TestMultiDimensionalAggregateRendersEveryGroupEvidenceCitation(t *testing.T) {
	selected := []candidate{
		testAggregateCandidate("region_row_a", "row_a", "region = North"),
		testAggregateCandidate("channel_row_a", "row_a", "channel = Web"),
		testAggregateCandidate("amount_row_a", "row_a", "amount = 7"),
		testAggregateCandidate("region_row_b", "row_b", "region = North"),
		testAggregateCandidate("channel_row_b", "row_b", "channel = Web"),
		testAggregateCandidate("amount_row_b", "row_b", "amount = 5"),
		testAggregateCandidate("region_row_c", "row_c", "region = South"),
		testAggregateCandidate("channel_row_c", "row_c", "channel = Store"),
		testAggregateCandidate("amount_row_c", "row_c", "amount = 10"),
	}
	planned, err := planner.Default().Plan("aggregate entity orders metric_field=amount group_by=region,channel top=2 order=desc")
	if err != nil {
		t.Fatal(err)
	}
	answer, citations, receipt := renderAnswerPlanAtWithReceipt("ws_demo", "aggregate entity orders metric_field=amount group_by=region,channel top=2 order=desc", planned, selected, time.Unix(1, 0).UTC())
	if !strings.HasPrefix(answer, "1. North / Web: 12") || !strings.Contains(answer, "2. South / Store: 10") {
		t.Fatalf("multi-group answer=%q", answer)
	}
	if receipt == nil || receipt.Status != "SUCCEEDED" {
		t.Fatalf("multi-group receipt=%+v", receipt)
	}
	if len(citations) != 7 {
		t.Fatalf("multi-group citations=%d, want numeric and two-dimensional labels for both buckets", len(citations))
	}
	seen := make(map[string]struct{}, len(citations))
	for _, citation := range citations {
		if citation.EvidenceFragment == "" || citation.DeepLink == "" || citation.SourceVersionID == "" {
			t.Fatalf("incomplete citation=%+v", citation)
		}
		seen[citation.EvidenceFragment] = struct{}{}
	}
	for _, id := range []string{"amount_row_a", "amount_row_b", "region_row_c", "channel_row_c", "amount_row_c"} {
		if _, ok := seen[id]; !ok {
			t.Fatalf("missing evidence citation %q: %v", id, seen)
		}
	}
	if _, northRegionA := seen["region_row_a"]; !northRegionA {
		if _, northRegionB := seen["region_row_b"]; !northRegionB {
			t.Fatalf("missing North region witness: %v", seen)
		}
	}
	if _, northChannelA := seen["channel_row_a"]; !northChannelA {
		if _, northChannelB := seen["channel_row_b"]; !northChannelB {
			t.Fatalf("missing North channel witness: %v", seen)
		}
	}
}

func TestJSONPathAggregateKeepsNumericFieldsDistinctAndEvidenceBound(t *testing.T) {
	selected := []candidate{
		testJSONAggregateCandidate("json_fragment_a", "json_row_a", "/metrics/kg", "payload[/metrics/kg] = 12.5"),
		testJSONAggregateCandidate("json_fragment_b", "json_row_b", "/metrics/kg", "payload[/metrics/kg] = 7.5"),
	}
	planned, err := planner.Default().Plan("\u0441\u043a\u043e\u043b\u044c\u043a\u043e payload metrics")
	if err != nil {
		t.Fatal(err)
	}
	answer, citations, receipt := renderAnswerPlanAtWithReceipt("ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e payload metrics", planned, selected, time.Unix(1, 0).UTC())
	if answer != "Total: 20.0" || len(citations) != 2 || receipt == nil || receipt.Status != "SUCCEEDED" {
		t.Fatalf("answer=%q citations=%d receipt=%+v", answer, len(citations), receipt)
	}
	for _, citation := range citations {
		if !strings.Contains(citation.Anchor, `"json_path":"/metrics/kg"`) {
			t.Fatalf("citation lost JSON path anchor: %s", citation.Anchor)
		}
	}
}

func TestJSONPathMultiDimensionalAggregateRendersPathCitations(t *testing.T) {
	selected := []candidate{
		testJSONAggregateCandidate("json-region-a", "json-row-a", "/Region", `payload[/Region] = "North"`),
		testJSONAggregateCandidate("json-channel-a", "json-row-a", "/Channel", `payload[/Channel] = "Web"`),
		testJSONAggregateCandidate("json-amount-a", "json-row-a", "/Amount", "payload[/Amount] = 7"),
		testJSONAggregateCandidate("json-region-b", "json-row-b", "/Region", `payload[/Region] = "South"`),
		testJSONAggregateCandidate("json-channel-b", "json-row-b", "/Channel", `payload[/Channel] = "Store"`),
		testJSONAggregateCandidate("json-amount-b", "json-row-b", "/Amount", "payload[/Amount] = 10"),
	}
	questionText := "aggregate entity records metric_field=payload[/Amount] group_by=payload[/Region],payload[/Channel] top=2 order=desc"
	planned, err := planner.Default().Plan(questionText)
	if err != nil {
		t.Fatal(err)
	}
	answer, citations, receipt := renderAnswerPlanAtWithReceipt("ws_demo", questionText, planned, selected, time.Unix(1, 0).UTC())
	if !strings.Contains(answer, "North / Web") || !strings.Contains(answer, "South / Store") || receipt == nil || receipt.Status != "SUCCEEDED" {
		t.Fatalf("JSON-path multi-group answer=%q receipt=%+v", answer, receipt)
	}
	if len(citations) != 6 {
		t.Fatalf("JSON-path multi-group citations=%d, want six exact path witnesses", len(citations))
	}
	for _, citation := range citations {
		if !strings.Contains(citation.Anchor, `"json_path":"/`) || citation.DeepLink == "" {
			t.Fatalf("JSON-path citation lost anchor/link: %+v", citation)
		}
	}
}

func TestRequestCancellationStopsAnalyticRendering(t *testing.T) {
	selected := []candidate{
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "row_a", "tonnes = 12.345"),
	}
	planned, err := planner.Default().Plan("\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	answer, citations, receipt := renderAnswerPlanAtWithReceiptContext(ctx, "ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", planned, selected, time.Unix(1, 0).UTC())
	if answer != "" || len(citations) != 0 || receipt != nil {
		t.Fatalf("cancelled request rendered analytic result: answer=%q citations=%d receipt=%+v", answer, len(citations), receipt)
	}
}

func TestCandidateForCitationUsesEvidenceIDNotSelectionPosition(t *testing.T) {
	selected := []candidate{
		{ID: "context-cell", Text: []byte("stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432")},
		{ID: "numeric-cell", Text: []byte("tonnes = 12.345")},
	}
	item, ok := candidateForCitation(selected, "numeric-cell")
	if !ok || item.ID != "numeric-cell" {
		t.Fatalf("candidateForCitation returned=%#v ok=%v", item, ok)
	}
	if _, ok := candidateForCitation(selected, "missing-cell"); ok {
		t.Fatal("missing evidence lineage was accepted")
	}
}

func TestRenderAnswerDoesNotAggregateMixedEvidence(t *testing.T) {
	selected := []candidate{testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "row_a", "North route")}
	answer, citations := renderAnswer("ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", selected)
	if answer != "" || len(citations) != 0 {
		t.Fatalf("unresolved aggregate was disclosed: answer=%q citations=%d", answer, len(citations))
	}
}

func TestRenderAnswerDoesNotSumDifferentPostgreSQLColumns(t *testing.T) {
	selected := []candidate{
		testAggregateCandidate("fragment_tonnes", "row_a", "tonnes = 12.345"),
		testAggregateCandidate("fragment_distance", "row_b", "distance = 7.125"),
	}
	answer, citations := renderAnswer("ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u0441\u0435\u0433\u043e?", selected)
	if answer != "" || len(citations) != 0 {
		t.Fatalf("mixed columns were disclosed: answer=%q citations=%d", answer, len(citations))
	}
}

func TestSelectCandidatesFailsClosedWithoutLexicalEvidence(t *testing.T) {
	candidates := []candidate{
		{ID: "fragment_unrelated", Text: []byte("North route closed")},
		{ID: "fragment_numeric", Text: []byte("tonnes = 42")},
	}
	if selected := selectCandidates(candidates, "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?"); len(selected) != 0 {
		t.Fatalf("unrelated evidence was selected: %+v", selected)
	}
}

func TestSelectCandidatesDoesNotUseCorpusForEmptySearchTerms(t *testing.T) {
	candidates := []candidate{{ID: "fragment_any", Text: []byte("arbitrary evidence")}}
	if selected := selectCandidates(candidates, "\u0430"); len(selected) != 0 {
		t.Fatalf("empty search terms selected corpus evidence: %+v", selected)
	}
}
