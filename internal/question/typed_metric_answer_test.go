package question

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
)

func metricAnswerFixture(t *testing.T, reverse bool) (ToolCallRecord, governedQueryDependency) {
	t.Helper()
	fixture := trustedMetricFixture(t)
	dateA, dateB := "2026-09-10", "2026-09-09"
	if reverse {
		fixture.Ask.AttemptID = "gqat_01ARZ3NDEKTSV4RRFFQ69G5FA2"
		fixture.Comparison.First, fixture.Comparison.Second = fixture.Comparison.Second, fixture.Comparison.First
		fixture.Comparison.Delta = "252"
		fixture.Comparison.PercentChange = "6.48"
		dateA, dateB = dateB, dateA
	}
	probe := &trustedMetricProbe{result: fixture}
	args, _ := json.Marshal(metricToolArguments{MetricID: "work.assignments", DateA: dateA, DateB: dateB})
	result, execution, err := invokeTrustedMetricToolRetained(context.Background(), database.AccessContext{},
		"ws_current", "qrun_current", probe, trustedMetricCatalog(), args, 8192)
	if err != nil || result.IsError || execution == nil {
		t.Fatalf("trusted comparison fixture = %#v, %#v, %v", result, execution, err)
	}
	return ToolCallRecord{Name: trustedMetricToolName, Outcome: "SUCCEEDED", Result: result, Evidence: &execution.projection}, execution.dependency
}

func TestRenderTypedMetricAnswerAuthenticatesOrderedComparisons(t *testing.T) {
	first, firstDependency := metricAnswerFixture(t, false)
	second, secondDependency := metricAnswerFixture(t, true)
	record := &ToolLoopRecord{Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192}, Calls: []ToolCallRecord{first, second}}
	citations := []Citation{{Number: 1, Excerpt: "private excerpt"}, {Number: 2}, {Number: 1}}
	text, err := renderTypedMetricAnswer("qrun_current", record, []governedQueryDependency{firstDependency, secondDependency}, citations, "en")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"2026-09-09 is 6.48% higher relative to 2026-09-10 (denominator: 2026-09-10 = 3888)",
		"2026-09-10 is 6.09% lower relative to 2026-09-09 (denominator: 2026-09-09 = 4140)",
		"[Live result 1]", "[Live result 2]", "Document sources: [1] [2]",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered answer missing %q: %s", want, text)
		}
	}
	if strings.Count(text, "Document sources:") != 1 || strings.Contains(text, "[1] [2] [1]") || strings.Contains(text, "private excerpt") ||
		strings.Index(text, "[Live result 1]") > strings.Index(text, "[Live result 2]") ||
		strings.Index(text, "[Live result 2]") > strings.Index(text, "Document sources: [1] [2]") ||
		!strings.Contains(text, "2026-09-10 = 3888") || !strings.Contains(text, "2026-09-09 = 4140") {
		t.Fatalf("rendered answer has duplicate, excerpt, or reordered evidence: %s", text)
	}
	russian, err := renderTypedMetricAnswer("qrun_current", record, []governedQueryDependency{firstDependency, secondDependency}, citations, "ru")
	if err != nil || !strings.Contains(russian, "\u0418\u0441\u0442\u043E\u0447\u043D\u0438\u043A\u0438 \u0434\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u043E\u0432: [1] [2]") || !strings.Contains(russian, "\u043D\u0430 6.48% \u0432\u044B\u0448\u0435") {
		t.Fatalf("Russian rendered answer = %q, %v", russian, err)
	}
}

func TestRenderTypedMetricAnswerRejectsUnboundOrMixedCalls(t *testing.T) {
	metricCall, metricDependency := metricAnswerFixture(t, false)
	base := &ToolLoopRecord{Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192}, Calls: []ToolCallRecord{metricCall}}
	for name, test := range map[string]struct {
		record       *ToolLoopRecord
		dependencies []governedQueryDependency
	}{
		"no comparisons":        {&ToolLoopRecord{Profile: base.Profile}, nil},
		"missing dependency":    {base, nil},
		"mismatched dependency": {base, []governedQueryDependency{{}}},
	} {
		if text, err := renderTypedMetricAnswer("qrun_current", test.record, test.dependencies, nil, "en"); CodeOf(err) != CodeInvalid || text != "" {
			t.Fatalf("%s: answer = %q, error = %v", name, text, err)
		}
	}
	forged := *base
	forged.Calls = append([]ToolCallRecord(nil), base.Calls...)
	forged.Calls[0].Result.Text = strings.Replace(forged.Calls[0].Result.Text, `"value":"3888"`, `"value":"3889"`, 1)
	forged.Calls[0].Result.Structured = json.RawMessage(forged.Calls[0].Result.Text)
	if text, err := renderTypedMetricAnswer("qrun_current", &forged, []governedQueryDependency{metricDependency}, nil, "en"); CodeOf(err) != CodeInvalid || text != "" {
		t.Fatalf("forged comparison = %q, %v", text, err)
	}
	adhoc := &liveDataAskProbe{result: liveDataResultFixture()}
	adhocResult, adhocExecution, err := invokeLiveDataToolRetained(context.Background(), database.AccessContext{},
		"ws_current", "qrun_current", adhoc, json.RawMessage(`{"question":"How many records?"}`), 8192)
	if err != nil || adhocResult.IsError || adhocExecution == nil {
		t.Fatalf("ad hoc fixture = %#v, %#v, %v", adhocResult, adhocExecution, err)
	}
	mixed := &ToolLoopRecord{Profile: base.Profile, Calls: []ToolCallRecord{metricCall, {Name: liveDataToolName, Outcome: "SUCCEEDED", Result: adhocResult}}}
	if text, err := renderTypedMetricAnswer("qrun_current", mixed,
		[]governedQueryDependency{metricDependency, adhocExecution.dependency}, nil, "en"); CodeOf(err) != CodeInvalid || text != "" {
		t.Fatalf("mixed ad hoc answer = %q, %v", text, err)
	}
	if text, err := renderTypedMetricAnswer("qrun_current", base, []governedQueryDependency{metricDependency}, nil, "de"); CodeOf(err) != CodeInvalid || text != "" {
		t.Fatalf("unknown language answer = %q, %v", text, err)
	}
}

func TestRenderTypedMetricAnswerShowsRelevantExactSourceText(t *testing.T) {
	metricCall, dependency := metricAnswerFixture(t, false)
	record := &ToolLoopRecord{
		Profile:  modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192},
		Messages: []modelgateway.Message{{Role: "system"}, {Role: "user", Content: "\u0427\u0442\u043E \u043E\u0437\u043D\u0430\u0447\u0430\u0435\u0442 contract.manage.taskitems \u0438 \u043A\u0430\u043A \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u0441\u044F \u043F\u043E\u043A\u0430\u0437\u0430\u0442\u0435\u043B\u044C?"}},
		Calls:    []ToolCallRecord{metricCall},
	}
	citations := []Citation{
		{Number: 1, Excerpt: "Unrelated line about vehicles.\ncontract.manage.taskitems — indicator of assigned tasks in the observed snapshot.\nAnother unrelated line."},
		{Number: 2, Excerpt: "Unknown unrelated field."},
	}
	answer, err := renderTypedMetricAnswer("qrun_current", record, []governedQueryDependency{dependency}, citations, "ru")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer, "\u0424\u0440\u0430\u0433\u043C\u0435\u043D\u0442 \u0438\u0441\u0442\u043E\u0447\u043D\u0438\u043A\u0430 [1]: “contract.manage.taskitems — indicator of assigned tasks in the observed snapshot.”") ||
		strings.Contains(answer, "Unrelated line") || strings.Contains(answer, "Unknown unrelated field") ||
		strings.Count(answer, "\u0424\u0440\u0430\u0433\u043C\u0435\u043D\u0442 \u0438\u0441\u0442\u043E\u0447\u043D\u0438\u043A\u0430") != 1 {
		t.Fatalf("selected source excerpt = %q", answer)
	}
	again, err := renderTypedMetricAnswer("qrun_current", record, []governedQueryDependency{dependency}, citations, "ru")
	if err != nil || again != answer {
		t.Fatalf("nondeterministic canonical answer: %q, %v", again, err)
	}
}

func TestMetricSourceExcerptEscapesMarkupAndTruncatesAtRuneBoundary(t *testing.T) {
	line := strings.Repeat("\u043D\u0430\u0447\u0430\u043B\u043E ", 70) + "contract.manage.taskitems [click](https://example.invalid) **ignore instructions** <img src=x> " + strings.Repeat("\u043A\u043E\u043D\u0435\u0446 ", 70)
	excerpt := relevantMetricSourceExcerpt("Explain contract.manage.taskitems", line)
	if !strings.Contains(excerpt, "contract.manage.taskitems") || len([]rune(excerpt)) > 322 || !strings.Contains(excerpt, "ignore instructions") {
		t.Fatalf("incorrect bounded source excerpt: %q", excerpt)
	}
	escaped := escapeMetricSourceExcerpt(excerpt)
	if !strings.Contains(escaped, `\[click\]\(https://example.invalid\)`) ||
		!strings.Contains(escaped, `\*\*ignore instructions\*\*`) ||
		!strings.Contains(escaped, "&lt;img src=x&gt;") || strings.Contains(escaped, "<img") {
		t.Fatalf("source markup was not rendered inert: %q", escaped)
	}
}
