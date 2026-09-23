package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestCompletedTypedMetricAnswerOwnsDirectionalPercent(t *testing.T) {
	call, dependency := metricAnswerFixture(t, true)
	record := &ToolLoopRecord{Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192}, Calls: []ToolCallRecord{call},
		StopReason: "ANSWER", AllClaimsBound: true, ClaimEvidenceVersion: "v1"}
	// The model's earlier wording said the first date was 6.09% higher. The
	// observed 4140 relative to 3888 is 6.48% higher.
	answer, selected, err := completedTypedMetricAnswer("qrun_current", "\u0410 \u043A\u0430\u043A\u043E\u0439 \u0438\u0437 \u044D\u0442\u0438\u0445 \u0434\u0432\u0443\u0445 \u0434\u043D\u0435\u0439 \u0432\u044B\u0448\u0435 \u0438 \u043D\u0430 \u0441\u043A\u043E\u043B\u044C\u043A\u043E \u043F\u0440\u043E\u0446\u0435\u043D\u0442\u043E\u0432?", record,
		[]governedQueryDependency{dependency}, []Citation{{Number: 1}})
	if err != nil || !selected || !strings.Contains(answer, "6.48%") || !strings.Contains(answer, "\u0418\u0441\u0442\u043E\u0447\u043D\u0438\u043A\u0438 \u0434\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u043E\u0432: [1]") {
		t.Fatalf("typed answer = %q, selected=%v, error=%v", answer, selected, err)
	}
	if strings.Contains(answer, "6.09% \u0432\u044B\u0448\u0435") {
		t.Fatalf("incorrect direction survived: %s", answer)
	}
	if record.PresentationVersion == nil || *record.PresentationVersion != "metric-comparison-v2" ||
		record.PresentationLanguage == nil || *record.PresentationLanguage != "ru" ||
		record.PresentationAnswerHash == nil || *record.PresentationAnswerHash != canon.Hash([]byte(answer)) {
		t.Fatalf("typed answer envelope is missing or unbound: %#v", record)
	}
	english, selected, err := completedTypedMetricAnswer("qrun_current", "Which day is higher, and by what percent?", record,
		[]governedQueryDependency{dependency}, nil)
	if err != nil || !selected || !strings.Contains(english, "6.48%") || !strings.Contains(english, "Metric work.assignments") {
		t.Fatalf("English typed answer = %q, selected=%v, error=%v", english, selected, err)
	}
}

func TestCompletedTypedMetricAnswerSkipsAdHocAndFailsClosedOnBadMetric(t *testing.T) {
	call, dependency := metricAnswerFixture(t, false)
	record := &ToolLoopRecord{Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192}, Calls: []ToolCallRecord{call},
		StopReason: "ANSWER", AllClaimsBound: true, ClaimEvidenceVersion: "v1"}
	if answer, selected, err := completedTypedMetricAnswer("qrun_current", "Compare dates", record, nil, nil); !selected || CodeOf(err) != CodeInvalid || answer != "" {
		t.Fatalf("unbound metric = %q, selected=%v, error=%v", answer, selected, err)
	}
	if record.PresentationVersion != nil || record.PresentationLanguage != nil || record.PresentationAnswerHash != nil {
		t.Fatal("unbound metric received presentation envelope")
	}
	record.Calls = append(record.Calls, ToolCallRecord{Name: liveDataToolName, Outcome: "SUCCEEDED"})
	if answer, selected, err := completedTypedMetricAnswer("qrun_current", "Compare dates", record,
		[]governedQueryDependency{dependency}, nil); !selected || answer != "" || CodeOf(err) != CodeInvalid {
		t.Fatalf("mixed live tools = %q, selected=%v, error=%v", answer, selected, err)
	}
	if record.PresentationVersion != nil || record.PresentationLanguage != nil || record.PresentationAnswerHash != nil {
		t.Fatal("mixed live tools received presentation envelope")
	}
	record.Calls = record.Calls[1:]
	if answer, selected, err := completedTypedMetricAnswer("qrun_current", "How many records?", record, nil, nil); selected || answer != "" || err != nil {
		t.Fatalf("ad hoc only = %q, selected=%v, error=%v", answer, selected, err)
	}
}

func TestCompletedTypedMetricAnswerPreservesClarification(t *testing.T) {
	call, dependency := metricAnswerFixture(t, false)
	record := &ToolLoopRecord{Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192}, Calls: []ToolCallRecord{call},
		StopReason: "CLARIFICATION", AllClaimsBound: true, ClaimEvidenceVersion: "v1"}
	if answer, selected, err := completedTypedMetricAnswer("qrun_current", "Which time zone?", record,
		[]governedQueryDependency{dependency}, nil); selected || answer != "" || err != nil {
		t.Fatalf("clarification = %q, selected=%v, error=%v", answer, selected, err)
	}
	if record.PresentationVersion != nil || record.PresentationLanguage != nil || record.PresentationAnswerHash != nil {
		t.Fatal("clarification received metric presentation envelope")
	}
}
