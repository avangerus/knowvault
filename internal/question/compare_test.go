package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
)

func compareCandidate(id, object, text string) candidate {
	return candidate{
		ID: id, SourceObjectID: object, SourceVersionID: "version_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ExtractionID: "extraction_01ARZ3NDEKTSV4RRFFQ69G5FAV", Text: []byte(text),
		Anchor: []byte(`{"kind":"TEXT","line_start":1,"line_end":1}`),
	}
}

func TestCompareFactsReportsGenericConflictWithEvidence(t *testing.T) {
	planned, err := planner.Default().Plan("\u0415\u0441\u0442\u044c \u043b\u0438 \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u043c\u0435\u0436\u0434\u0443 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u043e\u043c \u043f\u0438\u0441\u044c\u043c\u0430\u043c\u0438 \u0438 \u0444\u0430\u043a\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u043c\u0438 \u0434\u0430\u043d\u043d\u044b\u043c\u0438?")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Compare {
		t.Fatalf("plan=%+v err=%v", planned, err)
	}
	selected := []candidate{
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "object_contract", "status = signed"),
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FB0", "object_mail", "status = pending"),
	}
	answer, citations := renderCompareFacts("ws_demo", planned, selected)
	if !strings.Contains(answer, "Conflict for status") || !strings.Contains(answer, "signed") || !strings.Contains(answer, "pending") {
		t.Fatalf("answer=%q", answer)
	}
	if len(citations) != 2 || citations[0].EvidenceFragment == citations[1].EvidenceFragment {
		t.Fatalf("citations=%+v", citations)
	}
	_, conflicts, err := deriveSignals(planned, selected, citations, false)
	if err != nil || len(conflicts) != 1 || conflicts[0].Code != "CONFLICT_FACT_VALUE" || len(conflicts[0].EvidenceIDs) != 2 {
		t.Fatalf("conflicts=%+v err=%v", conflicts, err)
	}
}

func TestCompareFactsReportsBoundedAgreementOnlyWithCorroboration(t *testing.T) {
	planned, err := planner.Default().Plan("\u0415\u0441\u0442\u044c \u043b\u0438 \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u043c\u0435\u0436\u0434\u0443 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u043e\u043c \u0438 \u043f\u0438\u0441\u044c\u043c\u0430\u043c\u0438?")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Compare {
		t.Fatalf("plan=%+v err=%v", planned, err)
	}
	selected := []candidate{
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "object_contract", "owner = alice"),
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FB0", "object_mail", "owner = ALICE"),
	}
	answer, citations := renderCompareFacts("ws_demo", planned, selected)
	if !strings.Contains(answer, "conflicts") || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%+v", answer, citations)
	}
	_, conflicts, err := deriveSignals(planned, selected, citations, false)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("conflicts=%+v err=%v", conflicts, err)
	}
}

func TestCompareFactsDoesNotPromoteFreeProse(t *testing.T) {
	planned, err := planner.Default().Plan("\u0415\u0441\u0442\u044c \u043b\u0438 \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u043c\u0435\u0436\u0434\u0443 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u043e\u043c \u0438 \u043f\u0438\u0441\u044c\u043c\u0430\u043c\u0438?")
	if err != nil {
		t.Fatal(err)
	}
	selected := []candidate{
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "object_contract", "\u0414\u043e\u0433\u043e\u0432\u043e\u0440 \u043f\u043e\u0434\u043f\u0438\u0441\u0430\u043d \u0438 \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442."),
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FB0", "object_mail", "\u041f\u0438\u0441\u044c\u043c\u043e \u0443\u0442\u0432\u0435\u0440\u0436\u0434\u0430\u0435\u0442 \u0438\u043d\u043e\u0435."),
	}
	answer, citations := renderCompareFacts("ws_demo", planned, selected)
	if answer != "" || len(citations) != 0 {
		t.Fatalf("free prose became comparison result: answer=%q citations=%+v", answer, citations)
	}
	_, conflicts, err := deriveSignals(planned, selected, nil, false)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("free prose became conflict: %+v err=%v", conflicts, err)
	}
}

func TestCompareFactsAcceptsStructuredJSONCellKeys(t *testing.T) {
	planned, err := planner.Default().Plan("\u0441\u0440\u0430\u0432\u043d\u0438 status \u043c\u0435\u0436\u0434\u0443 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u0430\u043c\u0438 \u0438 \u0434\u0430\u043d\u043d\u044b\u043c\u0438")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Compare {
		t.Fatalf("plan=%+v err=%v", planned, err)
	}
	selected := []candidate{
		compareCandidate("fragment_json_contract", "object_contract", `payload[/status] = "SIGNED"`),
		compareCandidate("fragment_json_data", "object_data", `payload[/status] = "PENDING"`),
	}
	answer, citations := renderCompareFacts("ws_demo", planned, selected)
	if !strings.Contains(answer, "Conflict for payload[/status]") || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%+v", answer, citations)
	}
}
