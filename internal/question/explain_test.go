package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
)

func TestExplainDefinitionsAreGenericAndEvidenceBound(t *testing.T) {
	planned, err := planner.Default().Plan("\u0427\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 Kafka \u0438 \u0433\u0434\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f?")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Explain {
		t.Fatalf("plan=%+v err=%v", planned, err)
	}
	selected := []candidate{
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "object_doc", "Kafka means event bus."),
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FB0", "object_doc", "Kafka \u2014 \u044d\u0442\u043e event bus."),
	}
	answer, citations := renderExplainDefinitions("ws_demo", planned, selected)
	if strings.Count(answer, "Kafka means: event bus.") != 2 || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%+v", answer, citations)
	}
	if citations[0].EvidenceFragment != selected[0].ID || citations[0].Excerpt != "Kafka means event bus." {
		t.Fatalf("citation=%+v", citations[0])
	}
	if citations[1].EvidenceFragment != selected[1].ID || citations[1].Excerpt != "Kafka \u2014 \u044d\u0442\u043e event bus." {
		t.Fatalf("dash citation=%+v", citations[1])
	}
}

func TestExplainDoesNotPromoteUnrelatedOrFreeProse(t *testing.T) {
	planned, err := planner.Default().Plan("\u0427\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 Kafka?")
	if err != nil {
		t.Fatal(err)
	}
	selected := []candidate{
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "object_doc", "The event bus is important."),
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FB0", "object_doc", "Rabbit means animal."),
	}
	answer, citations := renderExplainDefinitions("ws_demo", planned, selected)
	if answer != "" || len(citations) != 0 {
		t.Fatalf("unrelated prose became definition: answer=%q citations=%+v", answer, citations)
	}
}

func TestExplainConflictsRequireDistinctEvidence(t *testing.T) {
	planned, err := planner.Default().Plan("\u0427\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 Kafka?")
	if err != nil {
		t.Fatal(err)
	}
	selected := []candidate{
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "object_contract", "Kafka means event bus."),
		compareCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FB0", "object_mail", "Kafka means stream."),
	}
	conflicts := explainConflicts(planned, selected)
	if len(conflicts) != 1 || conflicts[0].Code != "CONFLICT_DEFINITION_VALUE" || len(conflicts[0].EvidenceIDs) != 2 {
		t.Fatalf("conflicts=%+v", conflicts)
	}
}
