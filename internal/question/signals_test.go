package question

import (
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
)

func TestDeriveSignalsKeepsAmbiguityAndPartialExplicit(t *testing.T) {
	planned, err := planner.Default().Plan("\u0441\u0440\u0430\u0432\u043d\u0438 \u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432")
	if err != nil {
		t.Fatal(err)
	}
	if planned.Status != planner.ClarifyStatus {
		t.Fatalf("status=%s, want clarification", planned.Status)
	}
	uncertainties, conflicts, err := deriveSignals(planned, []candidate{{ID: "evidence_a"}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 || len(uncertainties) != 1 {
		t.Fatalf("signals=%#v conflicts=%#v", uncertainties, conflicts)
	}
	if uncertainties[0].Code != UncertaintyPlannerClarification {
		t.Fatalf("signals are not deterministically ordered: %#v", uncertainties)
	}
	ready, err := planner.Default().Plan("\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432")
	if err != nil || ready.Status != planner.Ready {
		t.Fatalf("ready plan: %#v %v", ready, err)
	}
	uncertainties, conflicts, err = deriveSignals(ready, []candidate{{ID: "evidence_a"}}, []Citation{{EvidenceFragment: "evidence_a"}}, true)
	if err != nil || len(conflicts) != 0 || len(uncertainties) != 1 || uncertainties[0].Code != UncertaintyCorpusPartial {
		t.Fatalf("partial signals=%#v conflicts=%#v err=%v", uncertainties, conflicts, err)
	}
	if len(uncertainties[0].EvidenceIDs) != 1 || uncertainties[0].EvidenceIDs[0] != "evidence_a" {
		t.Fatalf("partial signal evidence=%#v", uncertainties[0].EvidenceIDs)
	}
}

func TestNormalizeSignalsSortsEvidenceAndRejectsInvalidConflict(t *testing.T) {
	uncertainties, conflicts, err := normalizeSignals([]Uncertainty{{Code: "CORPUS_PARTIAL", EvidenceIDs: []string{"evidence_b", "evidence_a"}}}, []Conflict{{Code: "SOURCE_CONFLICT", EvidenceIDs: []string{"evidence_b", "evidence_a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if uncertainties[0].EvidenceIDs[0] != "evidence_a" || conflicts[0].EvidenceIDs[0] != "evidence_a" {
		t.Fatalf("signals were not canonicalized: %#v %#v", uncertainties, conflicts)
	}
	if _, _, err := normalizeSignals(nil, []Conflict{{Code: "SOURCE_CONFLICT", EvidenceIDs: []string{"evidence_a"}}}); err == nil {
		t.Fatal("single-evidence conflict was accepted")
	}
}

func TestDeriveSignalsDoesNotReuseEvidenceAcrossPartialReasons(t *testing.T) {
	planned, err := planner.Default().Plan("\u0441\u0440\u0430\u0432\u043d\u0438 status")
	if err != nil || planned.Status != planner.Ready {
		t.Fatalf("ready plan: %#v %v", planned, err)
	}
	uncertainties, conflicts, err := deriveSignals(planned,
		[]candidate{{ID: "evidence_a"}, {ID: "evidence_b"}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 || len(uncertainties) != 1 || uncertainties[0].Code != UncertaintyCorpusPartial {
		t.Fatalf("partial signals=%#v conflicts=%#v", uncertainties, conflicts)
	}
	if _, _, err := marshalSignals(uncertainties, conflicts); err != nil {
		t.Fatalf("partial signals must satisfy durable JSON contract: %v", err)
	}
}

func TestUnmarshalSignalsRejectsUnknownMembers(t *testing.T) {
	if _, _, err := unmarshalSignals([]byte(`[{"code":"CORPUS_PARTIAL","evidence_ids":[],"extra":true}]`), []byte(`[]`)); err == nil {
		t.Fatal("unknown uncertainty member was accepted")
	}
}
