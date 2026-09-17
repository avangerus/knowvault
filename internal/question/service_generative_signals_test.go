package question

import (
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
)

// TestGenerativeInsufficientSignalsNeverRepeatAnEvidenceIDAcrossItems guards a
// regression found live on the acc acceptance stand (GEN-2): a GENERATIVE run
// whose corpus was Ready but whose bounded generation/verification attempt
// failed used to report both an evidence-linked INSUFFICIENT_EVIDENCE/
// CORPUS_PARTIAL uncertainty (from deriveSignals) and a GENERATION_UNAVAILABLE
// uncertainty carrying the exact same Evidence IDs, which
// app.question_run_uncertainties_valid (db/migrations/000038) rejects because
// it forbids one Evidence ID appearing in two uncertainty records — every
// GENERATIVE question failed closed with a raw SQLSTATE 23514 instead of ever
// disclosing INSUFFICIENT_EVIDENCE cleanly. This test exercises the exact
// signal-construction sequence completeGenerativeInsufficient now uses
// (deriveSignals, then dropping the evidence-linked generic codes before
// appending GENERATION_UNAVAILABLE) and asserts no Evidence ID repeats across
// items, mirroring the database's own cross-item uniqueness rule.
func TestGenerativeInsufficientSignalsNeverRepeatAnEvidenceIDAcrossItems(t *testing.T) {
	selected := []candidate{
		testPostgreSQLCandidate("ev1", "row_1", "stream", "stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432"),
		testPostgreSQLCandidate("ev2", "row_1", "collected_at", "collected_at = 2026-08-29T09:34:56Z"),
	}
	planned := planner.Plan{Status: planner.Ready, Operation: planner.Lookup}

	for _, partial := range []bool{false, true} {
		uncertainties, _, err := deriveSignals(planned, selected, nil, partial)
		if err != nil {
			t.Fatalf("deriveSignals(partial=%v): %v", partial, err)
		}
		filtered := uncertainties[:0]
		for _, item := range uncertainties {
			if item.Code != UncertaintyCorpusPartial && item.Code != UncertaintyInsufficientEvidence {
				filtered = append(filtered, item)
			}
		}
		final, _, err := normalizeSignals(append(filtered, Uncertainty{Code: "GENERATION_UNAVAILABLE", EvidenceIDs: signalEvidenceIDs(selected)}), nil)
		if err != nil {
			t.Fatalf("normalizeSignals(partial=%v): %v", partial, err)
		}
		seen := map[string]string{}
		for _, item := range final {
			for _, evidenceID := range item.EvidenceIDs {
				if priorCode, exists := seen[evidenceID]; exists {
					t.Fatalf("partial=%v: evidence id %q appears in both %q and %q — violates app.question_run_uncertainties_valid's cross-item uniqueness rule", partial, evidenceID, priorCode, item.Code)
				}
				seen[evidenceID] = item.Code
			}
		}
		var codes []string
		for _, item := range final {
			codes = append(codes, item.Code)
		}
		if !contains(codes, "GENERATION_UNAVAILABLE") {
			t.Fatalf("partial=%v: expected GENERATION_UNAVAILABLE among %v", partial, codes)
		}
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
