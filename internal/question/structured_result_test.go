package question

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// r2AggregateFixture reduces a real COUNT snapshot whose rows all live under
// one bound source scope, so the projected AnswerResult carries a stable
// snapshot identity the digest is keyed by.
func r2AggregateFixture(t *testing.T) snapshotAggregate {
	t.Helper()
	today := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	rows := fleetSnapshot(today)
	for index := range rows {
		rows[index].sourceScopeID = "scope-fleet"
	}
	plan := mustPlan(t, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432 \u0440\u0435\u0439\u0441\u0435?")
	result, ok := reduceStructuredSnapshot(rows, plan, today, "UTC")
	if !ok {
		t.Fatalf("reducer declined a resolvable count")
	}
	return result
}

// TestCanonicalResultDigestIsDeterministicPerIntentAndSnapshot proves R2
// Outcome 3's negative control on the server side: the digest is a function of
// the validated intent, the stable snapshot/execution identity and the result
// content -- never of the per-run run_id -- so two runs tie out, while a
// different metric version or snapshot necessarily changes it.
func TestCanonicalResultDigestIsDeterministicPerIntentAndSnapshot(t *testing.T) {
	result := r2AggregateFixture(t)

	first := buildAnswerResult(result, answerResultIdentity{
		RunID: "run_first", SnapshotID: result.sourceScopeID, MetricVersion: "1",
		EvidenceRefs: []string{"frg_a", "frg_b"},
	})
	second := buildAnswerResult(result, answerResultIdentity{
		RunID: "run_second", SnapshotID: result.sourceScopeID, MetricVersion: "1",
		EvidenceRefs: []string{"frg_a", "frg_b"},
	})
	if first.ResultDigest == "" {
		t.Fatalf("result_digest is empty")
	}
	if !strings.HasPrefix(first.ResultDigest, "sha256:") || len(first.ResultDigest) != len("sha256:")+64 {
		t.Fatalf("result_digest=%q is not a sha256 digest", first.ResultDigest)
	}
	if first.ResultDigest != second.ResultDigest {
		t.Fatalf("same intent/snapshot produced different digests: %s vs %s", first.ResultDigest, second.ResultDigest)
	}
	if first.RunID != "run_first" || second.RunID != "run_second" {
		t.Fatalf("run_id not carried: %q / %q", first.RunID, second.RunID)
	}
	if len(first.EvidenceRefs) != 2 || first.EvidenceRefs[0] != "frg_a" {
		t.Fatalf("evidence_refs not carried: %#v", first.EvidenceRefs)
	}
	if first.ResultDigest != canonicalResultDigest(first) {
		t.Fatalf("stored digest does not match canonical recomputation")
	}
	if first.SnapshotID != "scope-fleet" || first.Snapshot.ID != "scope-fleet" {
		t.Fatalf("snapshot identity not carried: snapshot_id=%q snapshot.id=%q", first.SnapshotID, first.Snapshot.ID)
	}

	differentVersion := buildAnswerResult(result, answerResultIdentity{
		RunID: "run_first", SnapshotID: result.sourceScopeID, MetricVersion: "2",
	})
	if differentVersion.ResultDigest == first.ResultDigest {
		t.Fatalf("metric version change left the digest unchanged")
	}

	differentSnapshot := buildAnswerResult(result, answerResultIdentity{
		RunID: "run_first", SnapshotID: result.sourceScopeID + "-other", MetricVersion: "1",
	})
	if differentSnapshot.ResultDigest == first.ResultDigest {
		t.Fatalf("snapshot identity change left the digest unchanged")
	}

	differentContent := result
	differentContent.count = result.count + 1
	changed := buildAnswerResult(differentContent, answerResultIdentity{
		RunID: "run_first", SnapshotID: result.sourceScopeID, MetricVersion: "1",
	})
	if changed.ResultDigest == first.ResultDigest {
		t.Fatalf("result content change left the digest unchanged")
	}
}

// TestAnswerResultWithoutUnifiedFieldsKeepsTheR1Shape proves R2 Outcome 3's
// zero-value/older-answer backward compatibility: a decoded pre-R2 artifact
// leaves every unified field absent and marshals exactly the R1 shape, and a
// PARTIAL completeness is never upgraded on the way out.
func TestAnswerResultWithoutUnifiedFieldsKeepsTheR1Shape(t *testing.T) {
	legacy := AnswerResult{
		Kind: "CALCULATION", Operation: "COUNT", Rule: "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0441\u0442\u0440\u043e\u043a",
		Value: "3", Completeness: "PARTIAL",
		Snapshot: AnswerSnapshot{ID: "scope-fleet", RowCount: 7},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy AnswerResult: %v", err)
	}
	for _, key := range []string{
		"run_id", "intent", "rowset_ref", "metric_version", "snapshot_id",
		"execution_id", "result_digest", "freshness", "evidence_refs", "audit_receipt",
	} {
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatalf("older answer emitted unified field %q: %s", key, raw)
		}
	}
	if !strings.Contains(string(raw), `"completeness":"PARTIAL"`) {
		t.Fatalf("PARTIAL completeness was not preserved on the wire: %s", raw)
	}

	// A pre-R2 payload still decodes: every new field stays absent rather than
	// defaulting to an invented value.
	var decoded AnswerResult
	preR2 := `{"kind":"CALCULATION","value":"3","operation":"COUNT","rule":"r",` +
		`"snapshot":{"id":"scope-fleet","row_count":7},"completeness":"PARTIAL"}`
	if err := json.Unmarshal([]byte(preR2), &decoded); err != nil {
		t.Fatalf("decode pre-R2 payload: %v", err)
	}
	if decoded.Completeness != "PARTIAL" {
		t.Fatalf("completeness=%q want PARTIAL", decoded.Completeness)
	}
	if decoded.RunID != "" || decoded.ResultDigest != "" || decoded.Intent != nil ||
		decoded.Freshness != nil || decoded.SnapshotID != "" || decoded.ExecutionID != "" ||
		decoded.MetricVersion != "" || decoded.EvidenceRefs != nil || decoded.AuditReceipt != nil {
		t.Fatalf("pre-R2 payload invented unified fields: %#v", decoded)
	}
}
